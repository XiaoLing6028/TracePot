#include "core/sandbox/BwrapCommand.hpp"

#include <array>

#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

std::uint32_t sandboxUid(SandboxUser user)
{
    return user == SandboxUser::SimulatedRoot ? 0 : kSandboxUserUid;
}

std::string sandboxHome(SandboxUser user)
{
    return user == SandboxUser::SimulatedRoot ? std::string("/root") : "/home/" + std::string(kSandboxUserName);
}

BwrapFeatures parseBwrapFeatures(const std::string& helpText, const std::string& versionText)
{
    BwrapFeatures features;
    auto has = [&helpText](std::string_view option) { return helpText.find(option) != std::string::npos; };
    features.clearenv = has("--clearenv");
    features.disableUserns = has("--disable-userns");
    features.tmpfsSize = has("--size");
    features.unshareCgroupTry = has("--unshare-cgroup-try");
    std::string version = versionText;
    while (!version.empty() && (version.back() == '\n' || version.back() == '\r' || version.back() == ' ')) {
        version.pop_back();
    }
    features.version = version;
    return features;
}

bool isValidEnvironmentName(std::string_view name)
{
    if (name.empty() || (name.front() >= '0' && name.front() <= '9')) {
        return false;
    }
    for (const char c : name) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) {
            return false;
        }
    }
    return true;
}

std::string sandboxInterpreterPath(const std::string& shell)
{
    for (const auto* dir : {"/usr/bin/", "/bin/"}) {
        const std::string candidate = std::string(dir) + shell;
        struct stat st {};
        if (::stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0111) != 0) {
            // /bin is only visible in the sandbox if it is a symlink to usr/bin or bound itself;
            // both cases are handled by buildSandboxPlan, so either path is reachable.
            return candidate;
        }
    }
    return {};
}

Result<SandboxPlan> buildSandboxPlan(const SandboxRequest& request)
{
    if (request.bwrapPath.empty() || request.rootDir.empty() || request.interpreterPath.empty() ||
        request.scriptPath.empty()) {
        return makeError(ErrorCode::InvalidArgument, "incomplete sandbox request");
    }
    const bool root = request.user == SandboxUser::SimulatedRoot;
    const std::uint32_t uid = sandboxUid(request.user);
    const std::string home = sandboxHome(request.user);
    const std::string rootDir = request.rootDir.string();

    SandboxPlan plan;
    auto& a = plan.argv;
    a.push_back(request.bwrapPath.string());

    // Namespaces. The network namespace contains only a loopback interface, so analyzed code has
    // no route to the host network or the internet.
    a.insert(a.end(), {"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net"});
    plan.namespaces = {"user", "mount", "pid", "ipc", "uts", "net"};
    if (request.features.unshareCgroupTry) {
        a.push_back("--unshare-cgroup-try");
        plan.namespaces.emplace_back("cgroup (if supported)");
    }
    if (request.features.disableUserns) {
        a.push_back("--disable-userns");
        plan.nestedUserNamespacesDisabled = true;
    }
    a.insert(a.end(), {"--uid", std::to_string(uid), "--gid", std::to_string(uid)});
    a.insert(a.end(), {"--hostname", std::string(kSandboxHostname)});
    // --die-with-parent: the sandbox is killed with SIGKILL if its supervisor dies.
    // --new-session: no access to the controlling terminal (prevents TIOCSTI-style injection).
    a.insert(a.end(), {"--die-with-parent", "--new-session", "--cap-drop", "ALL"});

    // Environment: start empty and set only explicit variables.
    std::vector<std::pair<std::string, std::string>> env = {
        {"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        {"HOME", home},
        {"USER", root ? "root" : std::string(kSandboxUserName)},
        {"LOGNAME", root ? "root" : std::string(kSandboxUserName)},
        {"SHELL", ::access("/usr/bin/bash", X_OK) == 0 ? "/bin/bash" : "/bin/sh"},
        {"LANG", "C.UTF-8"},
        {"TERM", "dumb"},
        {"PWD", std::string(kSandboxWorkDir)},
    };
    if (!root) {
        env.emplace_back("XDG_RUNTIME_DIR", "/run/user/" + std::to_string(uid));
    }
    for (const auto& [key, value] : request.environment) {
        if (!isValidEnvironmentName(key)) {
            return makeError(ErrorCode::InvalidArgument, "invalid environment variable name: " + key);
        }
        bool replaced = false;
        for (auto& existing : env) {
            if (existing.first == key) {
                existing.second = value;
                replaced = true;
            }
        }
        if (!replaced) {
            env.emplace_back(key, value);
        }
    }
    if (request.features.clearenv) {
        a.push_back("--clearenv");
    } else {
        // Without --clearenv the supervisor still passes bwrap a minimal environment;
        // unset the two variables it contains before setting ours.
        a.insert(a.end(), {"--unsetenv", "LANG", "--unsetenv", "LC_ALL"});
    }
    for (const auto& [key, value] : env) {
        a.insert(a.end(), {"--setenv", key, value});
        plan.environmentKeys.push_back(key);
    }

    // Host system software, read-only.
    a.insert(a.end(), {"--ro-bind", "/usr", "/usr"});
    plan.readOnlyPaths.emplace_back("/usr");
    for (const auto* top : {"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}) {
        struct stat st {};
        if (::lstat(top, &st) != 0) {
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            std::error_code ec;
            const auto target = fs::read_symlink(top, ec);
            if (!ec) {
                a.insert(a.end(), {"--symlink", target.string(), top});
            }
        } else if (S_ISDIR(st.st_mode)) {
            a.insert(a.end(), {"--ro-bind", top, top});
            plan.readOnlyPaths.emplace_back(top);
        }
    }
    a.insert(a.end(), {"--proc", "/proc", "--dev", "/dev"});
    if (request.features.tmpfsSize) {
        a.insert(a.end(), {"--size", std::to_string(64ULL * 1024 * 1024), "--tmpfs", "/dev/shm"});
    } else {
        a.insert(a.end(), {"--tmpfs", "/dev/shm"});
    }

    // Prepared directories from the workspace. Bind order matters: parents before children.
    auto bindTree = [&](const std::string& sandboxPath, bool writable) {
        const std::string hostPath = rootDir + sandboxPath;
        a.insert(a.end(), {writable ? "--bind" : "--ro-bind", hostPath, sandboxPath});
        (writable ? plan.writablePaths : plan.readOnlyPaths).push_back(sandboxPath);
        if (writable) {
            plan.hostWritablePaths.push_back(hostPath);
        }
    };
    bindTree("/etc", root);
    bindTree("/var", root);
    bindTree("/var/tmp", true);
    bindTree("/opt", root);
    struct stat usrLocal {};
    if (::lstat("/usr/local", &usrLocal) == 0 && S_ISDIR(usrLocal.st_mode)) {
        bindTree("/usr/local", root);  // hides the host's /usr/local
    }
    bindTree("/run", root);
    if (!root) {
        bindTree("/run/user/" + std::to_string(uid), true);
    }
    bindTree("/home", root);
    if (!root) {
        bindTree(home, true);
    }
    bindTree("/root", root);
    bindTree("/tmp", true);
    bindTree(std::string(kSandboxWorkDir), true);
    a.insert(a.end(), {"--chdir", std::string(kSandboxWorkDir)});

    if (request.seccompFd) {
        a.insert(a.end(), {"--seccomp", std::to_string(*request.seccompFd)});
    }

    // The command is passed as an argument vector; nothing is interpreted by a host shell.
    plan.entryArgv = {request.interpreterPath, request.scriptPath};
    plan.entryArgv.insert(plan.entryArgv.end(), request.arguments.begin(), request.arguments.end());
    a.emplace_back("--");
    a.insert(a.end(), plan.entryArgv.begin(), plan.entryArgv.end());
    return plan;
}

}  // namespace tracepot
