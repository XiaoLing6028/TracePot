#include "core/sandbox/Readiness.hpp"

#include "core/sandbox/ProcessSupervisor.hpp"
#include "core/sandbox/SeccompFilter.hpp"
#include "core/util/FileUtil.hpp"

#include <fstream>

#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

namespace {

constexpr auto kProbeTimeout = std::chrono::seconds(15);

std::string readSysctl(const char* path)
{
    std::ifstream in(path);
    std::string value;
    std::getline(in, value);
    return value;
}

std::string firstLine(const std::string& text)
{
    return text.substr(0, text.find('\n'));
}

std::vector<std::string> probeSandboxArgv(const Readiness& r)
{
    std::vector<std::string> argv = {r.bwrapPath.string(), "--unshare-user", "--unshare-pid", "--unshare-ipc",
                                     "--unshare-uts", "--unshare-net"};
    if (r.bwrap.unshareCgroupTry) {
        argv.emplace_back("--unshare-cgroup-try");
    }
    if (r.bwrap.disableUserns) {
        argv.emplace_back("--disable-userns");
    }
    argv.insert(argv.end(), {"--die-with-parent", "--new-session", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr"});
    for (const auto* top : {"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}) {
        struct stat st {};
        if (::lstat(top, &st) != 0) {
            continue;
        }
        std::error_code ec;
        if (S_ISLNK(st.st_mode)) {
            argv.insert(argv.end(), {"--symlink", fs::read_symlink(top, ec).string(), top});
        } else if (S_ISDIR(st.st_mode)) {
            argv.insert(argv.end(), {"--ro-bind", top, top});
        }
    }
    argv.insert(argv.end(), {"--proc", "/proc", "--dev", "/dev", "--"});
    argv.emplace_back(::access("/usr/bin/true", X_OK) == 0 ? "/usr/bin/true" : "/bin/true");
    return argv;
}

std::string userNamespaceHint()
{
    std::string hint = "Unprivileged user namespaces must be available to bubblewrap.";
    if (readSysctl("/proc/sys/kernel/unprivileged_userns_clone") == "0") {
        hint += " kernel.unprivileged_userns_clone is 0.";
    }
    if (readSysctl("/proc/sys/user/max_user_namespaces") == "0") {
        hint += " user.max_user_namespaces is 0.";
    }
    if (readSysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") == "1") {
        hint += " AppArmor restricts unprivileged user namespaces (kernel.apparmor_restrict_unprivileged_userns=1);"
                " install the distribution's bwrap AppArmor profile.";
    }
    hint += " TracePot never falls back to running samples without a sandbox.";
    return hint;
}

}  // namespace

bool Readiness::sandboxReady() const
{
    return !bwrapPath.empty() && !helperPath.empty() && sandboxFunctional && seccompAvailable;
}

bool Readiness::tracingReady() const
{
    return !stracePath.empty() && tracingFunctional;
}

std::string Readiness::failureSummary(bool includeTracing) const
{
    std::string summary;
    for (const auto& check : checks) {
        if (check.ok || !check.required) {
            continue;
        }
        if (!includeTracing && check.name.find("strace") != std::string::npos) {
            continue;
        }
        summary += "- " + check.name + ": " + check.detail;
        if (!check.hint.empty()) {
            summary += " (" + check.hint + ")";
        }
        summary += "\n";
    }
    return summary;
}

fs::path locateLimitsHelper(const fs::path& override)
{
    auto usable = [](const fs::path& path) { return !path.empty() && ::access(path.c_str(), X_OK) == 0; };
    if (!override.empty()) {
        return usable(override) ? override : fs::path();
    }
    const auto exeDir = executableDirectory();
    if (exeDir.empty()) {
        return {};
    }
    for (const auto& candidate : {exeDir / "tracepot-limits", exeDir / ".." / "libexec" / "tracepot" / "tracepot-limits"}) {
        if (usable(candidate)) {
            return fs::weakly_canonical(candidate);
        }
    }
    return {};
}

Readiness checkReadiness(const fs::path& helperOverride)
{
    Readiness r;
    r.runningAsRoot = ::geteuid() == 0;

    r.bwrapPath = findSystemExecutable("bwrap");
    {
        DependencyCheck check{"bubblewrap (bwrap)", !r.bwrapPath.empty(), true, {}, {}};
        if (check.ok) {
            auto help = runAndCapture(r.bwrapPath, {r.bwrapPath.string(), "--help"}, kProbeTimeout);
            auto version = runAndCapture(r.bwrapPath, {r.bwrapPath.string(), "--version"}, kProbeTimeout);
            r.bwrap = parseBwrapFeatures(help ? help->out + help->err : std::string(),
                                         version ? firstLine(version->out) : std::string());
            check.detail = r.bwrapPath.string() + (r.bwrap.version.empty() ? "" : " (" + r.bwrap.version + ")");
            struct stat st {};
            if (::stat(r.bwrapPath.c_str(), &st) == 0 && (st.st_mode & S_ISUID) != 0) {
                check.detail += "; setuid installation (it runs unprivileged under the tracer)";
            }
        } else {
            check.detail = "not found";
            check.hint = "Install bubblewrap (Fedora: dnf install bubblewrap; Debian/Ubuntu: apt install bubblewrap).";
        }
        r.checks.push_back(check);
    }

    r.helperPath = locateLimitsHelper(helperOverride);
    r.checks.push_back({"tracepot-limits helper", !r.helperPath.empty(), true,
                        r.helperPath.empty() ? "not found next to the executable" : r.helperPath.string(),
                        r.helperPath.empty() ? "Reinstall TracePot; the helper applies resource limits." : ""});

    {
        auto program = buildSeccompProgram();
        r.seccompAvailable = program.ok();
        r.checks.push_back({"seccomp filter (libseccomp)", r.seccompAvailable, true,
                            r.seccompAvailable ? "filter compiled" : program.error().message,
                            r.seccompAvailable ? "" : "The kernel or libseccomp does not support the filter."});
    }

    if (!r.bwrapPath.empty()) {
        auto run = runAndCapture(r.bwrapPath, probeSandboxArgv(r), kProbeTimeout);
        r.sandboxFunctional = run && !run->timedOut && run->status.exited && run->status.code == 0;
        DependencyCheck check{"namespace sandbox probe", r.sandboxFunctional, true, {}, {}};
        if (r.sandboxFunctional) {
            check.detail = "user, mount, PID, IPC, UTS and network namespaces created";
        } else {
            check.detail = run ? firstLine(run->err.empty() ? std::string("probe failed") : run->err) : run.error().message;
            check.hint = userNamespaceHint();
        }
        r.checks.push_back(check);
    }

    r.stracePath = findSystemExecutable("strace");
    {
        DependencyCheck check{"strace", !r.stracePath.empty(), true, {}, {}};
        if (check.ok) {
            auto version = runAndCapture(r.stracePath, {r.stracePath.string(), "-V"}, kProbeTimeout);
            auto help = runAndCapture(r.stracePath, {r.stracePath.string(), "-h"}, kProbeTimeout);
            r.straceVersion = version ? firstLine(version->out) : std::string();
            const std::string helpText = help ? help->out + help->err : std::string();
            r.straceSeccompBpf = helpText.find("--seccomp-bpf") != std::string::npos;
            r.stracePidnsTranslation = helpText.find("pidns") != std::string::npos;
            check.detail = r.stracePath.string() + " (" + r.straceVersion + ")";
            if (!r.stracePidnsTranslation) {
                check.detail += "; no PID namespace translation, process ancestry will be incomplete";
            }
        } else {
            check.detail = "not found";
            check.hint = "Install strace (Fedora: dnf install strace; Debian/Ubuntu: apt install strace).";
        }
        r.checks.push_back(check);
    }

    if (!r.stracePath.empty() && r.sandboxFunctional) {
        std::vector<std::string> argv = {r.stracePath.string(), "-f", "-qq", "-o", "/dev/null"};
        if (r.straceSeccompBpf) {
            argv.emplace_back("--seccomp-bpf");
        }
        argv.emplace_back("--");
        const auto probe = probeSandboxArgv(r);
        argv.insert(argv.end(), probe.begin(), probe.end());
        auto run = runAndCapture(r.stracePath, argv, kProbeTimeout);
        r.tracingFunctional = run && !run->timedOut && run->status.exited && run->status.code == 0;
        DependencyCheck check{"strace through the sandbox", r.tracingFunctional, true, {}, {}};
        if (r.tracingFunctional) {
            check.detail = "syscall tracing of sandboxed processes works";
        } else {
            check.detail = run ? firstLine(run->err.empty() ? std::string("probe failed") : run->err) : run.error().message;
            check.hint = "ptrace of child processes must be permitted";
            if (readSysctl("/proc/sys/kernel/yama/ptrace_scope") == "3") {
                check.hint += " (kernel.yama.ptrace_scope is 3, which disables ptrace entirely)";
            }
        }
        r.checks.push_back(check);
    }

    if (r.runningAsRoot) {
        r.checks.push_back({"unprivileged user", false, false, "TracePot is running as root",
                            "Run TracePot as a regular user; root is neither needed nor recommended."});
    }
    return r;
}

}  // namespace tracepot
