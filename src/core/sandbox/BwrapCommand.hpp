#pragma once

#include "core/models/Result.hpp"
#include "core/models/Types.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tracepot {

// Sandbox-side constants shared by the workspace, the command builder and the analyzer.
inline constexpr std::string_view kSandboxWorkDir = "/work";
inline constexpr std::string_view kSandboxUserName = "tracepot";
inline constexpr std::string_view kSandboxHostname = "tracepot-sandbox";
inline constexpr std::uint32_t kSandboxUserUid = 1000;

std::uint32_t sandboxUid(SandboxUser user);
std::string sandboxHome(SandboxUser user);

struct BwrapFeatures {
    std::string version;
    bool clearenv = false;
    bool disableUserns = false;
    bool tmpfsSize = false;
    bool unshareCgroupTry = false;
};

// Parses `bwrap --help` / `bwrap --version` output.
BwrapFeatures parseBwrapFeatures(const std::string& helpText, const std::string& versionText);

struct SandboxRequest {
    std::filesystem::path bwrapPath;
    BwrapFeatures features;
    std::filesystem::path rootDir;  // host directory holding the sandbox's writable tree
    SandboxUser user = SandboxUser::Unprivileged;
    std::string interpreterPath;    // inside the sandbox, e.g. /usr/bin/sh
    std::string scriptPath;         // inside the sandbox, e.g. /work/install.sh
    std::vector<std::string> arguments;
    std::vector<std::pair<std::string, std::string>> environment;
    std::optional<int> seccompFd;   // descriptor number bwrap reads the BPF program from
};

struct SandboxPlan {
    std::vector<std::string> argv;  // complete bwrap command line
    std::vector<std::string> entryArgv;  // the command bwrap executes inside the sandbox
    std::vector<std::string> readOnlyPaths;
    std::vector<std::string> writablePaths;
    std::vector<std::string> hostWritablePaths;
    std::vector<std::string> namespaces;
    std::vector<std::string> environmentKeys;
    bool nestedUserNamespacesDisabled = false;
};

bool isValidEnvironmentName(std::string_view name);

// Resolves a shell name to an absolute path that exists in the sandbox's read-only /usr view.
std::string sandboxInterpreterPath(const std::string& shell);

// Builds the bubblewrap argument vector. The filesystem view is minimal and explicit:
//   * /usr (and /bin, /sbin, /lib* links or binds) read-only from the host;
//   * fresh /proc and a minimal /dev (null, zero, random, urandom, tty, ...);
//   * /etc, /home, /root, /var, /opt, /usr/local, /run come from TracePot's prepared copies in the
//     private workspace — never from the host — so host credentials, D-Bus/X11/Wayland sockets
//     and the user's home are not visible;
//   * /tmp, /var/tmp, /work and the sandbox user's home are writable; in simulated-root mode the
//     system directories are writable as well so system-level changes can be observed.
Result<SandboxPlan> buildSandboxPlan(const SandboxRequest& request);

}  // namespace tracepot
