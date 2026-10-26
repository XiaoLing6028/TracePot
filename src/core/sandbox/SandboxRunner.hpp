#pragma once

#include "core/analysis/Cancellation.hpp"
#include "core/models/Limits.hpp"
#include "core/models/Report.hpp"
#include "core/models/Result.hpp"
#include "core/sandbox/BwrapCommand.hpp"
#include "core/sandbox/ProcessSupervisor.hpp"
#include "core/sandbox/Workspace.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tracepot {

inline constexpr int kSeccompChildFd = 10;

struct SandboxRunOptions {
    SandboxPlan plan;
    WorkspacePaths paths;
    ResourceLimits limits;
    std::filesystem::path helperPath;
    std::filesystem::path stracePath;  // empty disables tracing
    bool straceSeccompBpf = false;
    bool stracePidnsTranslation = false;
    int seccompFd = -1;  // parent descriptor of the BPF program, passed to the child as kSeccompChildFd
    std::uint64_t maxTraceBytes = 1 * GiB;
    std::uint64_t maxTreeEntries = 200000;
};

struct SandboxRunResult {
    std::optional<TerminationReason> forced;  // set when TracePot terminated the sandbox
    std::string forcedDetail;
    std::optional<ExitStatus> launcherStatus;  // exit status of strace / the launcher chain
    double startEpoch = 0;
    double endEpoch = 0;
    double wallSeconds = 0;
    std::uint64_t traceBytes = 0;
    std::vector<ResourceLimitEvent> limitEvents;
};

using TraceSink = std::function<void(std::string_view chunk)>;
using RunHeartbeat = std::function<void(double elapsedSeconds)>;

// The strace command line used for observation (exposed for tests and documentation).
std::vector<std::string> straceArguments(const SandboxRunOptions& options);

// Runs the sandbox to completion, enforcing the wall-clock timeout, cancellation, disk-growth and
// trace-size limits. On enforcement, the whole sandbox is killed: bubblewrap is SIGKILLed, which
// tears down its PID namespace and every process in it; the launcher's process group is killed
// as a fallback.
Result<SandboxRunResult> runSandbox(const SandboxRunOptions& options, const CancellationToken& cancel,
                                    const TraceSink& sink, const RunHeartbeat& heartbeat);

}  // namespace tracepot
