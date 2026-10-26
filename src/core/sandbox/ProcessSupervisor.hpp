#pragma once

#include "core/models/Result.hpp"
#include "core/util/FileUtil.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sys/types.h>

namespace tracepot {

struct ExitStatus {
    bool exited = false;   // normal exit
    int code = 0;          // exit code when exited
    int signal = 0;        // terminating signal otherwise
};

std::string signalName(int signal);

struct SpawnSpec {
    std::string executable;              // absolute path, executed directly (no PATH lookup, no shell)
    std::vector<std::string> argv;       // argv[0] included
    std::vector<std::string> environment;  // KEY=VALUE; the parent environment is NOT inherited
    int stdinFd = -1;                    // -1 means /dev/null
    int stdoutFd = -1;
    int stderrFd = -1;
    std::vector<std::pair<int, int>> inheritedFds;  // (fd in parent, fd number in child)
};

// Launches one child process in its own session/process group and supervises it.
// The child receives SIGKILL if the launching thread exits (PR_SET_PDEATHSIG), and the destructor
// kills and reaps a still-running child, so a crashed or cancelled analysis does not leak processes.
class ProcessSupervisor {
public:
    ProcessSupervisor() = default;
    ~ProcessSupervisor();
    ProcessSupervisor(const ProcessSupervisor&) = delete;
    ProcessSupervisor& operator=(const ProcessSupervisor&) = delete;

    Status start(const SpawnSpec& spec);

    // Waits up to `timeout` for the child to exit. Returns the status once it has exited.
    std::optional<ExitStatus> waitFor(std::chrono::milliseconds timeout);

    // Sends a signal to the child's whole process group.
    void signalGroup(int signal) const;
    // Sends a signal to the child only.
    void signalProcess(int signal) const;

    [[nodiscard]] pid_t pid() const { return pid_; }
    [[nodiscard]] bool running() const { return pid_ > 0 && !status_.has_value(); }
    [[nodiscard]] const std::optional<ExitStatus>& status() const { return status_; }

private:
    void reap(bool block);

    pid_t pid_ = -1;
    UniqueFd pidFd_;
    std::optional<ExitStatus> status_;
};

struct CapturedRun {
    ExitStatus status;
    std::string out;
    std::string err;
    bool timedOut = false;
};

// Runs a short-lived helper command (version probes, readiness checks) and captures its output.
Result<CapturedRun> runAndCapture(const std::string& executable, const std::vector<std::string>& argv,
                                  std::chrono::milliseconds timeout, std::size_t maxOutput = 256ULL * 1024);

// PIDs whose parent is `parent` (scans /proc).
std::vector<pid_t> childProcesses(pid_t parent);

}  // namespace tracepot
