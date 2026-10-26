#include "core/sandbox/SandboxRunner.hpp"

#include "core/diff/Snapshot.hpp"
#include "core/util/FileUtil.hpp"
#include "core/util/TimeUtil.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

namespace tracepot {

namespace {

using Clock = std::chrono::steady_clock;

// Syscalls recorded by the tracer. The '?' prefix tells strace to ignore names that do not exist
// on the current architecture (e.g. open/fork on aarch64) or in older kernels.
constexpr std::string_view kTracedSyscalls =
    "trace=?execve,?execveat,?clone,?clone3,?fork,?vfork,?exit_group,?chdir,?fchdir,?open,?openat,?openat2,"
    "?creat,?unlink,?unlinkat,?rmdir,?rename,?renameat,?renameat2,?mkdir,?mkdirat,?symlink,?symlinkat,?link,"
    "?linkat,?chmod,?fchmod,?fchmodat,?fchmodat2,?chown,?lchown,?fchown,?fchownat,?truncate,?socket,?connect,"
    "?bind,?listen,?sendto,?sendmsg,?sendmmsg";

std::vector<std::string> helperArguments(const SandboxRunOptions& options)
{
    std::vector<std::string> argv = {options.helperPath.string()};
    if (!options.stracePath.empty()) {
        argv.emplace_back("--require-tracer");
    }
    const auto& limits = options.limits;
    if (limits.memoryBytes > 0) {
        argv.insert(argv.end(), {"--as", std::to_string(limits.memoryBytes)});
    }
    if (limits.maxFileSizeBytes > 0) {
        argv.insert(argv.end(), {"--fsize", std::to_string(limits.maxFileSizeBytes)});
    }
    if (limits.maxOpenFiles > 0) {
        argv.insert(argv.end(), {"--nofile", std::to_string(limits.maxOpenFiles)});
    }
    if (limits.maxProcesses > 0) {
        argv.insert(argv.end(), {"--nproc-extra", std::to_string(limits.maxProcesses)});
    }
    argv.insert(argv.end(), {"--core", "0"});
    if (options.seccompFd >= 0) {
        argv.insert(argv.end(), {"--keep-fd", std::to_string(kSeccompChildFd)});
    }
    argv.emplace_back("--");
    argv.insert(argv.end(), options.plan.argv.begin(), options.plan.argv.end());
    return argv;
}

std::optional<std::uint64_t> freeBytes(const std::filesystem::path& path)
{
    struct statvfs vfs {};
    if (::statvfs(path.c_str(), &vfs) != 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(vfs.f_bavail) * vfs.f_frsize;
}

std::uint64_t fileSize(int fd)
{
    struct stat st {};
    return ::fstat(fd, &st) == 0 ? static_cast<std::uint64_t>(st.st_size) : 0;
}

class TraceTail {
public:
    explicit TraceTail(std::filesystem::path path) : path_(std::move(path)) {}

    // Reads newly appended data (bounded per call) and forwards it to the sink.
    std::uint64_t pump(const TraceSink& sink, std::size_t budget)
    {
        if (!fd_) {
            fd_.reset(::open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
            if (!fd_) {
                return 0;
            }
        }
        std::uint64_t total = 0;
        while (total < budget) {
            const ssize_t got = ::read(fd_.get(), buffer_.data(), buffer_.size());
            if (got < 0 && errno == EINTR) {
                continue;
            }
            if (got <= 0) {
                break;
            }
            total += static_cast<std::uint64_t>(got);
            sink(std::string_view(buffer_.data(), static_cast<std::size_t>(got)));
        }
        return total;
    }

private:
    std::filesystem::path path_;
    UniqueFd fd_;
    std::array<char, 1 << 16> buffer_{};
};

}  // namespace

std::vector<std::string> straceArguments(const SandboxRunOptions& options)
{
    std::vector<std::string> argv = {options.stracePath.string(), "-f", "-ttt", "-q", "-y", "-s", "4096"};
    if (options.straceSeccompBpf) {
        argv.emplace_back("--seccomp-bpf");
    }
    if (options.stracePidnsTranslation) {
        argv.emplace_back("--pidns-translation");
    }
    argv.insert(argv.end(), {"-o", options.paths.traceLog.string(), "-e", std::string(kTracedSyscalls), "--"});
    return argv;
}

Result<SandboxRunResult> runSandbox(const SandboxRunOptions& options, const CancellationToken& cancel,
                                    const TraceSink& sink, const RunHeartbeat& heartbeat)
{
    const bool tracing = !options.stracePath.empty();
    UniqueFd stdoutFd(::open(options.paths.stdoutLog.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
    UniqueFd stderrFd(::open(options.paths.stderrLog.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!stdoutFd || !stderrFd) {
        return makeError(ErrorCode::Io, "cannot create output capture files: " + errnoMessage(errno));
    }

    SpawnSpec spec;
    std::vector<std::string> argv;
    if (tracing) {
        argv = straceArguments(options);
    }
    const auto helper = helperArguments(options);
    argv.insert(argv.end(), helper.begin(), helper.end());
    spec.executable = argv.front();
    spec.argv = argv;
    // The launcher chain gets a minimal environment; the sandbox environment is set by bwrap.
    spec.environment = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8"};
    spec.stdoutFd = stdoutFd.get();
    spec.stderrFd = stderrFd.get();
    if (options.seccompFd >= 0) {
        spec.inheritedFds.emplace_back(options.seccompFd, kSeccompChildFd);
    }

    // Baseline usage so the disk limit applies to growth caused by the sample.
    const auto baseline = measureTree(options.paths.rootDir, options.maxTreeEntries);
    // Safety net for growth the tree scan cannot see (e.g. beyond its depth limit): the drop in
    // free space on the workspace filesystem, minus what TracePot itself wrote (trace, output).
    const auto baselineFree = freeBytes(options.paths.rootDir);

    SandboxRunResult result;
    result.startEpoch = epochSeconds(std::chrono::system_clock::now());
    const auto start = Clock::now();
    ProcessSupervisor launcher;
    if (auto started = launcher.start(spec); !started) {
        return started.error();
    }

    TraceTail tail(options.paths.traceLog);
    auto lastDiskCheck = start;
    std::optional<Clock::time_point> killDeadline;

    auto terminate = [&](TerminationReason reason, const std::string& detail, const std::string& limit) {
        if (result.forced) {
            return;
        }
        result.forced = reason;
        result.forcedDetail = detail;
        if (!limit.empty()) {
            result.limitEvents.push_back({epochSeconds(std::chrono::system_clock::now()), limit, detail});
        }
        // Kill bubblewrap (and its PID-namespace init). Killing the init process makes the kernel
        // kill every process in the sandbox's PID namespace. The tracer stays alive to record the
        // terminations and then exits on its own.
        std::vector<pid_t> targets;
        if (tracing) {
            targets = childProcesses(launcher.pid());
        } else {
            targets.push_back(launcher.pid());
        }
        const auto direct = targets;
        for (const pid_t pid : direct) {
            for (const pid_t child : childProcesses(pid)) {
                targets.push_back(child);
            }
        }
        for (const pid_t pid : targets) {
            ::kill(pid, SIGKILL);
        }
        if (targets.empty()) {
            launcher.signalGroup(SIGKILL);
        }
        killDeadline = Clock::now() + std::chrono::seconds(5);
    };

    for (;;) {
        const auto status = launcher.waitFor(std::chrono::milliseconds(100));
        result.traceBytes += tail.pump(sink, 8 * MiB);
        if (status) {
            result.launcherStatus = status;
            break;
        }
        const auto now = Clock::now();
        const double elapsed = std::chrono::duration<double>(now - start).count();
        if (killDeadline && now > *killDeadline) {
            launcher.signalGroup(SIGKILL);  // fallback: the launcher did not exit after the kill
            launcher.signalProcess(SIGKILL);
        }
        if (cancel.cancelled()) {
            terminate(TerminationReason::Cancelled, "analysis cancelled by the user", {});
        } else if (options.limits.timeoutSeconds > 0 && elapsed > options.limits.timeoutSeconds) {
            terminate(TerminationReason::Timeout,
                      "wall-clock timeout of " + std::to_string(options.limits.timeoutSeconds) + " s reached",
                      "wall-clock-timeout");
        } else if (result.traceBytes > options.maxTraceBytes) {
            terminate(TerminationReason::ResourceLimit, "trace output exceeded its size limit", "trace-size");
        } else if (now - lastDiskCheck >= std::chrono::seconds(1)) {
            lastDiskCheck = now;
            const auto usage = measureTree(options.paths.rootDir, options.maxTreeEntries);
            if (usage.truncated) {
                terminate(TerminationReason::ResourceLimit,
                          "the sandbox created more than " + std::to_string(options.maxTreeEntries) + " filesystem entries",
                          "file-count");
            } else if (options.limits.maxDiskBytes > 0 && usage.bytes > baseline.bytes + options.limits.maxDiskBytes) {
                terminate(TerminationReason::ResourceLimit, "disk usage growth exceeded the configured limit", "disk");
            } else if (const auto freeNow = freeBytes(options.paths.rootDir);
                       options.limits.maxDiskBytes > 0 && baselineFree && freeNow && *baselineFree > *freeNow) {
                const std::uint64_t drop = *baselineFree - *freeNow;
                const std::uint64_t accounted = result.traceBytes + fileSize(stdoutFd.get()) + fileSize(stderrFd.get());
                const std::uint64_t slack = std::max<std::uint64_t>(64 * MiB, options.limits.maxDiskBytes / 4);
                if (drop > accounted + options.limits.maxDiskBytes + slack) {
                    terminate(TerminationReason::ResourceLimit,
                              "free space on the workspace filesystem dropped by more than the disk limit", "disk");
                }
            }
        }
        if (heartbeat) {
            heartbeat(elapsed);
        }
    }
    // Drain whatever the tracer wrote before exiting.
    for (;;) {
        const auto got = tail.pump(sink, 64 * MiB);
        result.traceBytes += got;
        if (got == 0) {
            break;
        }
    }
    result.wallSeconds = std::chrono::duration<double>(Clock::now() - start).count();
    result.endEpoch = epochSeconds(std::chrono::system_clock::now());
    return result;
}

}  // namespace tracepot
