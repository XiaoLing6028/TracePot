#include "core/sandbox/ProcessSupervisor.hpp"

#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>

#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace tracepot {

namespace {

UniqueFd openPidFd(pid_t pid)
{
#ifdef SYS_pidfd_open
    const long fd = ::syscall(SYS_pidfd_open, pid, 0);
    if (fd >= 0) {
        return UniqueFd(static_cast<int>(fd));
    }
#endif
    (void)pid;
    return UniqueFd();
}

// Marks every descriptor >= 3 close-on-exec in the child. Async-signal-safe.
void closeInheritedDescriptors()
{
#if defined(SYS_close_range) && defined(CLOSE_RANGE_CLOEXEC)
    if (::syscall(SYS_close_range, 3U, ~0U, CLOSE_RANGE_CLOEXEC) == 0) {
        return;
    }
#endif
    struct rlimit limit {};
    long maxFd = 4096;
    if (::getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY) {
        maxFd = static_cast<long>(std::min<rlim_t>(limit.rlim_cur, 65536));
    }
    for (long fd = 3; fd < maxFd; ++fd) {
        const int flags = ::fcntl(static_cast<int>(fd), F_GETFD);
        if (flags >= 0) {
            ::fcntl(static_cast<int>(fd), F_SETFD, flags | FD_CLOEXEC);
        }
    }
}

[[noreturn]] void childFail(int errorPipe, int err)
{
    const ssize_t ignored = ::write(errorPipe, &err, sizeof(err));
    (void)ignored;
    ::_exit(127);
}

ExitStatus decodeStatus(int status)
{
    ExitStatus result;
    if (WIFEXITED(status)) {
        result.exited = true;
        result.code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.signal = WTERMSIG(status);
    }
    return result;
}

}  // namespace

std::string signalName(int signal)
{
    switch (signal) {
    case SIGHUP: return "SIGHUP";
    case SIGINT: return "SIGINT";
    case SIGQUIT: return "SIGQUIT";
    case SIGILL: return "SIGILL";
    case SIGTRAP: return "SIGTRAP";
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGKILL: return "SIGKILL";
    case SIGUSR1: return "SIGUSR1";
    case SIGSEGV: return "SIGSEGV";
    case SIGUSR2: return "SIGUSR2";
    case SIGPIPE: return "SIGPIPE";
    case SIGALRM: return "SIGALRM";
    case SIGTERM: return "SIGTERM";
    case SIGCHLD: return "SIGCHLD";
    case SIGXCPU: return "SIGXCPU";
    case SIGXFSZ: return "SIGXFSZ";
    case SIGSYS: return "SIGSYS";
    default: return "SIG" + std::to_string(signal);
    }
}

ProcessSupervisor::~ProcessSupervisor()
{
    if (running()) {
        signalGroup(SIGKILL);
        signalProcess(SIGKILL);
        reap(true);
    }
}

Status ProcessSupervisor::start(const SpawnSpec& spec)
{
    if (pid_ > 0) {
        return makeError(ErrorCode::Internal, "process supervisor already started");
    }
    if (spec.executable.empty() || spec.executable.front() != '/') {
        return makeError(ErrorCode::InvalidArgument, "executable must be an absolute path");
    }
    // Everything the child needs is prepared before fork(): after fork() in a multi-threaded
    // program only async-signal-safe calls are allowed.
    std::vector<char*> argv;
    argv.reserve(spec.argv.size() + 1);
    for (const auto& arg : spec.argv) {
        argv.push_back(const_cast<char*>(arg.c_str()));
    }
    argv.push_back(nullptr);
    std::vector<char*> envp;
    envp.reserve(spec.environment.size() + 1);
    for (const auto& var : spec.environment) {
        envp.push_back(const_cast<char*>(var.c_str()));
    }
    envp.push_back(nullptr);

    UniqueFd devNull(::open("/dev/null", O_RDWR | O_CLOEXEC));
    if (!devNull) {
        return makeError(ErrorCode::Io, "cannot open /dev/null");
    }
    std::array<int, 2> errorPipe{-1, -1};
    if (::pipe2(errorPipe.data(), O_CLOEXEC) != 0) {
        return makeError(ErrorCode::Io, "pipe2 failed: " + errnoMessage(errno));
    }
    UniqueFd errorRead(errorPipe[0]);
    UniqueFd errorWrite(errorPipe[1]);

    const int stdinFd = spec.stdinFd >= 0 ? spec.stdinFd : devNull.get();
    const int stdoutFd = spec.stdoutFd >= 0 ? spec.stdoutFd : devNull.get();
    const int stderrFd = spec.stderrFd >= 0 ? spec.stderrFd : devNull.get();
    const pid_t parentPid = ::getpid();
    const char* executable = spec.executable.c_str();

    // Duplicate inherited fds above the highest target first so dup2 ordering cannot clobber them.
    std::vector<std::pair<int, int>> inherited;
    std::vector<UniqueFd> holders;
    for (const auto& [source, target] : spec.inheritedFds) {
        const int moved = ::fcntl(source, F_DUPFD_CLOEXEC, 100);
        if (moved < 0) {
            return makeError(ErrorCode::Io, "cannot duplicate descriptor: " + errnoMessage(errno));
        }
        holders.emplace_back(moved);
        inherited.emplace_back(moved, target);
    }
    const int movedStdin = ::fcntl(stdinFd, F_DUPFD_CLOEXEC, 100);
    const int movedStdout = ::fcntl(stdoutFd, F_DUPFD_CLOEXEC, 100);
    const int movedStderr = ::fcntl(stderrFd, F_DUPFD_CLOEXEC, 100);
    holders.emplace_back(movedStdin);
    holders.emplace_back(movedStdout);
    holders.emplace_back(movedStderr);
    if (movedStdin < 0 || movedStdout < 0 || movedStderr < 0) {
        return makeError(ErrorCode::Io, "cannot duplicate standard descriptors");
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        return makeError(ErrorCode::LaunchFailed, "fork failed: " + errnoMessage(errno));
    }
    if (pid == 0) {
        const int errFd = errorWrite.get();
        // New session: the child and everything it spawns outside the sandbox share a process
        // group we can signal as a unit, and the child has no controlling terminal.
        if (::setsid() < 0) {
            childFail(errFd, errno);
        }
        ::prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (::getppid() != parentPid) {
            ::_exit(127);  // parent already died; PDEATHSIG would not fire
        }
        sigset_t all;
        sigemptyset(&all);
        ::sigprocmask(SIG_SETMASK, &all, nullptr);
        struct sigaction defaultAction {};
        defaultAction.sa_handler = SIG_DFL;
        sigemptyset(&defaultAction.sa_mask);
        for (int sig = 1; sig < NSIG; ++sig) {
            if (sig != SIGKILL && sig != SIGSTOP) {
                ::sigaction(sig, &defaultAction, nullptr);
            }
        }
        if (::dup2(movedStdin, 0) < 0 || ::dup2(movedStdout, 1) < 0 || ::dup2(movedStderr, 2) < 0) {
            childFail(errFd, errno);
        }
        closeInheritedDescriptors();
        for (const auto& [source, target] : inherited) {
            if (::dup2(source, target) < 0) {  // dup2 clears FD_CLOEXEC on the new descriptor
                childFail(errFd, errno);
            }
        }
        ::execve(executable, argv.data(), envp.data());
        childFail(errFd, errno);
    }

    pid_ = pid;
    errorWrite.reset();
    holders.clear();
    int childErrno = 0;
    ssize_t got = 0;
    do {
        got = ::read(errorRead.get(), &childErrno, sizeof(childErrno));
    } while (got < 0 && errno == EINTR);
    if (got == static_cast<ssize_t>(sizeof(childErrno))) {
        reap(true);
        return makeError(ErrorCode::LaunchFailed, "cannot execute " + spec.executable + ": " + errnoMessage(childErrno));
    }
    pidFd_ = openPidFd(pid_);
    return {};
}

void ProcessSupervisor::reap(bool block)
{
    if (pid_ <= 0 || status_) {
        return;
    }
    int status = 0;
    for (;;) {
        const pid_t result = ::waitpid(pid_, &status, block ? 0 : WNOHANG);
        if (result == pid_) {
            status_ = decodeStatus(status);
            return;
        }
        if (result == 0) {
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        // ECHILD: someone else reaped it; treat as killed.
        status_ = ExitStatus{false, 0, SIGKILL};
        return;
    }
}

std::optional<ExitStatus> ProcessSupervisor::waitFor(std::chrono::milliseconds timeout)
{
    if (pid_ <= 0) {
        return std::nullopt;
    }
    reap(false);
    if (status_) {
        return status_;
    }
    if (pidFd_) {
        pollfd pfd{pidFd_.get(), POLLIN, 0};
        const int ms = static_cast<int>(std::min<long long>(timeout.count(), INT_MAX));
        while (::poll(&pfd, 1, ms) < 0 && errno == EINTR) {
        }
    } else {
        // Fallback for kernels without pidfd_open: short sleeps.
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            reap(false);
            if (status_) {
                return status_;
            }
            ::usleep(10000);
        }
    }
    reap(false);
    return status_;
}

void ProcessSupervisor::signalGroup(int signal) const
{
    if (pid_ > 0 && !status_) {
        ::kill(-pid_, signal);
    }
}

void ProcessSupervisor::signalProcess(int signal) const
{
    if (pid_ > 0 && !status_) {
        ::kill(pid_, signal);
    }
}

namespace {

std::string readMemfd(int fd, std::size_t maxOutput)
{
    std::string data;
    ::lseek(fd, 0, SEEK_SET);
    std::array<char, 8192> buffer{};
    while (data.size() < maxOutput) {
        const ssize_t got = ::read(fd, buffer.data(), buffer.size());
        if (got <= 0) {
            break;
        }
        data.append(buffer.data(), static_cast<std::size_t>(got));
    }
    if (data.size() > maxOutput) {
        data.resize(maxOutput);
    }
    return data;
}

}  // namespace

Result<CapturedRun> runAndCapture(const std::string& executable, const std::vector<std::string>& argv,
                                  std::chrono::milliseconds timeout, std::size_t maxOutput)
{
    UniqueFd out(::memfd_create("tracepot-out", MFD_CLOEXEC));
    UniqueFd err(::memfd_create("tracepot-err", MFD_CLOEXEC));
    if (!out || !err) {
        return makeError(ErrorCode::Io, "memfd_create failed: " + errnoMessage(errno));
    }
    SpawnSpec spec;
    spec.executable = executable;
    spec.argv = argv;
    spec.environment = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"};
    spec.stdoutFd = out.get();
    spec.stderrFd = err.get();
    ProcessSupervisor process;
    if (auto started = process.start(spec); !started) {
        return started.error();
    }
    CapturedRun run;
    auto status = process.waitFor(timeout);
    if (!status) {
        run.timedOut = true;
        process.signalGroup(SIGKILL);
        process.signalProcess(SIGKILL);
        status = process.waitFor(std::chrono::seconds(5));
    }
    if (status) {
        run.status = *status;
    }
    run.out = readMemfd(out.get(), maxOutput);
    run.err = readMemfd(err.get(), maxOutput);
    return run;
}

std::vector<pid_t> childProcesses(pid_t parent)
{
    std::vector<pid_t> children;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        std::ifstream stat(entry.path() / "stat");
        std::string content;
        std::getline(stat, content);
        // Format: pid (comm) state ppid ... ; comm may contain spaces/parentheses, so find the last ')'.
        const auto close = content.rfind(')');
        if (close == std::string::npos || close + 4 > content.size()) {
            continue;
        }
        const std::string rest = content.substr(close + 2);
        const auto space = rest.find(' ');
        if (space == std::string::npos) {
            continue;
        }
        try {
            const pid_t ppid = static_cast<pid_t>(std::stol(rest.substr(space + 1)));
            if (ppid == parent) {
                children.push_back(static_cast<pid_t>(std::stol(name)));
            }
        } catch (const std::exception&) {
            continue;
        }
    }
    return children;
}

}  // namespace tracepot
