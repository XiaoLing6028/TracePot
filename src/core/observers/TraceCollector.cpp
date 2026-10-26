#include "core/observers/TraceCollector.hpp"

#include "core/observers/NetworkObserver.hpp"
#include "core/util/Glob.hpp"
#include "core/util/PathUtil.hpp"

#include <algorithm>
#include <array>

namespace tracepot {

namespace {

bool startsWith(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool hasFlag(std::string_view flags, std::string_view flag)
{
    std::size_t start = 0;
    while (start <= flags.size()) {
        const auto bar = flags.find('|', start);
        const auto token = flags.substr(start, bar == std::string_view::npos ? std::string_view::npos : bar - start);
        if (token == flag) {
            return true;
        }
        if (bar == std::string_view::npos) {
            break;
        }
        start = bar + 1;
    }
    return false;
}

std::string stripDeleted(std::string path)
{
    constexpr std::string_view kSuffix = " (deleted)";
    if (path.size() > kSuffix.size() && path.compare(path.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0) {
        path.resize(path.size() - kSuffix.size());
    }
    return path;
}

// Extracts the raw value of `field` from a strace struct token "{a=1, b={...}, ...}".
std::optional<std::string> structField(std::string_view token, std::string_view field)
{
    if (token.size() < 2 || token.front() != '{') {
        return std::nullopt;
    }
    const auto close = token.rfind('}');
    if (close == std::string_view::npos) {
        return std::nullopt;
    }
    for (const auto& part : splitArguments(token.substr(1, close - 1))) {
        if (part.size() > field.size() && startsWith(part, field) && part[field.size()] == '=') {
            return part.substr(field.size() + 1);
        }
    }
    return std::nullopt;
}

std::string familyLabel(std::string_view family)
{
    if (family == "AF_INET") return "ipv4";
    if (family == "AF_INET6") return "ipv6";
    if (family == "AF_UNIX") return "unix";
    return {};
}

std::string networkFailureDetail(const std::string& errnoName)
{
    if (errnoName == "ENETUNREACH" || errnoName == "EHOSTUNREACH") {
        return "no route: the sandbox network namespace has no external interface";
    }
    if (errnoName == "ECONNREFUSED") {
        return "refused: nothing is listening at this address inside the sandbox";
    }
    if (errnoName == "ENOENT") {
        return "socket path does not exist inside the sandbox";
    }
    if (errnoName == "EINPROGRESS") {
        return "non-blocking connect started; completion was not observed";
    }
    return errnoName.empty() ? std::string() : "failed with " + errnoName;
}

std::string redactUrl(const std::string& url)
{
    const auto scheme = url.find("://");
    if (scheme == std::string::npos) {
        return url;
    }
    const auto hostStart = scheme + 3;
    const auto pathStart = url.find_first_of("/?#", hostStart);
    const auto at = url.rfind('@', pathStart == std::string::npos ? std::string::npos : pathStart);
    if (at == std::string::npos || at < hostStart) {
        return url;
    }
    return url.substr(0, hostStart) + "[credentials]@" + url.substr(at + 1);
}

bool isNoiseDevice(const std::string& path)
{
    static constexpr std::array<std::string_view, 7> kDevices = {"/dev/null", "/dev/zero", "/dev/full", "/dev/tty",
                                                                 "/dev/stdout", "/dev/stderr", "/dev/stdin"};
    return std::find(kDevices.begin(), kDevices.end(), path) != kDevices.end() || startsWith(path, "/dev/fd/") ||
           startsWith(path, "/proc/self/fd/");
}

bool isFileEvent(EventType type)
{
    switch (type) {
    case EventType::FileWrite:
    case EventType::FileDelete:
    case EventType::FileRename:
    case EventType::DirectoryCreate:
    case EventType::DirectoryDelete:
    case EventType::SymlinkCreate:
    case EventType::HardlinkCreate:
    case EventType::PermissionChange:
    case EventType::OwnershipChange:
    case EventType::FileTruncate:
    case EventType::SensitiveRead:
        return true;
    default:
        return false;
    }
}

Outcome outcomeOf(const SyscallRecord& record)
{
    if (!record.returnKnown) {
        return Outcome::Unknown;
    }
    return record.succeeded() ? Outcome::Success : Outcome::Failed;
}

std::string argOr(const SyscallRecord& record, std::size_t index)
{
    return index < record.args.size() ? record.args[index] : std::string();
}

std::string joinArgv(const std::vector<std::string>& argv, std::size_t maxBytes)
{
    std::string joined;
    for (const auto& arg : argv) {
        if (!joined.empty()) {
            joined += ' ';
        }
        joined += arg;
        if (joined.size() > maxBytes) {
            joined.resize(maxBytes);
            joined += "...";
            break;
        }
    }
    return joined;
}

}  // namespace

TraceCollector::TraceCollector(TraceCollectorOptions options) : options_(std::move(options)) {}

void TraceCollector::feed(std::string_view chunk)
{
    std::size_t start = 0;
    while (start < chunk.size()) {
        const auto newline = chunk.find('\n', start);
        if (newline == std::string_view::npos) {
            if (!skippingLongLine_) {
                partial_.append(chunk.substr(start));
                if (partial_.size() > options_.maxLineBytes) {
                    partial_.clear();
                    skippingLongLine_ = true;
                    ++linesMalformed_;
                }
            }
            return;
        }
        const auto piece = chunk.substr(start, newline - start);
        if (skippingLongLine_) {
            skippingLongLine_ = false;  // end of an oversized line that was already discarded
        } else if (partial_.empty()) {
            if (piece.size() <= options_.maxLineBytes) {
                handleLine(piece);
            } else {
                ++linesMalformed_;
            }
        } else {
            partial_.append(piece);
            if (partial_.size() <= options_.maxLineBytes) {
                handleLine(partial_);
            } else {
                ++linesMalformed_;
            }
            partial_.clear();
        }
        start = newline + 1;
    }
}

void TraceCollector::handleLine(std::string_view line)
{
    if (line.empty()) {
        return;
    }
    auto parsed = parseStraceLine(line);
    if (!parsed) {
        ++linesMalformed_;
        return;
    }
    ++linesParsed_;
    switch (parsed->kind) {
    case StraceLine::Kind::Exited:
    case StraceLine::Kind::Killed:
    case StraceLine::Kind::Signal:
        (void)assembler_.push(*parsed);
        handleExitLine(*parsed);
        return;
    default:
        break;
    }
    if (auto record = assembler_.push(*parsed)) {
        handleRecord(*record);
    } else if (parsed->kind == StraceLine::Kind::Syscall) {
        ++linesMalformed_;
    }
}

void TraceCollector::handleExitLine(const StraceLine& line)
{
    if (!entryPid_ || infrastructurePids_.count(line.pid) != 0) {
        return;
    }
    int tgid = line.pid;
    if (processes_.count(line.pid) == 0) {
        const auto thread = threadToProcess_.find(line.pid);
        if (thread == threadToProcess_.end()) {
            if (bufferedCount_ < options_.maxBufferedRecords) {
                buffered_[line.pid].emplace_back(line);
                ++bufferedCount_;
            }
            return;
        }
        tgid = thread->second;
        if (line.kind != StraceLine::Kind::Signal) {
            return;  // a thread ending does not end its process
        }
    }
    ProcessRecord& process = processes_[tgid];
    switch (line.kind) {
    case StraceLine::Kind::Exited:
        process.exitCode = line.exitCode;
        process.endTime = line.timestamp;
        break;
    case StraceLine::Kind::Killed:
        process.signal = line.name;
        process.endTime = line.timestamp;
        break;
    case StraceLine::Kind::Signal:
        if (line.name == "SIGXFSZ") {
            limitEvents_.push_back({line.timestamp, "file-size",
                                    "process " + std::to_string(tgid) + " exceeded the maximum file size (SIGXFSZ)"});
        } else if (line.name == "SIGXCPU") {
            limitEvents_.push_back({line.timestamp, "cpu-time",
                                    "process " + std::to_string(tgid) + " exceeded its CPU time limit (SIGXCPU)"});
        }
        break;
    default:
        break;
    }
}

void TraceCollector::handleRecord(const SyscallRecord& record)
{
    if (!entryPid_) {
        if ((record.name == "execve") && record.args.size() >= 2) {
            const auto path = decodeQuotedString(record.args[0]);
            const auto argv = parseStringArray(record.args[1]);
            const std::size_t compare = std::min<std::size_t>(2, options_.entryArgv.size());
            const bool argvMatches =
                argv.size() >= compare && std::equal(options_.entryArgv.begin(),
                                                     options_.entryArgv.begin() + static_cast<long>(compare), argv.begin());
            if (path && *path == options_.entryExecutable && argvMatches) {
                entryPid_ = record.pid;
                infrastructurePids_.erase(record.pid);
                adoptProcess(record.pid, std::nullopt, record.timestamp);
                cwd_[record.pid] = options_.initialCwd;
                onExec(record.pid, record);
                return;
            }
        }
        infrastructurePids_.insert(record.pid);  // bubblewrap's own setup activity
        return;
    }
    if (infrastructurePids_.count(record.pid) != 0) {
        return;
    }
    int tgid = record.pid;
    if (processes_.count(record.pid) == 0) {
        const auto thread = threadToProcess_.find(record.pid);
        if (thread != threadToProcess_.end()) {
            tgid = thread->second;
        } else if (!options_.pidTranslationAvailable) {
            adoptProcess(record.pid, std::nullopt, record.timestamp);
        } else {
            // A child whose creating clone() has not been reported yet: strace may print the
            // child's first syscalls before the parent's clone() returns.
            if (bufferedCount_ < options_.maxBufferedRecords) {
                buffered_[record.pid].emplace_back(record);
                ++bufferedCount_;
            } else {
                ++eventsDropped_;
            }
            return;
        }
    }
    dispatch(tgid, record);
}

void TraceCollector::adoptProcess(int pid, std::optional<int> ppid, double timestamp)
{
    ProcessRecord& process = processes_[pid];
    process.pid = pid;
    process.ppid = ppid;
    if (!process.startTime) {
        process.startTime = timestamp;
    }
    if (ppid) {
        if (const auto it = cwd_.find(*ppid); it != cwd_.end()) {
            cwd_[pid] = it->second;
        }
    }
    const auto buffered = buffered_.find(pid);
    if (buffered == buffered_.end()) {
        return;
    }
    std::vector<Buffered> items = std::move(buffered->second);
    buffered_.erase(buffered);
    bufferedCount_ -= std::min(bufferedCount_, items.size());
    for (const auto& item : items) {
        if (const auto* record = std::get_if<SyscallRecord>(&item)) {
            dispatch(pid, *record);
        } else {
            handleExitLine(std::get<StraceLine>(item));
        }
    }
}

void TraceCollector::dispatch(int tgid, const SyscallRecord& record)
{
    const std::string& name = record.name;
    if (name == "clone" || name == "clone3" || name == "fork" || name == "vfork") {
        onClone(tgid, record);
    } else if (name == "execve" || name == "execveat") {
        onExec(tgid, record);
    } else if (name == "chdir") {
        if (record.succeeded()) {
            if (auto path = decodeQuotedString(argOr(record, 0))) {
                cwd_[tgid] = resolvePath(tgid, nullptr, *path);
            }
        }
    } else if (name == "fchdir") {
        if (record.succeeded()) {
            const auto fd = parseFdToken(argOr(record, 0));
            if (!fd.path.empty() && fd.path.front() == '/') {
                cwd_[tgid] = stripDeleted(fd.path);
            }
        }
    } else if (name == "open" || name == "openat" || name == "creat" || name == "openat2") {
        onOpen(tgid, record);
    } else if (name == "socket") {
        onSocket(record);
    } else if (name == "connect" || name == "bind") {
        onConnectOrBind(tgid, record);
    } else if (name == "listen") {
        onListen(tgid, record);
    } else if (name == "sendto" || name == "sendmsg" || name == "sendmmsg") {
        onSend(tgid, record);
    } else if (name != "exit_group" && name != "exit") {
        onPathMutation(tgid, record);
    }
}

void TraceCollector::onClone(int tgid, const SyscallRecord& record)
{
    std::string joined;
    for (const auto& arg : record.args) {
        joined += arg;
        joined += ' ';
    }
    const bool thread = joined.find("CLONE_THREAD") != std::string::npos;
    if (!record.succeeded()) {
        if (record.errnoName == "EAGAIN") {
            if (!processLimitNoted_) {
                limitEvents_.push_back({record.timestamp, "process-count",
                                        "process creation failed with EAGAIN (process limit reached)"});
                processLimitNoted_ = true;
            }
        }
        TraceEvent event;
        event.timestamp = record.timestamp;
        event.pid = tgid;
        event.type = EventType::ProcessSpawn;
        event.syscall = record.name;
        event.outcome = outcomeOf(record);
        event.error = record.errnoName;
        event.detail = thread ? "thread creation failed" : "process creation failed";
        addEvent(std::move(event));
        return;
    }
    if (!record.translatedPid || *record.translatedPid <= 0) {
        return;  // children are adopted lazily when PID translation is unavailable
    }
    const int child = static_cast<int>(*record.translatedPid);
    if (thread) {
        threadToProcess_[child] = tgid;
        ++processes_[tgid].threadCount;
        const auto buffered = buffered_.find(child);
        if (buffered != buffered_.end()) {
            auto items = std::move(buffered->second);
            buffered_.erase(buffered);
            bufferedCount_ -= std::min(bufferedCount_, items.size());
            for (const auto& item : items) {
                if (const auto* r = std::get_if<SyscallRecord>(&item)) {
                    dispatch(tgid, *r);
                } else {
                    handleExitLine(std::get<StraceLine>(item));
                }
            }
        }
        return;
    }
    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = EventType::ProcessSpawn;
    event.syscall = record.name;
    event.outcome = Outcome::Success;
    event.detail = "created child process " + std::to_string(child);
    addEvent(std::move(event));
    adoptProcess(child, tgid, record.timestamp);
}

void TraceCollector::onExec(int tgid, const SyscallRecord& record)
{
    std::optional<std::string> path;
    std::vector<std::string> argv;
    if (record.name == "execve") {
        path = decodeQuotedString(argOr(record, 0));
        argv = parseStringArray(argOr(record, 1));
    } else {
        const auto dir = parseFdToken(argOr(record, 0));
        if (auto relative = decodeQuotedString(argOr(record, 1))) {
            path = resolvePath(tgid, &dir, *relative);
        }
        argv = parseStringArray(argOr(record, 2));
    }
    if (!path) {
        return;
    }
    ExecRecord exec;
    exec.timestamp = record.timestamp;
    exec.path = displaySafe(*path);
    for (const auto& arg : argv) {
        exec.argv.push_back(displaySafe(arg));
    }
    exec.outcome = outcomeOf(record);
    exec.error = record.errnoName;
    ProcessRecord& process = processes_[tgid];
    if (process.execs.size() < 256) {
        process.execs.push_back(exec);
    }

    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = EventType::ProcessExec;
    event.syscall = record.name;
    event.path = exec.path;
    event.detail = joinArgv(exec.argv, 1024);
    event.outcome = exec.outcome;
    event.error = exec.error;
    addEvent(std::move(event));

    if (exec.outcome == Outcome::Success) {
        for (const auto& url : extractUrls(argv)) {
            const auto parts = parseUrl(url);
            if (!parts) {
                continue;
            }
            NetworkEvent net;
            net.timestamp = record.timestamp;
            net.pid = tgid;
            net.kind = NetworkEventKind::InferredDestination;
            net.protocol = parts->scheme;
            net.hostname = displaySafe(parts->host);
            net.port = parts->port;
            net.outcome = Outcome::Unknown;
            net.evidence = EvidenceKind::Inferred;
            net.source = ObservationSource::CommandLine;
            net.detail = "URL in the command line of " + exec.path + ": " + displaySafe(redactUrl(url));
            addNetworkEvent(std::move(net));
        }
    }
}

void TraceCollector::onOpen(int tgid, const SyscallRecord& record)
{
    std::string pathToken;
    std::string flags;
    std::optional<FdRef> dir;
    if (record.name == "open") {
        pathToken = argOr(record, 0);
        flags = argOr(record, 1);
    } else if (record.name == "creat") {
        pathToken = argOr(record, 0);
        flags = "O_WRONLY|O_CREAT|O_TRUNC";
    } else {
        noteFdcwd(tgid, argOr(record, 0));
        dir = parseFdToken(argOr(record, 0));
        pathToken = argOr(record, 1);
        flags = argOr(record, 2);
        if (record.name == "openat2") {
            flags = structField(flags, "flags").value_or(std::string());
        }
    }
    const auto requested = decodeQuotedString(pathToken);
    if (!requested) {
        return;
    }
    std::string resolved;
    if (record.succeeded() && startsWith(record.returnDecoration, "/")) {
        resolved = stripDeleted(record.returnDecoration);  // the kernel's view of the opened file
    } else {
        resolved = resolvePath(tgid, dir ? &*dir : nullptr, *requested);
    }
    const bool writeIntent = hasFlag(flags, "O_WRONLY") || hasFlag(flags, "O_RDWR") || hasFlag(flags, "O_CREAT") ||
                             hasFlag(flags, "O_TRUNC") || hasFlag(flags, "O_APPEND");
    if (!writeIntent) {
        ++readOnlyOpens_;
        const bool sensitive = std::any_of(options_.sensitiveReadPatterns.begin(), options_.sensitiveReadPatterns.end(),
                                           [&resolved](const std::string& p) { return globMatch(p, resolved); });
        if (sensitive) {
            TraceEvent event;
            event.timestamp = record.timestamp;
            event.pid = tgid;
            event.type = EventType::SensitiveRead;
            event.syscall = record.name;
            event.path = displaySafe(resolved);
            event.detail = "read access to a credential or secret location";
            event.outcome = outcomeOf(record);
            event.error = record.errnoName;
            addEvent(std::move(event));
        }
        return;
    }
    if (isNoiseDevice(resolved)) {
        return;
    }
    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = EventType::FileWrite;
    event.syscall = record.name;
    event.path = displaySafe(resolved);
    event.detail = displaySafe(flags);
    event.outcome = outcomeOf(record);
    event.error = record.errnoName;
    addEvent(std::move(event));
}

void TraceCollector::onPathMutation(int tgid, const SyscallRecord& record)
{
    struct Spec {
        std::string_view name;
        EventType type;
        int dir;        // index of dirfd argument, -1 if none
        int path;       // index of path argument (or fd argument when isFd)
        int dir2;
        int path2;      // second path (rename/link target), -1 if none
        int detail;     // index of mode/len argument, -1 if none
        bool isFd;      // path argument is a descriptor (fchmod, fchown)
    };
    static constexpr std::array<Spec, 21> kSpecs = {{
        {"unlink", EventType::FileDelete, -1, 0, -1, -1, -1, false},
        {"unlinkat", EventType::FileDelete, 0, 1, -1, -1, 2, false},
        {"rmdir", EventType::DirectoryDelete, -1, 0, -1, -1, -1, false},
        {"rename", EventType::FileRename, -1, 0, -1, 1, -1, false},
        {"renameat", EventType::FileRename, 0, 1, 2, 3, -1, false},
        {"renameat2", EventType::FileRename, 0, 1, 2, 3, 4, false},
        {"mkdir", EventType::DirectoryCreate, -1, 0, -1, -1, 1, false},
        {"mkdirat", EventType::DirectoryCreate, 0, 1, -1, -1, 2, false},
        {"symlink", EventType::SymlinkCreate, -1, 1, -1, -1, -1, false},
        {"symlinkat", EventType::SymlinkCreate, 1, 2, -1, -1, -1, false},
        {"link", EventType::HardlinkCreate, -1, 1, -1, 0, -1, false},
        {"linkat", EventType::HardlinkCreate, 2, 3, 0, 1, -1, false},
        {"chmod", EventType::PermissionChange, -1, 0, -1, -1, 1, false},
        {"fchmod", EventType::PermissionChange, -1, 0, -1, -1, 1, true},
        {"fchmodat", EventType::PermissionChange, 0, 1, -1, -1, 2, false},
        {"fchmodat2", EventType::PermissionChange, 0, 1, -1, -1, 2, false},
        {"chown", EventType::OwnershipChange, -1, 0, -1, -1, 1, false},
        {"lchown", EventType::OwnershipChange, -1, 0, -1, -1, 1, false},
        {"fchown", EventType::OwnershipChange, -1, 0, -1, -1, 1, true},
        {"fchownat", EventType::OwnershipChange, 0, 1, -1, -1, 2, false},
        {"truncate", EventType::FileTruncate, -1, 0, -1, -1, 1, false},
    }};
    const auto spec = std::find_if(kSpecs.begin(), kSpecs.end(), [&](const Spec& s) { return s.name == record.name; });
    if (spec == kSpecs.end()) {
        return;
    }
    auto pathAt = [&](int dirIndex, int pathIndex) -> std::optional<std::string> {
        if (pathIndex < 0) {
            return std::nullopt;
        }
        std::optional<FdRef> dir;
        if (dirIndex >= 0) {
            noteFdcwd(tgid, argOr(record, static_cast<std::size_t>(dirIndex)));
            dir = parseFdToken(argOr(record, static_cast<std::size_t>(dirIndex)));
        }
        const auto raw = decodeQuotedString(argOr(record, static_cast<std::size_t>(pathIndex)));
        if (!raw) {
            return std::nullopt;
        }
        return resolvePath(tgid, dir ? &*dir : nullptr, *raw);
    };

    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = spec->type;
    event.syscall = record.name;
    event.outcome = outcomeOf(record);
    event.error = record.errnoName;

    if (spec->isFd) {
        const auto fd = parseFdToken(argOr(record, static_cast<std::size_t>(spec->path)));
        if (fd.path.empty()) {
            return;
        }
        event.path = displaySafe(stripDeleted(fd.path));
    } else {
        const auto path = pathAt(spec->dir, spec->path);
        if (!path) {
            return;
        }
        event.path = displaySafe(*path);
    }

    if (spec->type == EventType::SymlinkCreate) {
        // The link target is recorded verbatim; it is interpreted relative to the link itself.
        if (auto target = decodeQuotedString(argOr(record, 0))) {
            event.targetPath = displaySafe(*target);
        }
    } else if (spec->path2 >= 0) {
        // rename: path = source, targetPath = destination.
        // link:   path = new name, targetPath = existing file (see the spec table).
        if (auto second = pathAt(spec->dir2, spec->path2)) {
            event.targetPath = displaySafe(*second);
        }
    }
    if (spec->type == EventType::OwnershipChange) {
        const auto uidIndex = static_cast<std::size_t>(spec->detail);
        event.detail = "uid " + argOr(record, uidIndex) + ", gid " + argOr(record, uidIndex + 1);
    } else if (spec->detail >= 0) {
        event.detail = displaySafe(argOr(record, static_cast<std::size_t>(spec->detail)));
    }
    if (record.name == "unlinkat" && hasFlag(argOr(record, 2), "AT_REMOVEDIR")) {
        event.type = EventType::DirectoryDelete;
    }
    if (event.type == EventType::DirectoryCreate && event.error == "EEXIST") {
        return;  // e.g. `mkdir -p` walking existing parents: no information, only noise
    }
    addEvent(std::move(event));
}

void TraceCollector::onSocket(const SyscallRecord& record)
{
    if (!record.succeeded() || !startsWith(record.returnDecoration, "socket:[")) {
        return;
    }
    const auto inode = std::strtoull(record.returnDecoration.c_str() + 8, nullptr, 10);
    SocketInfo info;
    info.domain = argOr(record, 0);
    const std::string type = argOr(record, 1);
    if (info.domain == "AF_UNIX") {
        info.protocol = "unix";
    } else if (hasFlag(type, "SOCK_STREAM")) {
        info.protocol = "tcp";
    } else if (hasFlag(type, "SOCK_DGRAM")) {
        info.protocol = "udp";
    } else if (hasFlag(type, "SOCK_RAW")) {
        info.protocol = "raw";
    } else {
        info.protocol = "unknown";
    }
    sockets_[inode] = std::move(info);
}

void TraceCollector::onConnectOrBind(int tgid, const SyscallRecord& record)
{
    const auto fd = parseFdToken(argOr(record, 0));
    const auto addr = parseSockAddr(argOr(record, 1));
    if (!addr) {
        return;
    }
    const std::string family = familyLabel(addr->family);
    if (family.empty()) {
        return;  // netlink and other families are not network traffic
    }
    SocketInfo* socket = nullptr;
    if (fd.socketInode) {
        socket = &sockets_[*fd.socketInode];
    }
    const bool connect = record.name == "connect";
    if (socket != nullptr) {
        (connect ? socket->remote : socket->local) = *addr;
    }
    NetworkEvent net;
    net.timestamp = record.timestamp;
    net.pid = tgid;
    net.family = family;
    net.protocol = socket != nullptr && !socket->protocol.empty() ? socket->protocol
                                                                  : (family == "unix" ? "unix" : "unknown");
    net.address = displaySafe(addr->address);
    net.port = addr->port;
    net.error = record.errnoName;
    // "success" is reserved for outcomes that mean what they say: an established TCP connection or
    // a reachable local socket. A UDP connect() only associates an address and sends nothing, and a
    // non-blocking connect() that returned EINPROGRESS did not complete while being observed.
    const bool udpAssociation = connect && net.protocol == "udp" && record.succeeded();
    if (record.errnoName == "EINPROGRESS" || udpAssociation) {
        net.outcome = Outcome::Unknown;
    } else {
        net.outcome = outcomeOf(record);
    }
    if (family == "unix") {
        net.kind = NetworkEventKind::LocalSocket;
        net.detail = std::string(connect ? "connect to" : "bind") + " local socket";
    } else {
        net.kind = connect ? NetworkEventKind::Connect : NetworkEventKind::Bind;
        if (udpAssociation) {
            net.detail = "UDP socket associated with destination (no packet or response implied)";
        } else if (net.outcome == Outcome::Success) {
            if (!connect) {
                net.detail = "bound local address";
            } else {
                net.detail = "connection established (only loopback services inside the sandbox are reachable)";
            }
        } else {
            net.detail = networkFailureDetail(record.errnoName);
        }
    }
    if (addr->port && *addr->port == 53 && connect) {
        net.detail += "; DNS port";
    }
    addNetworkEvent(net);

    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = connect ? EventType::NetworkConnect : EventType::NetworkBind;
    event.syscall = record.name;
    event.path = net.address + (net.port ? ":" + std::to_string(*net.port) : std::string());
    event.detail = net.protocol;
    event.outcome = outcomeOf(record);
    event.error = record.errnoName;
    addEvent(std::move(event));
}

void TraceCollector::onListen(int tgid, const SyscallRecord& record)
{
    const auto fd = parseFdToken(argOr(record, 0));
    NetworkEvent net;
    net.timestamp = record.timestamp;
    net.pid = tgid;
    net.kind = NetworkEventKind::Listen;
    net.outcome = outcomeOf(record);
    net.error = record.errnoName;
    net.detail = "listening socket";
    if (fd.socketInode) {
        const auto it = sockets_.find(*fd.socketInode);
        if (it != sockets_.end()) {
            net.protocol = it->second.protocol;
            if (it->second.local) {
                net.family = familyLabel(it->second.local->family);
                net.address = displaySafe(it->second.local->address);
                net.port = it->second.local->port;
            }
        }
    }
    addNetworkEvent(std::move(net));
    TraceEvent event;
    event.timestamp = record.timestamp;
    event.pid = tgid;
    event.type = EventType::NetworkListen;
    event.syscall = record.name;
    event.outcome = outcomeOf(record);
    event.error = record.errnoName;
    addEvent(std::move(event));
}

void TraceCollector::recordDatagram(int tgid, const SyscallRecord& record, const SockAddr& destination,
                                    const std::string& payload, const std::string& protocol)
{
    const std::string family = familyLabel(destination.family);
    if (family.empty() || family == "unix") {
        return;
    }
    if (destination.port && *destination.port == 53) {
        const auto questions = decodeDnsQuery(payload);
        auto base = [&]() {
            NetworkEvent net;
            net.timestamp = record.timestamp;
            net.pid = tgid;
            net.kind = NetworkEventKind::DnsQuery;
            net.protocol = protocol.empty() ? "udp" : protocol;
            net.family = family;
            net.address = displaySafe(destination.address);
            net.port = 53;
            // A successful send() only means the kernel accepted the packet; no answer was observed.
            net.outcome = record.succeeded() ? Outcome::Unknown : outcomeOf(record);
            net.error = record.errnoName;
            return net;
        };
        if (questions.empty()) {
            NetworkEvent net = base();
            net.detail = "datagram to DNS port (payload not decodable as a DNS query)";
            addNetworkEvent(std::move(net));
        }
        for (const auto& question : questions) {
            NetworkEvent net = base();
            net.hostname = displaySafe(question.name);
            net.detail = "DNS " + question.type + " query sent to resolver; no answer is possible under the "
                         "isolated network policy";
            addNetworkEvent(std::move(net));
        }
        return;
    }
    if (protocol == "tcp") {
        return;  // stream data on a connected socket; the connect() is already recorded
    }
    NetworkEvent net;
    net.timestamp = record.timestamp;
    net.pid = tgid;
    net.kind = NetworkEventKind::Datagram;
    net.protocol = protocol.empty() ? "udp" : protocol;
    net.family = family;
    net.address = displaySafe(destination.address);
    net.port = destination.port;
    net.outcome = record.succeeded() ? Outcome::Unknown : outcomeOf(record);
    net.error = record.errnoName;
    net.detail = record.succeeded() ? "datagram handed to the kernel (delivery not observed)"
                                    : networkFailureDetail(record.errnoName);
    addNetworkEvent(std::move(net));
}

void TraceCollector::onSend(int tgid, const SyscallRecord& record)
{
    const auto fd = parseFdToken(argOr(record, 0));
    const SocketInfo* socket = nullptr;
    if (fd.socketInode) {
        const auto it = sockets_.find(*fd.socketInode);
        if (it != sockets_.end()) {
            socket = &it->second;
        }
    }
    const std::string protocol = socket != nullptr ? socket->protocol : std::string();
    auto destinationOr = [&](std::optional<SockAddr> explicitAddress) -> std::optional<SockAddr> {
        if (explicitAddress) {
            return explicitAddress;
        }
        if (socket != nullptr && socket->remote) {
            return socket->remote;
        }
        return std::nullopt;
    };
    auto handleMsgHdr = [&](const std::string& header) {
        std::optional<SockAddr> address;
        if (auto name = structField(header, "msg_name")) {
            address = parseSockAddr(*name);
        }
        std::string payload;
        if (auto iov = structField(header, "msg_iov")) {
            const auto open = iov->find('{');
            if (open != std::string::npos) {
                const auto close = iov->rfind('}');
                if (auto base = structField(iov->substr(open, close - open + 1), "iov_base")) {
                    payload = decodeQuotedString(*base).value_or(std::string());
                }
            }
        }
        if (auto destination = destinationOr(address)) {
            recordDatagram(tgid, record, *destination, payload, protocol);
        }
    };

    if (record.name == "sendto") {
        std::optional<SockAddr> address;
        if (record.args.size() >= 5) {
            address = parseSockAddr(record.args[4]);
        }
        if (auto destination = destinationOr(address)) {
            recordDatagram(tgid, record, *destination, decodeQuotedString(argOr(record, 1)).value_or(std::string()),
                           protocol);
        }
    } else if (record.name == "sendmsg") {
        handleMsgHdr(argOr(record, 1));
    } else {
        const std::string vector = argOr(record, 1);
        if (vector.size() >= 2 && vector.front() == '[') {
            const auto close = vector.rfind(']');
            for (const auto& element : splitArguments(std::string_view(vector).substr(1, close - 1))) {
                if (auto header = structField(element, "msg_hdr")) {
                    handleMsgHdr(*header);
                }
            }
        }
    }
}

std::string TraceCollector::cwdOf(int tgid) const
{
    const auto it = cwd_.find(tgid);
    return it == cwd_.end() ? std::string() : it->second;
}

void TraceCollector::noteFdcwd(int tgid, const std::string& token)
{
    if (!startsWith(token, "AT_FDCWD<")) {
        return;
    }
    const auto ref = parseFdToken(token);
    if (!ref.path.empty() && ref.path.front() == '/') {
        cwd_[tgid] = stripDeleted(ref.path);
    }
}

std::string TraceCollector::resolvePath(int tgid, const FdRef* dirFd, const std::string& path)
{
    if (!path.empty() && path.front() == '/') {
        return normalizeAbsolute(path);
    }
    std::string base;
    if (dirFd != nullptr && !dirFd->path.empty()) {
        base = stripDeleted(dirFd->path);
    } else if (dirFd == nullptr || dirFd->atFdcwd) {
        base = cwdOf(tgid);
    }
    if (base.empty() || base.front() != '/') {
        return path.empty() ? std::string("?") : "?/" + path;  // base directory unknown
    }
    if (path.empty()) {
        return normalizeAbsolute(base);  // e.g. AT_EMPTY_PATH operations on a descriptor
    }
    return resolveAgainst(base, path);
}

void TraceCollector::addEvent(TraceEvent event)
{
    if (events_.size() >= options_.maxEvents) {
        ++eventsDropped_;
        return;
    }
    event.seq = nextSeq_++;
    if (isFileEvent(event.type)) {
        ++fileEventCount_;
    }
    events_.push_back(std::move(event));
}

void TraceCollector::addNetworkEvent(NetworkEvent event)
{
    if (networkEvents_.size() >= options_.maxEvents) {
        ++eventsDropped_;
        return;
    }
    networkEvents_.push_back(std::move(event));
}

void TraceCollector::finish()
{
    if (!partial_.empty() && !skippingLongLine_) {
        const std::string last = std::move(partial_);
        partial_.clear();
        handleLine(last);
    }
    // Records from PIDs whose creation was never reported. Adopt those that did real work (they
    // can only be sandbox processes, since bubblewrap's PIDs were registered before the entry).
    std::vector<int> pending;
    for (const auto& [pid, items] : buffered_) {
        pending.push_back(pid);
    }
    for (const int pid : pending) {
        const auto it = buffered_.find(pid);
        if (it == buffered_.end()) {
            continue;
        }
        const bool active = std::any_of(it->second.begin(), it->second.end(), [](const Buffered& item) {
            const auto* record = std::get_if<SyscallRecord>(&item);
            return record != nullptr && record->name != "exit_group" && record->name != "exit";
        });
        if (!active) {
            buffered_.erase(it);
            continue;
        }
        double first = 0;
        if (const auto* record = std::get_if<SyscallRecord>(&it->second.front())) {
            first = record->timestamp;
        }
        warnings_.push_back("parent of process " + std::to_string(pid) + " could not be determined");
        adoptProcess(pid, std::nullopt, first);
    }

    // Records of children can be processed after their parent's later records (they are buffered
    // until the parent's clone() returns), so restore chronological order and renumber.
    std::stable_sort(events_.begin(), events_.end(),
                     [](const TraceEvent& a, const TraceEvent& b) { return a.timestamp < b.timestamp; });
    for (std::size_t i = 0; i < events_.size(); ++i) {
        events_[i].seq = i + 1;
    }
    std::stable_sort(networkEvents_.begin(), networkEvents_.end(), [](const NetworkEvent& a, const NetworkEvent& b) {
        return a.timestamp.value_or(0) < b.timestamp.value_or(0);
    });

    if (!entryPid_) {
        warnings_.emplace_back("the entry process was never observed in the trace");
        return;
    }
    const ProcessRecord& entry = processes_[*entryPid_];
    bool missingEnd = false;
    for (auto& [pid, process] : processes_) {
        if (!process.endTime) {
            missingEnd = true;
            continue;
        }
        if (pid != *entryPid_ && entry.endTime && process.signal == "SIGKILL" &&
            *process.endTime + 0.001 >= *entry.endTime) {
            process.terminatedAtTeardown = true;
        }
    }
    if (missingEnd) {
        warnings_.emplace_back("the end of some processes was not observed (trace ended first)");
    }
}

TraceCounts TraceCollector::counts() const
{
    TraceCounts counts;
    counts.processes = processes_.size();
    counts.fileEvents = fileEventCount_;
    counts.networkEvents = networkEvents_.size();
    counts.lines = linesParsed_;
    return counts;
}

const ProcessRecord* TraceCollector::entryProcess() const
{
    if (!entryPid_) {
        return nullptr;
    }
    const auto it = processes_.find(*entryPid_);
    return it == processes_.end() ? nullptr : &it->second;
}

std::vector<ProcessRecord> TraceCollector::processes() const
{
    std::vector<ProcessRecord> result;
    result.reserve(processes_.size());
    for (const auto& [pid, process] : processes_) {
        result.push_back(process);
    }
    std::sort(result.begin(), result.end(), [](const ProcessRecord& a, const ProcessRecord& b) {
        return a.startTime.value_or(0) < b.startTime.value_or(0);
    });
    return result;
}

}  // namespace tracepot
