#pragma once

#include "core/models/Report.hpp"
#include "core/observers/StraceParser.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace tracepot {

struct TraceCollectorOptions {
    // The sandboxed command as bwrap executes it. Everything before its execve is bubblewrap's own
    // setup and is ignored.
    std::string entryExecutable;
    std::vector<std::string> entryArgv;
    std::string initialCwd = "/work";
    std::uint64_t maxEvents = 100000;
    std::size_t maxLineBytes = 4 * 1024 * 1024;
    std::size_t maxBufferedRecords = 50000;
    std::vector<std::string> sensitiveReadPatterns;  // globs on sandbox paths
    bool pidTranslationAvailable = true;
};

struct TraceCounts {
    std::uint64_t processes = 0;
    std::uint64_t fileEvents = 0;
    std::uint64_t networkEvents = 0;
    std::uint64_t lines = 0;
};

// Incrementally consumes strace output and builds the process tree, file-event timeline and
// network observations for the sandboxed process tree only.
class TraceCollector {
public:
    explicit TraceCollector(TraceCollectorOptions options);

    void feed(std::string_view chunk);
    // Flushes partial input and resolves buffered records. Call once after the trace is complete.
    void finish();

    [[nodiscard]] bool entryObserved() const { return entryPid_.has_value(); }
    [[nodiscard]] std::optional<int> entryPid() const { return entryPid_; }
    [[nodiscard]] TraceCounts counts() const;

    [[nodiscard]] const ProcessRecord* entryProcess() const;
    [[nodiscard]] std::vector<ProcessRecord> processes() const;
    [[nodiscard]] const std::vector<TraceEvent>& events() const { return events_; }
    [[nodiscard]] const std::vector<NetworkEvent>& networkEvents() const { return networkEvents_; }
    [[nodiscard]] const std::vector<ResourceLimitEvent>& limitEvents() const { return limitEvents_; }
    [[nodiscard]] const std::vector<std::string>& warnings() const { return warnings_; }
    [[nodiscard]] std::uint64_t linesParsed() const { return linesParsed_; }
    [[nodiscard]] std::uint64_t linesMalformed() const { return linesMalformed_; }
    [[nodiscard]] std::uint64_t eventsDropped() const { return eventsDropped_; }
    [[nodiscard]] std::uint64_t readOnlyOpens() const { return readOnlyOpens_; }

private:
    struct SocketInfo {
        std::string domain;
        std::string protocol;
        std::optional<SockAddr> remote;
        std::optional<SockAddr> local;
    };
    using Buffered = std::variant<SyscallRecord, StraceLine>;

    void handleLine(std::string_view line);
    void handleExitLine(const StraceLine& line);
    void handleRecord(const SyscallRecord& record);
    void dispatch(int tgid, const SyscallRecord& record);
    void adoptProcess(int pid, std::optional<int> ppid, double timestamp);

    void onClone(int tgid, const SyscallRecord& record);
    void onExec(int tgid, const SyscallRecord& record);
    void onOpen(int tgid, const SyscallRecord& record);
    void onPathMutation(int tgid, const SyscallRecord& record);
    void onSocket(const SyscallRecord& record);
    void onConnectOrBind(int tgid, const SyscallRecord& record);
    void onListen(int tgid, const SyscallRecord& record);
    void onSend(int tgid, const SyscallRecord& record);

    std::string resolvePath(int tgid, const FdRef* dirFd, const std::string& path);
    std::string cwdOf(int tgid) const;
    void noteFdcwd(int tgid, const std::string& token);

    void addEvent(TraceEvent event);
    void addNetworkEvent(NetworkEvent event);
    void recordDatagram(int tgid, const SyscallRecord& record, const SockAddr& destination, const std::string& payload,
                        const std::string& protocol);

    TraceCollectorOptions options_;
    StraceAssembler assembler_;
    std::string partial_;
    bool skippingLongLine_ = false;

    std::optional<int> entryPid_;
    std::set<int> infrastructurePids_;
    std::map<int, ProcessRecord> processes_;
    std::map<int, int> threadToProcess_;
    std::map<int, std::string> cwd_;
    std::map<int, std::vector<Buffered>> buffered_;
    std::size_t bufferedCount_ = 0;
    std::map<std::uint64_t, SocketInfo> sockets_;

    std::vector<TraceEvent> events_;
    std::vector<NetworkEvent> networkEvents_;
    std::vector<ResourceLimitEvent> limitEvents_;
    std::vector<std::string> warnings_;
    std::uint64_t nextSeq_ = 1;
    std::uint64_t linesParsed_ = 0;
    std::uint64_t linesMalformed_ = 0;
    std::uint64_t eventsDropped_ = 0;
    std::uint64_t readOnlyOpens_ = 0;
    std::uint64_t fileEventCount_ = 0;
    bool processLimitNoted_ = false;
};

}  // namespace tracepot
