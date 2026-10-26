#pragma once

#include "core/models/Limits.hpp"
#include "core/models/Types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tracepot {

inline constexpr std::string_view kReportSchemaName = "tracepot-report";
inline constexpr int kReportSchemaMajor = 1;
inline constexpr int kReportSchemaMinor = 0;

// Metadata of one filesystem entry as seen by a snapshot.
struct FileMetadata {
    FileType type = FileType::Unknown;
    std::uint32_t mode = 0;  // permission bits including setuid/setgid/sticky
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint64_t size = 0;
    std::int64_t mtimeNs = 0;
    std::string linkTarget;               // symlinks only
    std::optional<std::string> sha256;    // regular files within hashing limits
    std::string hashNote;                 // why a hash is missing, if it is
};

struct FileChange {
    std::string path;  // path inside the sandbox
    ChangeKind kind = ChangeKind::Modified;
    std::vector<std::string> aspects;  // content, size, permissions, ownership, link-target, type, timestamps
    std::string area;                  // home, system-config, system-data, temporary, work, runtime
    std::optional<FileMetadata> before;
    std::optional<FileMetadata> after;
    std::optional<std::string> textDiff;
    bool textDiffTruncated = false;
    std::vector<int> attributedPids;  // processes seen modifying the path in the trace
    std::vector<std::string> notes;
};

struct ExecRecord {
    double timestamp = 0;
    std::string path;
    std::vector<std::string> argv;
    Outcome outcome = Outcome::Unknown;
    std::string error;
};

struct ProcessRecord {
    int pid = 0;  // PID as seen by the tracer (host PID namespace)
    std::optional<int> ppid;
    std::optional<double> startTime;
    std::optional<double> endTime;
    std::vector<ExecRecord> execs;
    std::optional<int> exitCode;
    std::string signal;  // terminating signal name, if any
    bool terminatedAtTeardown = false;
    int threadCount = 0;

    [[nodiscard]] std::string executable() const;
    [[nodiscard]] std::vector<std::string> argv() const;
};

struct TraceEvent {
    std::uint64_t seq = 0;
    double timestamp = 0;
    int pid = 0;
    EventType type = EventType::FileWrite;
    std::string syscall;
    std::string path;
    std::string targetPath;
    std::string detail;
    Outcome outcome = Outcome::Unknown;
    std::string error;
};

struct NetworkEvent {
    std::optional<double> timestamp;
    std::optional<int> pid;
    NetworkEventKind kind = NetworkEventKind::Connect;
    std::string protocol;  // tcp, udp, unix, raw, unknown
    std::string family;    // ipv4, ipv6, unix
    std::string address;
    std::optional<int> port;
    std::string hostname;  // DNS query name or URL host
    Outcome outcome = Outcome::Unknown;
    std::string error;
    EvidenceKind evidence = EvidenceKind::Observed;
    ObservationSource source = ObservationSource::SyscallTrace;
    std::string detail;
};

struct PersistenceFinding {
    PersistenceCategory category = PersistenceCategory::Custom;
    std::string scope;   // user or system
    std::string path;
    std::string action;  // created, modified, deleted, write-attempt, command
    std::string outcome; // applied-in-sandbox, attempt-failed, attempt-observed, command-executed
    std::string ruleId;
    std::string description;
    std::vector<ObservationSource> basis;
    std::vector<int> pids;
};

struct ResourceLimitEvent {
    std::optional<double> timestamp;
    std::string limit;
    std::string detail;
};

struct Diagnostic {
    Severity severity = Severity::Info;
    DiagnosticKind kind = DiagnosticKind::Note;
    std::string code;
    std::string message;
};

struct ArchiveEntrySummary {
    std::string path;
    FileType type = FileType::Unknown;
    std::uint64_t size = 0;
    std::uint32_t mode = 0;
    std::string linkTarget;
};

struct ArchiveSummary {
    std::string format;
    std::uint64_t entryCount = 0;
    std::uint64_t totalBytes = 0;
    std::vector<ArchiveEntrySummary> entries;
    bool entriesTruncated = false;
};

struct InputSummary {
    std::string fileName;
    std::string sha256;
    std::uint64_t sizeBytes = 0;
    InputKind kind = InputKind::Unsupported;
    std::string format;
    std::string interpreter;
    std::string entryPoint;  // sandbox path of the executed script
    std::vector<std::string> arguments;
    std::vector<std::string> environmentKeys;
    std::optional<ArchiveSummary> archive;
};

struct SandboxInfo {
    std::string backend;
    std::string backendVersion;
    std::vector<std::string> namespaces;
    SandboxUser user = SandboxUser::Unprivileged;
    std::uint32_t sandboxUid = 0;
    bool seccompEnabled = false;
    std::vector<std::string> seccompBlocked;
    bool nestedUserNamespacesDisabled = false;
    std::vector<std::string> readOnlyPaths;
    std::vector<std::string> writablePaths;
    std::vector<std::string> hostWritablePaths;
    ResourceLimits limits;
    std::vector<std::string> limitNotes;
    std::string tracer;
    std::string tracerVersion;
    bool tracingEnabled = false;
    bool hostRoot = false;
};

struct NetworkPolicyInfo {
    std::string mode;
    std::string description;
    bool externalConnectivity = false;
    bool dnsResolution = false;
    std::string observationMethod;
};

struct ExecutionResult {
    TerminationReason reason = TerminationReason::NotStarted;
    std::optional<int> exitCode;
    std::string signal;
    std::string detail;
    double executionSeconds = 0;
    std::string stdoutExcerpt;
    std::string stderrExcerpt;
    std::uint64_t stdoutBytes = 0;
    std::uint64_t stderrBytes = 0;
};

struct HostIntegrityResult {
    bool performed = false;
    std::vector<std::string> pathsChecked;
    std::uint64_t entriesCompared = 0;
    std::vector<FileChange> changes;
    std::string note;
};

struct Statistics {
    std::uint64_t traceLinesParsed = 0;
    std::uint64_t traceLinesMalformed = 0;
    std::uint64_t traceBytes = 0;
    std::uint64_t eventsRecorded = 0;
    std::uint64_t eventsDropped = 0;
    std::uint64_t readOnlyOpens = 0;
    std::uint64_t entriesBefore = 0;
    std::uint64_t entriesAfter = 0;
    std::uint64_t bytesHashed = 0;
};

struct AnalysisReport {
    std::string schemaVersion;
    std::string applicationName;
    std::string applicationVersion;
    std::string analysisId;
    std::string disclaimer;
    std::string startedAt;
    std::string finishedAt;
    double durationSeconds = 0;

    InputSummary input;
    SandboxInfo sandbox;
    NetworkPolicyInfo networkPolicy;
    ExecutionResult execution;

    std::vector<ProcessRecord> processes;
    std::vector<TraceEvent> events;
    std::vector<FileChange> filesystemChanges;
    std::vector<NetworkEvent> networkEvents;
    std::vector<PersistenceFinding> persistence;
    std::vector<ResourceLimitEvent> resourceLimitEvents;
    HostIntegrityResult hostIntegrity;
    Statistics statistics;
    std::vector<Diagnostic> diagnostics;
};

std::string reportSchemaVersionString();
std::string reportDisclaimer();

}  // namespace tracepot
