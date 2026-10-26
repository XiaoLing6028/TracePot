#include "core/reporting/ReportJson.hpp"

#include "core/util/FileUtil.hpp"
#include "core/util/TimeUtil.hpp"

#include <cerrno>
#include <cstdio>

#include <fcntl.h>
#include <nlohmann/json.hpp>
#include <sys/random.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

// ---- writing ---------------------------------------------------------------------------------

template <typename T>
json optional(const std::optional<T>& value)
{
    return value ? json(*value) : json(nullptr);
}

json textOrNull(const std::string& value)
{
    return value.empty() ? json(nullptr) : json(value);
}

template <typename E>
json name(E value)
{
    return std::string(enumName(value));
}

std::string modeString(std::uint32_t mode)
{
    char buffer[8];
    std::snprintf(buffer, sizeof(buffer), "%04o", mode & 07777);
    return buffer;
}

json toJson(const FileMetadata& m)
{
    return json{{"type", name(m.type)},
                {"mode", modeString(m.mode)},
                {"uid", m.uid},
                {"gid", m.gid},
                {"size", m.size},
                {"mtimeNs", m.mtimeNs},
                {"sha256", optional(m.sha256)},
                {"hashNote", textOrNull(m.hashNote)},
                {"linkTarget", m.type == FileType::Symlink ? json(m.linkTarget) : json(nullptr)}};
}

json toJson(const FileChange& c)
{
    return json{{"path", c.path},
                {"change", name(c.kind)},
                {"area", c.area},
                {"aspects", c.aspects},
                {"before", c.before ? toJson(*c.before) : json(nullptr)},
                {"after", c.after ? toJson(*c.after) : json(nullptr)},
                {"textDiff", optional(c.textDiff)},
                {"textDiffTruncated", c.textDiffTruncated},
                {"attributedPids", c.attributedPids},
                {"notes", c.notes},
                {"source", name(ObservationSource::FilesystemDiff)},
                {"evidence", name(EvidenceKind::Observed)}};
}

json toJson(const ExecRecord& e)
{
    return json{{"timestamp", e.timestamp},
                {"path", e.path},
                {"argv", e.argv},
                {"outcome", name(e.outcome)},
                {"error", textOrNull(e.error)}};
}

json toJson(const ProcessRecord& p)
{
    json execs = json::array();
    for (const auto& exec : p.execs) {
        execs.push_back(toJson(exec));
    }
    return json{{"pid", p.pid},
                {"ppid", optional(p.ppid)},
                {"startTime", optional(p.startTime)},
                {"endTime", optional(p.endTime)},
                {"executable", textOrNull(p.executable())},
                {"execs", execs},
                {"exitCode", optional(p.exitCode)},
                {"signal", textOrNull(p.signal)},
                {"terminatedAtTeardown", p.terminatedAtTeardown},
                {"threadCount", p.threadCount}};
}

json toJson(const TraceEvent& e)
{
    return json{{"seq", e.seq},
                {"timestamp", e.timestamp},
                {"pid", e.pid},
                {"type", name(e.type)},
                {"syscall", e.syscall},
                {"path", textOrNull(e.path)},
                {"targetPath", textOrNull(e.targetPath)},
                {"detail", textOrNull(e.detail)},
                {"outcome", name(e.outcome)},
                {"error", textOrNull(e.error)},
                {"source", name(ObservationSource::SyscallTrace)},
                {"evidence", name(EvidenceKind::Observed)}};
}

json toJson(const NetworkEvent& n)
{
    return json{{"timestamp", optional(n.timestamp)},
                {"pid", optional(n.pid)},
                {"kind", name(n.kind)},
                {"protocol", textOrNull(n.protocol)},
                {"family", textOrNull(n.family)},
                {"address", textOrNull(n.address)},
                {"port", optional(n.port)},
                {"hostname", textOrNull(n.hostname)},
                {"outcome", name(n.outcome)},
                {"error", textOrNull(n.error)},
                {"evidence", name(n.evidence)},
                {"source", name(n.source)},
                {"detail", textOrNull(n.detail)}};
}

json toJson(const PersistenceFinding& f)
{
    json basis = json::array();
    for (const auto source : f.basis) {
        basis.push_back(name(source));
    }
    return json{{"category", name(f.category)},
                {"scope", f.scope},
                {"path", f.path},
                {"action", f.action},
                {"outcome", f.outcome},
                {"ruleId", f.ruleId},
                {"description", f.description},
                {"evidence", name(EvidenceKind::Inferred)},
                {"basis", basis},
                {"pids", f.pids}};
}

json toJson(const ResourceLimits& l)
{
    return json{{"timeoutSeconds", l.timeoutSeconds},     {"memoryBytes", l.memoryBytes},
                {"maxProcesses", l.maxProcesses},         {"maxFileSizeBytes", l.maxFileSizeBytes},
                {"maxDiskBytes", l.maxDiskBytes},         {"maxOpenFiles", l.maxOpenFiles}};
}

// ---- reading ---------------------------------------------------------------------------------

const json* field(const json& object, const char* key)
{
    if (!object.is_object()) {
        return nullptr;
    }
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) {
        return nullptr;
    }
    return &*it;
}

std::string getString(const json& object, const char* key)
{
    const json* value = field(object, key);
    return value != nullptr ? value->get<std::string>() : std::string();
}

template <typename T>
T getNumber(const json& object, const char* key, T fallback = T{})
{
    const json* value = field(object, key);
    return value != nullptr ? value->get<T>() : fallback;
}

template <typename T>
std::optional<T> getOptional(const json& object, const char* key)
{
    const json* value = field(object, key);
    if (value == nullptr) {
        return std::nullopt;
    }
    return value->get<T>();
}

bool getBool(const json& object, const char* key)
{
    const json* value = field(object, key);
    return value != nullptr && value->get<bool>();
}

template <typename E>
E getEnum(const json& object, const char* key, E fallback)
{
    const json* value = field(object, key);
    if (value == nullptr) {
        return fallback;
    }
    return parseEnum<E>(value->get<std::string>()).value_or(fallback);
}

std::vector<std::string> getStrings(const json& object, const char* key)
{
    const json* value = field(object, key);
    return value != nullptr ? value->get<std::vector<std::string>>() : std::vector<std::string>();
}

template <typename T, typename F>
std::vector<T> getArray(const json& object, const char* key, F convert)
{
    std::vector<T> result;
    const json* value = field(object, key);
    if (value == nullptr) {
        return result;
    }
    if (!value->is_array()) {
        throw std::runtime_error(std::string("field '") + key + "' must be an array");
    }
    for (const auto& item : *value) {
        result.push_back(convert(item));
    }
    return result;
}

FileMetadata metadataFromJson(const json& j)
{
    FileMetadata m;
    m.type = getEnum(j, "type", FileType::Unknown);
    const std::string mode = getString(j, "mode");
    m.mode = mode.empty() ? 0 : static_cast<std::uint32_t>(std::stoul(mode, nullptr, 8));
    m.uid = getNumber<std::uint32_t>(j, "uid");
    m.gid = getNumber<std::uint32_t>(j, "gid");
    m.size = getNumber<std::uint64_t>(j, "size");
    m.mtimeNs = getNumber<std::int64_t>(j, "mtimeNs");
    m.sha256 = getOptional<std::string>(j, "sha256");
    m.hashNote = getString(j, "hashNote");
    m.linkTarget = getString(j, "linkTarget");
    return m;
}

FileChange changeFromJson(const json& j)
{
    FileChange c;
    c.path = getString(j, "path");
    c.kind = getEnum(j, "change", ChangeKind::Modified);
    c.area = getString(j, "area");
    c.aspects = getStrings(j, "aspects");
    if (const json* before = field(j, "before")) {
        c.before = metadataFromJson(*before);
    }
    if (const json* after = field(j, "after")) {
        c.after = metadataFromJson(*after);
    }
    c.textDiff = getOptional<std::string>(j, "textDiff");
    c.textDiffTruncated = getBool(j, "textDiffTruncated");
    if (const json* pids = field(j, "attributedPids")) {
        c.attributedPids = pids->get<std::vector<int>>();
    }
    c.notes = getStrings(j, "notes");
    return c;
}

ProcessRecord processFromJson(const json& j)
{
    ProcessRecord p;
    p.pid = getNumber<int>(j, "pid");
    p.ppid = getOptional<int>(j, "ppid");
    p.startTime = getOptional<double>(j, "startTime");
    p.endTime = getOptional<double>(j, "endTime");
    p.execs = getArray<ExecRecord>(j, "execs", [](const json& e) {
        ExecRecord exec;
        exec.timestamp = getNumber<double>(e, "timestamp");
        exec.path = getString(e, "path");
        exec.argv = getStrings(e, "argv");
        exec.outcome = getEnum(e, "outcome", Outcome::Unknown);
        exec.error = getString(e, "error");
        return exec;
    });
    p.exitCode = getOptional<int>(j, "exitCode");
    p.signal = getString(j, "signal");
    p.terminatedAtTeardown = getBool(j, "terminatedAtTeardown");
    p.threadCount = getNumber<int>(j, "threadCount");
    return p;
}

AnalysisReport reportFromJson(const json& root)
{
    AnalysisReport r;
    r.schemaVersion = getString(root, "schemaVersion");
    if (const json* app = field(root, "application")) {
        r.applicationName = getString(*app, "name");
        r.applicationVersion = getString(*app, "version");
    }
    r.analysisId = getString(root, "analysisId");
    r.disclaimer = getString(root, "disclaimer");
    if (const json* timing = field(root, "timing")) {
        r.startedAt = getString(*timing, "startedAt");
        r.finishedAt = getString(*timing, "finishedAt");
        r.durationSeconds = getNumber<double>(*timing, "durationSeconds");
    }
    if (const json* in = field(root, "input")) {
        r.input.fileName = getString(*in, "fileName");
        r.input.sha256 = getString(*in, "sha256");
        r.input.sizeBytes = getNumber<std::uint64_t>(*in, "sizeBytes");
        r.input.kind = getEnum(*in, "kind", InputKind::Unsupported);
        r.input.format = getString(*in, "format");
        r.input.interpreter = getString(*in, "interpreter");
        r.input.entryPoint = getString(*in, "entryPoint");
        r.input.arguments = getStrings(*in, "arguments");
        r.input.environmentKeys = getStrings(*in, "environmentKeys");
        if (const json* archive = field(*in, "archive")) {
            ArchiveSummary a;
            a.format = getString(*archive, "format");
            a.entryCount = getNumber<std::uint64_t>(*archive, "entryCount");
            a.totalBytes = getNumber<std::uint64_t>(*archive, "totalBytes");
            a.entriesTruncated = getBool(*archive, "entriesTruncated");
            a.entries = getArray<ArchiveEntrySummary>(*archive, "entries", [](const json& e) {
                ArchiveEntrySummary entry;
                entry.path = getString(e, "path");
                entry.type = getEnum(e, "type", FileType::Unknown);
                entry.size = getNumber<std::uint64_t>(e, "size");
                const std::string mode = getString(e, "mode");
                entry.mode = mode.empty() ? 0 : static_cast<std::uint32_t>(std::stoul(mode, nullptr, 8));
                entry.linkTarget = getString(e, "linkTarget");
                return entry;
            });
            r.input.archive = std::move(a);
        }
    }
    if (const json* s = field(root, "sandbox")) {
        r.sandbox.backend = getString(*s, "backend");
        r.sandbox.backendVersion = getString(*s, "backendVersion");
        r.sandbox.namespaces = getStrings(*s, "namespaces");
        r.sandbox.user = getEnum(*s, "user", SandboxUser::Unprivileged);
        r.sandbox.sandboxUid = getNumber<std::uint32_t>(*s, "sandboxUid");
        if (const json* seccomp = field(*s, "seccomp")) {
            r.sandbox.seccompEnabled = getBool(*seccomp, "enabled");
            r.sandbox.seccompBlocked = getStrings(*seccomp, "blocked");
        }
        r.sandbox.nestedUserNamespacesDisabled = getBool(*s, "nestedUserNamespacesDisabled");
        r.sandbox.readOnlyPaths = getStrings(*s, "readOnlyPaths");
        r.sandbox.writablePaths = getStrings(*s, "writablePaths");
        r.sandbox.hostWritablePaths = getStrings(*s, "hostWritablePaths");
        if (const json* l = field(*s, "limits")) {
            r.sandbox.limits.timeoutSeconds = getNumber<int>(*l, "timeoutSeconds");
            r.sandbox.limits.memoryBytes = getNumber<std::uint64_t>(*l, "memoryBytes");
            r.sandbox.limits.maxProcesses = getNumber<std::uint32_t>(*l, "maxProcesses");
            r.sandbox.limits.maxFileSizeBytes = getNumber<std::uint64_t>(*l, "maxFileSizeBytes");
            r.sandbox.limits.maxDiskBytes = getNumber<std::uint64_t>(*l, "maxDiskBytes");
            r.sandbox.limits.maxOpenFiles = getNumber<std::uint32_t>(*l, "maxOpenFiles");
        }
        r.sandbox.limitNotes = getStrings(*s, "limitNotes");
        if (const json* t = field(*s, "tracer")) {
            r.sandbox.tracer = getString(*t, "name");
            r.sandbox.tracerVersion = getString(*t, "version");
            r.sandbox.tracingEnabled = getBool(*t, "enabled");
        }
        r.sandbox.hostRoot = getBool(*s, "runningAsHostRoot");
    }
    if (const json* n = field(root, "networkPolicy")) {
        r.networkPolicy.mode = getString(*n, "mode");
        r.networkPolicy.description = getString(*n, "description");
        r.networkPolicy.externalConnectivity = getBool(*n, "externalConnectivity");
        r.networkPolicy.dnsResolution = getBool(*n, "dnsResolution");
        r.networkPolicy.observationMethod = getString(*n, "observationMethod");
    }
    if (const json* e = field(root, "execution")) {
        r.execution.reason = getEnum(*e, "terminationReason", TerminationReason::NotStarted);
        r.execution.exitCode = getOptional<int>(*e, "exitCode");
        r.execution.signal = getString(*e, "signal");
        r.execution.detail = getString(*e, "detail");
        r.execution.executionSeconds = getNumber<double>(*e, "executionSeconds");
        r.execution.stdoutExcerpt = getString(*e, "stdoutExcerpt");
        r.execution.stderrExcerpt = getString(*e, "stderrExcerpt");
        r.execution.stdoutBytes = getNumber<std::uint64_t>(*e, "stdoutBytes");
        r.execution.stderrBytes = getNumber<std::uint64_t>(*e, "stderrBytes");
    }
    r.processes = getArray<ProcessRecord>(root, "processes", processFromJson);
    r.events = getArray<TraceEvent>(root, "events", [](const json& j) {
        TraceEvent e;
        e.seq = getNumber<std::uint64_t>(j, "seq");
        e.timestamp = getNumber<double>(j, "timestamp");
        e.pid = getNumber<int>(j, "pid");
        e.type = getEnum(j, "type", EventType::FileWrite);
        e.syscall = getString(j, "syscall");
        e.path = getString(j, "path");
        e.targetPath = getString(j, "targetPath");
        e.detail = getString(j, "detail");
        e.outcome = getEnum(j, "outcome", Outcome::Unknown);
        e.error = getString(j, "error");
        return e;
    });
    r.filesystemChanges = getArray<FileChange>(root, "filesystemChanges", changeFromJson);
    r.networkEvents = getArray<NetworkEvent>(root, "networkEvents", [](const json& j) {
        NetworkEvent n;
        n.timestamp = getOptional<double>(j, "timestamp");
        n.pid = getOptional<int>(j, "pid");
        n.kind = getEnum(j, "kind", NetworkEventKind::Connect);
        n.protocol = getString(j, "protocol");
        n.family = getString(j, "family");
        n.address = getString(j, "address");
        n.port = getOptional<int>(j, "port");
        n.hostname = getString(j, "hostname");
        n.outcome = getEnum(j, "outcome", Outcome::Unknown);
        n.error = getString(j, "error");
        n.evidence = getEnum(j, "evidence", EvidenceKind::Observed);
        n.source = getEnum(j, "source", ObservationSource::SyscallTrace);
        n.detail = getString(j, "detail");
        return n;
    });
    r.persistence = getArray<PersistenceFinding>(root, "persistence", [](const json& j) {
        PersistenceFinding f;
        f.category = getEnum(j, "category", PersistenceCategory::Custom);
        f.scope = getString(j, "scope");
        f.path = getString(j, "path");
        f.action = getString(j, "action");
        f.outcome = getString(j, "outcome");
        f.ruleId = getString(j, "ruleId");
        f.description = getString(j, "description");
        for (const auto& source : getStrings(j, "basis")) {
            if (auto parsed = parseEnum<ObservationSource>(source)) {
                f.basis.push_back(*parsed);
            }
        }
        if (const json* pids = field(j, "pids")) {
            f.pids = pids->get<std::vector<int>>();
        }
        return f;
    });
    r.resourceLimitEvents = getArray<ResourceLimitEvent>(root, "resourceLimitEvents", [](const json& j) {
        return ResourceLimitEvent{getOptional<double>(j, "timestamp"), getString(j, "limit"), getString(j, "detail")};
    });
    if (const json* h = field(root, "hostIntegrity")) {
        r.hostIntegrity.performed = getBool(*h, "performed");
        r.hostIntegrity.pathsChecked = getStrings(*h, "pathsChecked");
        r.hostIntegrity.entriesCompared = getNumber<std::uint64_t>(*h, "entriesCompared");
        r.hostIntegrity.changes = getArray<FileChange>(*h, "changes", changeFromJson);
        r.hostIntegrity.note = getString(*h, "note");
    }
    if (const json* s = field(root, "statistics")) {
        auto& st = r.statistics;
        st.traceLinesParsed = getNumber<std::uint64_t>(*s, "traceLinesParsed");
        st.traceLinesMalformed = getNumber<std::uint64_t>(*s, "traceLinesMalformed");
        st.traceBytes = getNumber<std::uint64_t>(*s, "traceBytes");
        st.eventsRecorded = getNumber<std::uint64_t>(*s, "eventsRecorded");
        st.eventsDropped = getNumber<std::uint64_t>(*s, "eventsDropped");
        st.readOnlyOpens = getNumber<std::uint64_t>(*s, "readOnlyOpens");
        st.entriesBefore = getNumber<std::uint64_t>(*s, "entriesBefore");
        st.entriesAfter = getNumber<std::uint64_t>(*s, "entriesAfter");
        st.bytesHashed = getNumber<std::uint64_t>(*s, "bytesHashed");
    }
    r.diagnostics = getArray<Diagnostic>(root, "diagnostics", [](const json& j) {
        return Diagnostic{getEnum(j, "severity", Severity::Info), getEnum(j, "kind", DiagnosticKind::Note),
                          getString(j, "code"), getString(j, "message")};
    });
    return r;
}

}  // namespace

std::string serializeReport(const AnalysisReport& r, int indent)
{
    json root;
    root["schema"] = std::string(kReportSchemaName);
    root["schemaVersion"] = r.schemaVersion.empty() ? reportSchemaVersionString() : r.schemaVersion;
    root["application"] = {{"name", r.applicationName}, {"version", r.applicationVersion}};
    root["analysisId"] = r.analysisId;
    root["disclaimer"] = r.disclaimer;
    root["timing"] = {{"startedAt", textOrNull(r.startedAt)},
                      {"finishedAt", textOrNull(r.finishedAt)},
                      {"durationSeconds", r.durationSeconds}};

    json archive = nullptr;
    if (r.input.archive) {
        const auto& a = *r.input.archive;
        json entries = json::array();
        for (const auto& e : a.entries) {
            entries.push_back({{"path", e.path},
                               {"type", name(e.type)},
                               {"size", e.size},
                               {"mode", modeString(e.mode)},
                               {"linkTarget", textOrNull(e.linkTarget)}});
        }
        archive = {{"format", a.format},
                   {"entryCount", a.entryCount},
                   {"totalBytes", a.totalBytes},
                   {"entries", entries},
                   {"entriesTruncated", a.entriesTruncated}};
    }
    root["input"] = {{"fileName", r.input.fileName},
                     {"sha256", textOrNull(r.input.sha256)},
                     {"sizeBytes", r.input.sizeBytes},
                     {"kind", name(r.input.kind)},
                     {"format", textOrNull(r.input.format)},
                     {"interpreter", textOrNull(r.input.interpreter)},
                     {"entryPoint", textOrNull(r.input.entryPoint)},
                     {"arguments", r.input.arguments},
                     {"environmentKeys", r.input.environmentKeys},
                     {"archive", archive}};

    const auto& s = r.sandbox;
    root["sandbox"] = {{"backend", s.backend},
                       {"backendVersion", textOrNull(s.backendVersion)},
                       {"namespaces", s.namespaces},
                       {"user", name(s.user)},
                       {"sandboxUid", s.sandboxUid},
                       {"seccomp", {{"enabled", s.seccompEnabled}, {"blocked", s.seccompBlocked}}},
                       {"nestedUserNamespacesDisabled", s.nestedUserNamespacesDisabled},
                       {"readOnlyPaths", s.readOnlyPaths},
                       {"writablePaths", s.writablePaths},
                       {"hostWritablePaths", s.hostWritablePaths},
                       {"limits", toJson(s.limits)},
                       {"limitNotes", s.limitNotes},
                       {"tracer", {{"name", textOrNull(s.tracer)},
                                   {"version", textOrNull(s.tracerVersion)},
                                   {"enabled", s.tracingEnabled}}},
                       {"runningAsHostRoot", s.hostRoot}};
    root["networkPolicy"] = {{"mode", r.networkPolicy.mode},
                             {"description", r.networkPolicy.description},
                             {"externalConnectivity", r.networkPolicy.externalConnectivity},
                             {"dnsResolution", r.networkPolicy.dnsResolution},
                             {"observationMethod", r.networkPolicy.observationMethod}};
    const auto& e = r.execution;
    root["execution"] = {{"terminationReason", name(e.reason)},
                         {"exitCode", optional(e.exitCode)},
                         {"signal", textOrNull(e.signal)},
                         {"detail", textOrNull(e.detail)},
                         {"executionSeconds", e.executionSeconds},
                         {"stdoutExcerpt", e.stdoutExcerpt},
                         {"stderrExcerpt", e.stderrExcerpt},
                         {"stdoutBytes", e.stdoutBytes},
                         {"stderrBytes", e.stderrBytes},
                         {"outputNote", "Captured output is untrusted program output; stderr also contains "
                                        "sandbox launcher diagnostics."}};

    auto array = [](const auto& items) {
        json out = json::array();
        for (const auto& item : items) {
            out.push_back(toJson(item));
        }
        return out;
    };
    root["processes"] = array(r.processes);
    root["events"] = array(r.events);
    root["filesystemChanges"] = array(r.filesystemChanges);
    root["networkEvents"] = array(r.networkEvents);
    root["persistence"] = array(r.persistence);
    json limitEvents = json::array();
    for (const auto& event : r.resourceLimitEvents) {
        limitEvents.push_back({{"timestamp", optional(event.timestamp)}, {"limit", event.limit}, {"detail", event.detail}});
    }
    root["resourceLimitEvents"] = limitEvents;
    root["hostIntegrity"] = {{"performed", r.hostIntegrity.performed},
                             {"pathsChecked", r.hostIntegrity.pathsChecked},
                             {"entriesCompared", r.hostIntegrity.entriesCompared},
                             {"changes", array(r.hostIntegrity.changes)},
                             {"note", r.hostIntegrity.note}};
    const auto& st = r.statistics;
    root["statistics"] = {{"traceLinesParsed", st.traceLinesParsed}, {"traceLinesMalformed", st.traceLinesMalformed},
                          {"traceBytes", st.traceBytes},             {"eventsRecorded", st.eventsRecorded},
                          {"eventsDropped", st.eventsDropped},       {"readOnlyOpens", st.readOnlyOpens},
                          {"entriesBefore", st.entriesBefore},       {"entriesAfter", st.entriesAfter},
                          {"bytesHashed", st.bytesHashed}};
    json diagnostics = json::array();
    for (const auto& d : r.diagnostics) {
        diagnostics.push_back(
            {{"severity", name(d.severity)}, {"kind", name(d.kind)}, {"code", d.code}, {"message", d.message}});
    }
    root["diagnostics"] = diagnostics;
    return root.dump(indent, ' ', false, json::error_handler_t::replace) + "\n";
}

Result<AnalysisReport> parseReport(std::string_view text)
{
    json root;
    try {
        root = json::parse(text.begin(), text.end());
    } catch (const json::exception& ex) {
        return makeError(ErrorCode::ReportInvalid, std::string("not valid JSON: ") + ex.what());
    }
    if (!root.is_object() || !root.contains("schema") || !root["schema"].is_string() ||
        root["schema"].get<std::string>() != kReportSchemaName) {
        return makeError(ErrorCode::ReportInvalid, "not a TracePot report (missing \"schema\": \"tracepot-report\")");
    }
    if (!root.contains("schemaVersion") || !root["schemaVersion"].is_string()) {
        return makeError(ErrorCode::ReportInvalid, "report has no schemaVersion");
    }
    const std::string version = root["schemaVersion"].get<std::string>();
    int major = -1;
    try {
        major = std::stoi(version.substr(0, version.find('.')));
    } catch (const std::exception&) {
        return makeError(ErrorCode::ReportInvalid, "malformed schemaVersion '" + version + "'");
    }
    if (major != kReportSchemaMajor) {
        return makeError(ErrorCode::ReportInvalid,
                         "unsupported report schema version " + version + " (this build reads " +
                             std::to_string(kReportSchemaMajor) + ".x)");
    }
    try {
        return reportFromJson(root);
    } catch (const std::exception& ex) {
        return makeError(ErrorCode::ReportInvalid, std::string("invalid report content: ") + ex.what());
    }
}

Status writeTextFileAtomic(const fs::path& path, std::string_view content)
{
    std::uint32_t random = 0;
    if (::getrandom(&random, sizeof(random), 0) != static_cast<ssize_t>(sizeof(random))) {
        random = static_cast<std::uint32_t>(::getpid());
    }
    const fs::path temporary = path.parent_path() / (".tracepot-tmp-" + std::to_string(random));
    UniqueFd fd(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644));
    if (!fd) {
        return makeError(ErrorCode::Io, "cannot write " + path.string() + ": " + errnoMessage(errno));
    }
    const char* data = content.data();
    std::size_t remaining = content.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd.get(), data, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int err = errno;
            ::unlink(temporary.c_str());
            return makeError(ErrorCode::Io, "write failed for " + path.string() + ": " + errnoMessage(err));
        }
        data += written;
        remaining -= static_cast<std::size_t>(written);
    }
    if (::fsync(fd.get()) != 0 || ::rename(temporary.c_str(), path.c_str()) != 0) {
        const int err = errno;
        ::unlink(temporary.c_str());
        return makeError(ErrorCode::Io, "cannot finalize " + path.string() + ": " + errnoMessage(err));
    }
    return {};
}

Result<AnalysisReport> loadReportFile(const fs::path& path)
{
    // Report paths are chosen by the user, so symlinks to reports are resolved deliberately.
    std::error_code ec;
    const fs::path resolved = fs::canonical(path, ec);
    if (ec) {
        return makeError(ErrorCode::ReportInvalid, "cannot open " + path.string() + ": " + ec.message());
    }
    auto content = readFileBounded(resolved, 512 * MiB);
    if (!content) {
        return makeError(ErrorCode::ReportInvalid, content.error().message);
    }
    if (content->truncated) {
        return makeError(ErrorCode::ReportInvalid, "report file is larger than 512 MiB");
    }
    return parseReport(content->data);
}

}  // namespace tracepot
