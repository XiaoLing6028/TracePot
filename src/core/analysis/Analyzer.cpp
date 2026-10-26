#include "core/analysis/Analyzer.hpp"

#include "Version.hpp"
#include "core/analysis/Persistence.hpp"
#include "core/archive/EntryPoint.hpp"
#include "core/archive/InputInspector.hpp"
#include "core/archive/SafeExtractor.hpp"
#include "core/diff/FsDiff.hpp"
#include "core/diff/Snapshot.hpp"
#include "core/observers/NetworkObserver.hpp"
#include "core/sandbox/BwrapCommand.hpp"
#include "core/sandbox/SandboxRunner.hpp"
#include "core/sandbox/SeccompFilter.hpp"
#include "core/sandbox/Workspace.hpp"
#include "core/util/FileUtil.hpp"
#include "core/util/PathUtil.hpp"
#include "core/util/TimeUtil.hpp"

#include <chrono>
#include <map>
#include <set>

#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

std::string_view stageLabel(AnalysisStage stage)
{
    switch (stage) {
    case AnalysisStage::Validating: return "Validating input";
    case AnalysisStage::PreparingWorkspace: return "Preparing workspace";
    case AnalysisStage::CapturingBaseline: return "Capturing baseline";
    case AnalysisStage::Running: return "Running in sandbox";
    case AnalysisStage::Collecting: return "Collecting events";
    case AnalysisStage::Comparing: return "Comparing filesystem state";
    case AnalysisStage::Classifying: return "Classifying observations";
    case AnalysisStage::Finalizing: return "Writing report";
    case AnalysisStage::Done: return "Done";
    }
    return "Unknown";
}

std::vector<std::string> defaultSensitiveReadPatterns()
{
    std::vector<std::string> patterns = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/**",
                                         "/etc/ssh/ssh_host_*_key", "/proc/*/environ", "/proc/*/mem"};
    for (const auto* rel : {"/.ssh/**", "/.gnupg/**", "/.aws/**", "/.netrc", "/.git-credentials",
                            "/.docker/config.json", "/.kube/config", "/.config/gcloud/**", "/.password-store/**",
                            "/.mozilla/**", "/.config/google-chrome/**", "/.config/chromium/**",
                            "/.local/share/keyrings/**", "/.bash_history", "/.zsh_history"}) {
        patterns.push_back(std::string("/home/*") + rel);
        patterns.push_back(std::string("/root") + rel);
    }
    return patterns;
}

namespace {

Diagnostic diag(Severity severity, DiagnosticKind kind, std::string code, std::string message)
{
    return Diagnostic{severity, kind, std::move(code), std::move(message)};
}

std::string scriptFileName(const fs::path& input)
{
    std::string name = input.filename().string();
    if (name.empty() || name == "." || name == "..") {
        name = "installer.sh";
    }
    return name;
}

std::string firstLines(const std::string& text, std::size_t maxLines)
{
    std::string out;
    std::size_t lines = 0;
    std::size_t start = 0;
    while (start < text.size() && lines < maxLines) {
        const auto end = text.find('\n', start);
        out += text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        out += '\n';
        ++lines;
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    while (!out.empty() && out.back() == '\n') {
        out.pop_back();
    }
    return out;
}

void attributeChanges(std::vector<FileChange>& changes, const std::vector<TraceEvent>& events)
{
    std::map<std::string, std::set<int>> writers;
    for (const auto& event : events) {
        if (event.outcome != Outcome::Success) {
            continue;
        }
        switch (event.type) {
        case EventType::FileWrite:
        case EventType::FileDelete:
        case EventType::DirectoryCreate:
        case EventType::DirectoryDelete:
        case EventType::SymlinkCreate:
        case EventType::HardlinkCreate:
        case EventType::PermissionChange:
        case EventType::OwnershipChange:
        case EventType::FileTruncate:
            writers[event.path].insert(event.pid);
            break;
        case EventType::FileRename:
            writers[event.path].insert(event.pid);
            writers[event.targetPath].insert(event.pid);
            break;
        default:
            break;
        }
    }
    for (auto& change : changes) {
        if (const auto it = writers.find(change.path); it != writers.end()) {
            change.attributedPids.assign(it->second.begin(), it->second.end());
        }
    }
}

void addStandardLimitations(AnalysisReport& report)
{
    auto& d = report.diagnostics;
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "shared-kernel",
                     "The sandbox shares the host kernel. Namespaces and seccomp reduce, but do not eliminate, the "
                     "risk of a kernel-level escape. Analyze high-risk samples in a disposable virtual machine."));
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "network-isolated",
                     "Network access was blocked. Behavior that depends on downloaded content or remote responses "
                     "was not exercised; only connection and DNS attempts were recorded."));
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "single-run",
                     "One execution with the configured arguments and time limit was observed. Delayed, "
                     "conditional, or login/boot-triggered behavior was not exercised."));
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "environment-detection",
                     "Analyzed code can detect the sandbox (hostname, PID namespace, missing /sys and services) "
                     "and behave differently."));
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "dev-shm",
                     "/dev/shm is a private size-limited tmpfs and is not part of the filesystem comparison."));
}

}  // namespace

Analyzer::Analyzer(AnalysisConfig config) : config_(std::move(config)) {}

Result<AnalysisReport> Analyzer::run(const CancellationToken& cancel, const ProgressCallback& progress)
{
    const auto analysisStart = std::chrono::system_clock::now();
    auto report_progress = [&](AnalysisStage stage, std::string message, double elapsed = 0, TraceCounts counts = {}) {
        if (progress) {
            progress(ProgressUpdate{stage, elapsed, counts, std::move(message)});
        }
    };

    // ---- Validation -------------------------------------------------------------------------
    report_progress(AnalysisStage::Validating, "Checking sandbox readiness");
    if (!readiness_) {
        readiness_ = checkReadiness(config_.helperPath);
    }
    const Readiness& readiness = *readiness_;
    if (!readiness.sandboxReady()) {
        return makeError(ErrorCode::SandboxUnavailable,
                         "the sandbox is not available; TracePot will not run the input without isolation",
                         readiness.failureSummary(false));
    }
    const bool tracing = readiness.tracingReady();
    if (!tracing && config_.requireTracing) {
        return makeError(ErrorCode::ObserverUnavailable, "syscall tracing (strace) is not available",
                         readiness.failureSummary(true) +
                             "Install strace, or explicitly allow an untraced run (filesystem diff only).");
    }
    if (config_.limits.timeoutSeconds <= 0) {
        return makeError(ErrorCode::InvalidArgument, "timeout must be positive");
    }
    for (const auto& [key, value] : config_.environment) {
        if (!isValidEnvironmentName(key) || value.find('\0') != std::string::npos) {
            return makeError(ErrorCode::InvalidArgument, "invalid environment variable: " + displaySafe(key));
        }
    }
    for (const auto& arg : config_.arguments) {
        if (arg.find('\0') != std::string::npos) {
            return makeError(ErrorCode::InvalidArgument, "arguments must not contain NUL bytes");
        }
    }
    auto inspected = inspectInput(config_.inputPath);
    if (!inspected) {
        return inspected.error();
    }
    const InputInfo& input = inspected.value();
    if (input.kind == InputKind::Unsupported) {
        return makeError(input.malformed ? ErrorCode::ArchiveMalformed : ErrorCode::UnsupportedInput, input.reason,
                         "The input was not executed.");
    }
    if (cancel.cancelled()) {
        return makeError(ErrorCode::Cancelled, "analysis cancelled before execution");
    }

    // ---- Workspace --------------------------------------------------------------------------
    report_progress(AnalysisStage::PreparingWorkspace, "Preparing the private workspace");
    AnalysisReport report;
    report.schemaVersion = reportSchemaVersionString();
    report.applicationName = std::string(kApplicationName);
    report.applicationVersion = std::string(kApplicationVersion);
    report.analysisId = makeAnalysisId();
    report.disclaimer = reportDisclaimer();
    report.startedAt = isoTimestampUtc(analysisStart);

    const fs::path base = config_.workspaceBase.empty() ? tracepotCacheDir() / "runs" : config_.workspaceBase;
    const std::size_t staleRemoved = Workspace::removeStale(base);
    auto workspaceResult = Workspace::create(base, report.analysisId);
    if (!workspaceResult) {
        return workspaceResult.error();
    }
    Workspace workspace = std::move(workspaceResult.value());
    workspace.setKeep(config_.keepWorkspace);
    const WorkspacePaths& paths = workspace.paths();

    const fs::path inputCopy = paths.inputDir / scriptFileName(config_.inputPath);
    auto inputHash = copyFileWithHash(config_.inputPath, inputCopy, 0600, kMaxInputBytes);
    if (!inputHash) {
        return inputHash.error();
    }
    report.input.fileName = displaySafe(config_.inputPath.filename().string());
    report.input.sha256 = inputHash.value();
    report.input.sizeBytes = input.sizeBytes;
    report.input.kind = input.kind;
    report.input.format = input.format;
    for (const auto& arg : config_.arguments) {
        report.input.arguments.push_back(displaySafe(arg));
    }
    for (const auto& [key, value] : config_.environment) {
        report.input.environmentKeys.push_back(key);  // values may be secrets; never reported
    }

    if (auto populated = workspace.populateSandboxRoot(config_.user); !populated) {
        return populated.error();
    }
    const fs::path workDir = paths.rootDir / "work";
    std::string shell;
    std::string scriptRelative;
    if (input.kind == InputKind::ShellScript) {
        scriptRelative = scriptFileName(config_.inputPath);
        auto copied = copyFileWithHash(inputCopy, workDir / scriptRelative, 0755, kMaxInputBytes);
        if (!copied) {
            return copied.error();
        }
        shell = input.interpreter;
    } else {
        auto extraction = extractTarSafely(inputCopy, workDir, config_.collection.archive);
        if (!extraction) {
            return extraction.error();
        }
        auto entry = resolveEntryPoint(extraction.value(), workDir, config_.entryPoint);
        if (!entry) {
            return entry.error();
        }
        scriptRelative = entry->relativePath;
        shell = entry->interpreter;
        ArchiveSummary archive;
        archive.format = extraction->format;
        archive.entryCount = extraction->entries.size();
        archive.totalBytes = extraction->totalBytes;
        const auto limit = config_.collection.maxArchiveManifestEntries;
        for (std::size_t i = 0; i < extraction->entries.size() && i < limit; ++i) {
            archive.entries.push_back(extraction->entries[i]);
        }
        archive.entriesTruncated = extraction->entries.size() > limit;
        report.input.archive = std::move(archive);
    }
    const std::string interpreterPath = sandboxInterpreterPath(shell);
    if (interpreterPath.empty()) {
        return makeError(ErrorCode::UnsupportedInput, "the script requires '" + shell + "', which is not installed",
                         "Install the shell on the host; the sandbox uses the host's /usr read-only.");
    }
    report.input.interpreter = shell;
    report.input.entryPoint = std::string(kSandboxWorkDir) + "/" + displaySafe(scriptRelative);

    // ---- Sandbox plan -----------------------------------------------------------------------
    auto seccomp = buildSeccompProgram();
    if (!seccomp) {
        return seccomp.error();
    }
    IsolatedNetwork network;
    SandboxRequest request;
    request.bwrapPath = readiness.bwrapPath;
    request.features = readiness.bwrap;
    request.rootDir = paths.rootDir;
    request.user = config_.user;
    request.interpreterPath = interpreterPath;
    request.scriptPath = std::string(kSandboxWorkDir) + "/" + scriptRelative;
    request.arguments = config_.arguments;
    request.environment = config_.environment;
    request.seccompFd = kSeccompChildFd;
    auto planResult = buildSandboxPlan(request);
    if (!planResult) {
        return planResult.error();
    }
    SandboxPlan plan = std::move(planResult.value());

    report.sandbox.backend = "bubblewrap";
    report.sandbox.backendVersion = readiness.bwrap.version;
    report.sandbox.namespaces = plan.namespaces;
    report.sandbox.user = config_.user;
    report.sandbox.sandboxUid = sandboxUid(config_.user);
    report.sandbox.seccompEnabled = true;
    report.sandbox.seccompBlocked = seccomp->blocked;
    report.sandbox.nestedUserNamespacesDisabled = true;  // seccomp blocks CLONE_NEWUSER in all cases
    report.sandbox.readOnlyPaths = plan.readOnlyPaths;
    report.sandbox.writablePaths = plan.writablePaths;
    report.sandbox.hostWritablePaths = plan.hostWritablePaths;
    report.sandbox.limits = config_.limits;
    report.sandbox.tracer = tracing ? "strace" : "";
    report.sandbox.tracerVersion = tracing ? readiness.straceVersion : "";
    report.sandbox.tracingEnabled = tracing;
    report.sandbox.hostRoot = readiness.runningAsRoot;
    auto& notes = report.sandbox.limitNotes;
    notes.emplace_back("memory: RLIMIT_AS per process (virtual address space)");
    notes.emplace_back("disk: workspace growth polled once per second; short overshoots are possible");
    notes.emplace_back("file size: RLIMIT_FSIZE per file (SIGXFSZ when exceeded)");
    notes.emplace_back(readiness.runningAsRoot ? "processes: RLIMIT_NPROC is not enforced because TracePot runs as root"
                                               : "processes: RLIMIT_NPROC relative to the user's current process count");
    report.networkPolicy = network.describe();

    if (cancel.cancelled()) {
        return makeError(ErrorCode::Cancelled, "analysis cancelled before execution");
    }

    // ---- Baseline ---------------------------------------------------------------------------
    report_progress(AnalysisStage::CapturingBaseline, "Capturing filesystem baseline");
    SnapshotOptions snapshotOptions;
    snapshotOptions.limits = config_.collection.snapshot;
    snapshotOptions.uidMapping = std::make_pair(static_cast<std::uint32_t>(::getuid()), sandboxUid(config_.user));
    snapshotOptions.gidMapping = std::make_pair(static_cast<std::uint32_t>(::getgid()), sandboxUid(config_.user));
    const std::vector<SnapshotRoot> sandboxRoots = {{paths.rootDir, "/"}};
    Snapshot before = takeSnapshot(sandboxRoots, snapshotOptions);

    const fs::path hostHome = config_.hostHome.empty() ? hostHomeDirectory() : config_.hostHome;
    std::vector<SnapshotRoot> hostRoots;
    for (const auto& path : hostPersistencePaths(hostHome)) {
        hostRoots.push_back({path, path.string()});
    }
    SnapshotOptions hostOptions;
    hostOptions.captureText = false;
    hostOptions.limits.maxEntries = 5000;
    hostOptions.limits.maxHashFileBytes = 1 * MiB;
    hostOptions.limits.maxTotalHashBytes = 64 * MiB;
    hostOptions.limits.maxDepth = 6;
    Snapshot hostBefore = takeSnapshot(hostRoots, hostOptions);

    // ---- Execution --------------------------------------------------------------------------
    TraceCollectorOptions collectorOptions;
    collectorOptions.entryExecutable = plan.entryArgv.front();
    collectorOptions.entryArgv = plan.entryArgv;
    collectorOptions.initialCwd = std::string(kSandboxWorkDir);
    collectorOptions.maxEvents = config_.collection.maxEvents;
    collectorOptions.sensitiveReadPatterns = defaultSensitiveReadPatterns();
    collectorOptions.pidTranslationAvailable = readiness.stracePidnsTranslation;
    TraceCollector collector(collectorOptions);

    SandboxRunOptions runOptions;
    runOptions.plan = plan;
    runOptions.paths = paths;
    runOptions.limits = config_.limits;
    runOptions.helperPath = readiness.helperPath;
    if (tracing) {
        runOptions.stracePath = readiness.stracePath;
        runOptions.straceSeccompBpf = readiness.straceSeccompBpf;
        runOptions.stracePidnsTranslation = readiness.stracePidnsTranslation;
    }
    runOptions.seccompFd = seccomp->fd.get();
    runOptions.maxTraceBytes = config_.collection.maxTraceBytes;
    runOptions.maxTreeEntries = config_.collection.snapshot.maxEntries;

    report_progress(AnalysisStage::Running, "Starting the sandbox");
    auto lastProgress = std::chrono::steady_clock::now();
    auto runResult = runSandbox(
        runOptions, cancel, [&collector](std::string_view chunk) { collector.feed(chunk); },
        [&](double elapsed) {
            const auto now = std::chrono::steady_clock::now();
            if (now - lastProgress >= std::chrono::milliseconds(200)) {
                lastProgress = now;
                report_progress(AnalysisStage::Running, "Running in sandbox", elapsed, collector.counts());
            }
        });
    if (!runResult) {
        return runResult.error();
    }
    const SandboxRunResult& run = runResult.value();

    // ---- Collection -------------------------------------------------------------------------
    report_progress(AnalysisStage::Collecting, "Collecting events", run.wallSeconds, collector.counts());
    collector.finish();

    ExecutionResult& execution = report.execution;
    execution.executionSeconds = run.wallSeconds;
    auto stdoutRead = readFileBounded(paths.stdoutLog, config_.collection.maxOutputExcerptBytes);
    auto stderrRead = readFileBounded(paths.stderrLog, config_.collection.maxOutputExcerptBytes);
    if (stdoutRead) {
        execution.stdoutExcerpt = displaySafeMultiline(stdoutRead->data);
        execution.stdoutBytes = stdoutRead->totalSize;
    }
    if (stderrRead) {
        execution.stderrExcerpt = displaySafeMultiline(stderrRead->data);
        execution.stderrBytes = stderrRead->totalSize;
    }

    if (tracing) {
        const ProcessRecord* entry = collector.entryProcess();
        const bool entryExecFailed = entry != nullptr && !entry->execs.empty() &&
                                     entry->execs.front().outcome == Outcome::Failed;
        if (entry == nullptr || entryExecFailed) {
            execution.reason = run.forced ? *run.forced : TerminationReason::LaunchFailed;
            execution.detail = entry == nullptr ? "the sandbox did not start the entry script"
                                                : "executing the entry script failed: " + entry->execs.front().error;
            const auto stderrHead = firstLines(execution.stderrExcerpt, 3);
            if (!stderrHead.empty()) {
                execution.detail += " (" + stderrHead + ")";
            }
        } else {
            execution.exitCode = entry->exitCode;
            execution.signal = entry->signal;
            if (run.forced) {
                execution.reason = *run.forced;
                execution.detail = run.forcedDetail;
            } else if (!entry->signal.empty()) {
                execution.reason = TerminationReason::Signaled;
                execution.detail = "terminated by " + entry->signal;
            } else if (entry->exitCode) {
                execution.reason = TerminationReason::Exited;
                execution.detail = "exited with status " + std::to_string(*entry->exitCode);
            } else if (run.launcherStatus && run.launcherStatus->exited) {
                execution.reason = TerminationReason::Exited;
                execution.exitCode = run.launcherStatus->code;
                execution.detail = "exit status taken from the launcher (entry exit not traced)";
            }
        }
    } else {
        // Without a trace the only status is bubblewrap's, which mirrors the script's exit code but
        // cannot be distinguished from bubblewrap's own failures except through its error output.
        const bool launcherError = execution.stderrExcerpt.find("bwrap:") != std::string::npos ||
                                   execution.stderrExcerpt.find("tracepot-limits:") != std::string::npos;
        if (run.forced) {
            execution.reason = *run.forced;
            execution.detail = run.forcedDetail;
        } else if (launcherError) {
            execution.reason = TerminationReason::LaunchFailed;
            execution.detail = firstLines(execution.stderrExcerpt, 3);
        } else if (run.launcherStatus) {
            if (run.launcherStatus->exited) {
                execution.reason = TerminationReason::Exited;
                execution.exitCode = run.launcherStatus->code;
                execution.detail = "exit status reported by the sandbox launcher";
                if (run.launcherStatus->code > 128) {
                    execution.detail += " (values above 128 may indicate termination by signal " +
                                        std::to_string(run.launcherStatus->code - 128) + ")";
                }
            } else {
                execution.reason = TerminationReason::Signaled;
                execution.signal = signalName(run.launcherStatus->signal);
            }
        }
    }

    report.processes = collector.processes();
    report.events = collector.events();
    report.networkEvents = collector.networkEvents();
    for (auto& event : network.collectEvents()) {
        report.networkEvents.push_back(std::move(event));
    }
    report.resourceLimitEvents = run.limitEvents;
    for (const auto& event : collector.limitEvents()) {
        report.resourceLimitEvents.push_back(event);
    }

    // ---- Comparison -------------------------------------------------------------------------
    report_progress(AnalysisStage::Comparing, "Comparing filesystem state", run.wallSeconds, collector.counts());
    Snapshot after = takeSnapshot(sandboxRoots, snapshotOptions);
    DiffOptions diffOptions;
    diffOptions.maxTextDiffBytes = static_cast<std::size_t>(config_.collection.maxTextDiffBytes);
    report.filesystemChanges = diffSnapshots(before, after, diffOptions);
    attributeChanges(report.filesystemChanges, report.events);

    Snapshot hostAfter = takeSnapshot(hostRoots, hostOptions);
    report.hostIntegrity.performed = true;
    for (const auto& root : hostRoots) {
        report.hostIntegrity.pathsChecked.push_back(displaySafe(root.displayPath));
    }
    report.hostIntegrity.entriesCompared = hostAfter.entries.size();
    DiffOptions hostDiff;
    hostDiff.includeTextDiffs = false;
    report.hostIntegrity.changes = diffSnapshots(hostBefore, hostAfter, hostDiff);
    report.hostIntegrity.note =
        report.hostIntegrity.changes.empty()
            ? "No changes were detected in the checked host persistence locations during the analysis window."
            : "Host persistence locations changed during the analysis window. The sandbox does not expose these "
              "paths, so the change is not attributed to the sample, but it should be investigated.";

    // ---- Classification ---------------------------------------------------------------------
    report_progress(AnalysisStage::Classifying, "Classifying observations", run.wallSeconds, collector.counts());
    PersistenceClassifier classifier(config_.extraPersistencePatterns);
    report.persistence = classifier.classify(report.filesystemChanges, report.events, report.processes);

    // ---- Diagnostics ------------------------------------------------------------------------
    report_progress(AnalysisStage::Finalizing, "Writing report", run.wallSeconds, collector.counts());
    auto& d = report.diagnostics;
    if (readiness.runningAsRoot) {
        d.push_back(diag(Severity::Warning, DiagnosticKind::Warning, "running-as-root",
                         "TracePot ran as root. Sandboxed processes were still confined by namespaces, read-only "
                         "mounts and seccomp, but running as an unprivileged user is strongly recommended."));
    }
    if (!tracing) {
        d.push_back(diag(Severity::Warning, DiagnosticKind::Limitation, "no-trace",
                         "No syscall trace was collected. Process, file-event and network observations are "
                         "missing; only the filesystem comparison is available."));
    } else {
        d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "trace-scope",
                         "Only process, file-mutation and network syscalls were traced. Ordinary file reads are "
                         "counted, not listed; writes through memory mappings or already-open descriptors appear "
                         "only in the filesystem comparison. Syscalls denied by the seccomp filter (for example "
                         "io_uring) do not appear in the trace."));
        if (!readiness.stracePidnsTranslation) {
            d.push_back(diag(Severity::Warning, DiagnosticKind::Limitation, "no-pid-translation",
                             "The installed strace cannot translate PID-namespace PIDs; parent processes are unknown."));
        }
        for (const auto& warning : collector.warnings()) {
            d.push_back(diag(Severity::Warning, DiagnosticKind::Warning, "trace", warning));
        }
        if (collector.eventsDropped() > 0) {
            d.push_back(diag(Severity::Warning, DiagnosticKind::Limitation, "event-limit",
                             std::to_string(collector.eventsDropped()) +
                                 " events were not recorded because the event limit was reached."));
        }
        if (collector.linesMalformed() > 0) {
            d.push_back(diag(Severity::Info, DiagnosticKind::Note, "trace-unparsed",
                             std::to_string(collector.linesMalformed()) + " trace lines could not be interpreted."));
        }
    }
    addStandardLimitations(report);
    if (std::any_of(report.processes.begin(), report.processes.end(),
                    [](const ProcessRecord& p) { return p.terminatedAtTeardown; })) {
        d.push_back(diag(Severity::Info, DiagnosticKind::Note, "teardown",
                         "Some processes were still running when the entry script finished and were terminated "
                         "when the sandbox was torn down; their later behavior was not observed."));
    }
    d.push_back(diag(Severity::Info, DiagnosticKind::Limitation, "ownership",
                     "Ownership changes cannot take effect inside the user namespace; attempts appear as failed "
                     "syscalls rather than filesystem changes."));
    for (const auto& snapshot : {&before, &after}) {
        for (const auto& warning : snapshot->warnings) {
            d.push_back(diag(Severity::Warning, DiagnosticKind::Limitation, "snapshot", warning));
        }
    }
    if (!report.hostIntegrity.changes.empty()) {
        d.push_back(diag(Severity::Warning, DiagnosticKind::Warning, "host-changed", report.hostIntegrity.note));
    }
    for (const auto& event : report.resourceLimitEvents) {
        d.push_back(diag(Severity::Warning, DiagnosticKind::Warning, "resource-limit", event.detail));
    }
    if (execution.reason == TerminationReason::LaunchFailed) {
        d.push_back(diag(Severity::Error, DiagnosticKind::Error, "launch-failed", execution.detail));
    }

    auto& stats = report.statistics;
    stats.traceLinesParsed = collector.linesParsed();
    stats.traceLinesMalformed = collector.linesMalformed();
    stats.traceBytes = run.traceBytes;
    stats.eventsRecorded = report.events.size();
    stats.eventsDropped = collector.eventsDropped();
    stats.readOnlyOpens = collector.readOnlyOpens();
    stats.entriesBefore = before.entries.size();
    stats.entriesAfter = after.entries.size();
    stats.bytesHashed = before.bytesHashed + after.bytesHashed;

    if (staleRemoved > 0) {
        d.push_back(diag(Severity::Info, DiagnosticKind::Note, "stale-workspaces",
                         "Removed " + std::to_string(staleRemoved) +
                             " workspace(s) left behind by interrupted earlier analyses."));
    }
    if (config_.keepWorkspace) {
        d.push_back(diag(Severity::Info, DiagnosticKind::Note, "workspace-kept",
                         "Workspace kept at " + displaySafe(paths.runDir.string())));
    } else if (auto removed = workspace.remove(); !removed) {
        d.push_back(diag(Severity::Warning, DiagnosticKind::Warning, "cleanup", removed.error().message));
    }
    const auto finished = std::chrono::system_clock::now();
    report.finishedAt = isoTimestampUtc(finished);
    report.durationSeconds = std::chrono::duration<double>(finished - analysisStart).count();
    report_progress(AnalysisStage::Done, "Analysis complete", run.wallSeconds, collector.counts());
    return report;
}

}  // namespace tracepot
