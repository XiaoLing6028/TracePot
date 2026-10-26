#include "core/reporting/ReportRender.hpp"

#include "core/util/TimeUtil.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

namespace tracepot {

namespace {

std::string escapeHtml(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

std::string modeString(std::uint32_t mode)
{
    char buffer[8];
    std::snprintf(buffer, sizeof(buffer), "%04o", mode & 07777);
    return buffer;
}

std::string relativeTime(double timestamp, double origin)
{
    if (origin <= 0 || timestamp <= 0) {
        return "";
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "+%.3f s", timestamp - origin);
    return buffer;
}

double timeOrigin(const AnalysisReport& report)
{
    double origin = 0;
    for (const auto& process : report.processes) {
        if (process.startTime && (origin == 0 || *process.startTime < origin)) {
            origin = *process.startTime;
        }
    }
    return origin;
}

std::string joinArgs(const std::vector<std::string>& argv)
{
    std::string joined;
    for (const auto& arg : argv) {
        if (!joined.empty()) {
            joined += ' ';
        }
        joined += arg;
    }
    return joined;
}

std::string networkTarget(const NetworkEvent& event)
{
    std::string target = event.hostname.empty() ? event.address : event.hostname;
    if (!event.hostname.empty() && !event.address.empty()) {
        target += " via " + event.address;
    }
    if (event.port) {
        target += ":" + std::to_string(*event.port);
    }
    return target;
}

std::string changeSummary(const FileChange& change)
{
    std::string text = std::string(enumName(change.kind));
    if (!change.aspects.empty()) {
        text += " (";
        for (std::size_t i = 0; i < change.aspects.size(); ++i) {
            text += (i > 0 ? ", " : "") + change.aspects[i];
        }
        text += ")";
    }
    return text;
}

const char* kStyle = R"CSS(
:root { --bg:#ffffff; --fg:#1d1f21; --muted:#5f6368; --border:#d0d4d9; --head:#f3f4f6;
        --warn:#8a5a00; --warnbg:#fff4d6; --err:#a01818; --errbg:#fde8e8; --ok:#17663a; --code:#f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16181b; --fg:#e6e6e6; --muted:#a0a6ad; --border:#3a3f45; --head:#22262b;
          --warn:#f0c46c; --warnbg:#3a2f12; --err:#ff9a9a; --errbg:#3d1a1a; --ok:#7ed69f; --code:#1e2125; }
}
body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0 auto;
       max-width: 1200px; padding: 16px; line-height: 1.45; }
h1 { font-size: 1.6rem; margin-bottom: 0.2rem; }
h2 { font-size: 1.2rem; border-bottom: 1px solid var(--border); padding-bottom: 4px; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; margin: 8px 0; }
th, td { border: 1px solid var(--border); padding: 4px 6px; text-align: left; vertical-align: top;
         overflow-wrap: anywhere; }
th { background: var(--head); }
code, pre { font-family: ui-monospace, monospace; font-size: 0.85rem; }
pre { background: var(--code); padding: 8px; overflow-x: auto; white-space: pre-wrap; border: 1px solid var(--border); }
.muted { color: var(--muted); }
.banner { border: 1px solid var(--warn); background: var(--warnbg); color: var(--fg); padding: 8px 12px; margin: 12px 0; }
.tag { display: inline-block; border: 1px solid var(--border); border-radius: 3px; padding: 0 4px; font-size: 0.8rem; }
.sev-warning { color: var(--warn); font-weight: 600; }
.sev-error { color: var(--err); font-weight: 600; }
.wrap { overflow-x: auto; }
details summary { cursor: pointer; }
)CSS";

}  // namespace

std::string formatBytes(std::uint64_t bytes)
{
    char buffer[32];
    if (bytes < 1024) {
        std::snprintf(buffer, sizeof(buffer), "%llu B", static_cast<unsigned long long>(bytes));
    } else if (bytes < 1024ULL * 1024) {
        std::snprintf(buffer, sizeof(buffer), "%.1f KiB", static_cast<double>(bytes) / 1024.0);
    } else if (bytes < 1024ULL * 1024 * 1024) {
        std::snprintf(buffer, sizeof(buffer), "%.1f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.2f GiB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    }
    return buffer;
}

std::string describeTermination(const ExecutionResult& e)
{
    std::string text;
    switch (e.reason) {
    case TerminationReason::NotStarted: text = "not started"; break;
    case TerminationReason::Exited:
        text = e.exitCode ? "exited with status " + std::to_string(*e.exitCode) : "exited";
        break;
    case TerminationReason::Signaled: text = "terminated by " + (e.signal.empty() ? std::string("a signal") : e.signal); break;
    case TerminationReason::Timeout: text = "stopped by TracePot: timeout"; break;
    case TerminationReason::Cancelled: text = "stopped by TracePot: cancelled"; break;
    case TerminationReason::ResourceLimit: text = "stopped by TracePot: resource limit"; break;
    case TerminationReason::LaunchFailed: text = "launch failed"; break;
    }
    if (!e.detail.empty() && e.reason != TerminationReason::Exited) {
        text += " — " + e.detail;
    }
    return text;
}

std::string renderHtmlReport(const AnalysisReport& r)
{
    const double origin = timeOrigin(r);
    std::ostringstream h;
    h << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
      << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
      << "<meta name=\"generator\" content=\"" << escapeHtml(r.applicationName) << " "
      << escapeHtml(r.applicationVersion) << "\">\n"
      << "<title>TracePot report: " << escapeHtml(r.input.fileName) << "</title>\n<style>" << kStyle
      << "</style>\n</head>\n<body>\n";
    h << "<h1>TracePot report</h1>\n<p class=\"muted\">" << escapeHtml(r.input.fileName) << " &middot; analysis "
      << escapeHtml(r.analysisId) << " &middot; " << escapeHtml(r.startedAt) << " &middot; schema "
      << escapeHtml(r.schemaVersion) << "</p>\n";
    h << "<div class=\"banner\" role=\"note\"><strong>How to read this report.</strong> "
      << escapeHtml(r.disclaimer)
      << " <em>Observed</em> entries were recorded directly; <em>inferred</em> entries are classifications.</div>\n";

    // Summary
    h << "<h2 id=\"summary\">Summary</h2>\n<table>\n";
    auto row = [&h](const std::string& key, const std::string& value) {
        h << "<tr><th scope=\"row\">" << escapeHtml(key) << "</th><td>" << escapeHtml(value) << "</td></tr>\n";
    };
    row("Input", r.input.fileName + " (" + std::string(enumName(r.input.kind)) + ", " + formatBytes(r.input.sizeBytes) + ")");
    row("SHA-256", r.input.sha256);
    row("Entry point", r.input.entryPoint + (r.input.interpreter.empty() ? "" : " (run with " + r.input.interpreter + ")"));
    row("Arguments", r.input.arguments.empty() ? "(none)" : joinArgs(r.input.arguments));
    row("Outcome", describeTermination(r.execution));
    char seconds[32];
    std::snprintf(seconds, sizeof(seconds), "%.2f s", r.execution.executionSeconds);
    row("Execution time", seconds);
    row("Sandbox", r.sandbox.backend + " " + r.sandbox.backendVersion + ", simulated user: " +
                       std::string(enumName(r.sandbox.user)) + ", namespaces: " + joinArgs(r.sandbox.namespaces));
    row("Network policy", r.networkPolicy.mode + " — " + r.networkPolicy.description);
    row("Tracing", r.sandbox.tracingEnabled ? r.sandbox.tracer + " (" + r.sandbox.tracerVersion + ")"
                                            : "not available (process, file-event and network evidence missing)");
    row("Observed", std::to_string(r.processes.size()) + " processes, " + std::to_string(r.filesystemChanges.size()) +
                        " filesystem changes, " + std::to_string(r.networkEvents.size()) + " network events, " +
                        std::to_string(r.persistence.size()) + " persistence-related findings");
    row("Host integrity", r.hostIntegrity.performed ? std::to_string(r.hostIntegrity.changes.size()) +
                                                          " changes in " +
                                                          std::to_string(r.hostIntegrity.pathsChecked.size()) +
                                                          " checked host locations"
                                                    : "not performed");
    h << "</table>\n";

    // Diagnostics
    h << "<h2 id=\"diagnostics\">Warnings and limitations</h2>\n<table>\n<tr><th>Severity</th><th>Kind</th>"
         "<th>Message</th></tr>\n";
    for (const auto& d : r.diagnostics) {
        const std::string severity(enumName(d.severity));
        h << "<tr><td class=\"sev-" << severity << "\">" << escapeHtml(severity) << "</td><td>"
          << escapeHtml(std::string(enumName(d.kind))) << "</td><td>" << escapeHtml(d.message) << "</td></tr>\n";
    }
    h << "</table>\n";

    // Persistence
    h << "<h2 id=\"persistence\">Persistence-related changes <span class=\"tag\">inferred</span></h2>\n";
    if (r.persistence.empty()) {
        h << "<p>No persistence-related locations were modified or targeted in the observed run.</p>\n";
    } else {
        h << "<p class=\"muted\">A persistence-related location is not automatically malicious; "
             "installers legitimately create services and shell configuration.</p>\n"
          << "<table>\n<tr><th>Category</th><th>Scope</th><th>Path</th><th>Action</th><th>Outcome</th>"
             "<th>Basis</th><th>PIDs</th><th>Description</th></tr>\n";
        for (const auto& f : r.persistence) {
            std::string basis;
            for (const auto b : f.basis) {
                basis += (basis.empty() ? "" : ", ") + std::string(enumName(b));
            }
            std::string pids;
            for (const int pid : f.pids) {
                pids += (pids.empty() ? "" : ", ") + std::to_string(pid);
            }
            h << "<tr><td>" << escapeHtml(std::string(enumName(f.category))) << "</td><td>" << escapeHtml(f.scope)
              << "</td><td><code>" << escapeHtml(f.path) << "</code></td><td>" << escapeHtml(f.action) << "</td><td>"
              << escapeHtml(f.outcome) << "</td><td>" << escapeHtml(basis) << "</td><td>" << escapeHtml(pids)
              << "</td><td>" << escapeHtml(f.description) << "</td></tr>\n";
        }
        h << "</table>\n";
    }

    // Filesystem
    h << "<h2 id=\"filesystem\">Filesystem changes inside the sandbox <span class=\"tag\">observed</span></h2>\n";
    if (r.filesystemChanges.empty()) {
        h << "<p>No filesystem changes were detected.</p>\n";
    } else {
        h << "<div class=\"wrap\"><table>\n<tr><th>Path</th><th>Change</th><th>Area</th><th>Type</th><th>Mode</th>"
             "<th>Size</th><th>SHA-256</th><th>PIDs</th></tr>\n";
        for (const auto& c : r.filesystemChanges) {
            const FileMetadata* meta = c.after ? &*c.after : (c.before ? &*c.before : nullptr);
            std::string mode;
            if (c.before && c.after && c.before->mode != c.after->mode) {
                mode = modeString(c.before->mode) + " → " + modeString(c.after->mode);
            } else if (meta != nullptr) {
                mode = modeString(meta->mode);
            }
            std::string pids;
            for (const int pid : c.attributedPids) {
                pids += (pids.empty() ? "" : ", ") + std::to_string(pid);
            }
            std::string type = meta != nullptr ? std::string(enumName(meta->type)) : "";
            if (meta != nullptr && meta->type == FileType::Symlink) {
                type += " → " + meta->linkTarget;
            }
            h << "<tr><td><code>" << escapeHtml(c.path) << "</code></td><td>" << escapeHtml(changeSummary(c))
              << "</td><td>" << escapeHtml(c.area) << "</td><td>" << escapeHtml(type) << "</td><td>"
              << escapeHtml(mode) << "</td><td>" << (meta != nullptr ? escapeHtml(formatBytes(meta->size)) : "")
              << "</td><td><code>"
              << escapeHtml(meta != nullptr && meta->sha256 ? meta->sha256->substr(0, 16) + "…" : meta != nullptr ? meta->hashNote : "")
              << "</code></td><td>" << escapeHtml(pids) << "</td></tr>\n";
        }
        h << "</table></div>\n";
        for (const auto& c : r.filesystemChanges) {
            if (c.textDiff) {
                h << "<details><summary><code>" << escapeHtml(c.path) << "</code> content diff"
                  << (c.textDiffTruncated ? " (truncated)" : "") << "</summary><pre>" << escapeHtml(*c.textDiff)
                  << "</pre></details>\n";
            }
        }
    }

    // Processes
    h << "<h2 id=\"processes\">Process timeline <span class=\"tag\">observed</span></h2>\n";
    if (r.processes.empty()) {
        h << "<p>" << (r.sandbox.tracingEnabled ? "No processes were recorded." : "Not observed: tracing was unavailable.")
          << "</p>\n";
    } else {
        h << "<div class=\"wrap\"><table>\n<tr><th>Start</th><th>PID</th><th>Parent</th><th>Executable</th>"
             "<th>Arguments</th><th>End</th></tr>\n";
        for (const auto& p : r.processes) {
            std::string end;
            if (p.exitCode) {
                end = "exit " + std::to_string(*p.exitCode);
            } else if (!p.signal.empty()) {
                end = p.signal;
            }
            if (p.terminatedAtTeardown) {
                end += " (sandbox teardown)";
            }
            const std::string exe = p.executable().empty() ? "(forked, no exec)" : p.executable();
            h << "<tr><td>" << escapeHtml(relativeTime(p.startTime.value_or(0), origin)) << "</td><td>" << p.pid
              << "</td><td>" << (p.ppid ? std::to_string(*p.ppid) : std::string("—")) << "</td><td><code>"
              << escapeHtml(exe) << "</code></td><td><code>" << escapeHtml(joinArgs(p.argv())) << "</code></td><td>"
              << escapeHtml(end) << "</td></tr>\n";
        }
        h << "</table></div>\n";
    }

    // Network
    h << "<h2 id=\"network\">Network activity</h2>\n<p class=\"muted\">"
      << escapeHtml(r.networkPolicy.description) << "</p>\n";
    if (r.networkEvents.empty()) {
        h << "<p>" << (r.sandbox.tracingEnabled ? "No network activity was observed."
                                                 : "Not observed: tracing was unavailable.")
          << "</p>\n";
    } else {
        h << "<div class=\"wrap\"><table>\n<tr><th>Time</th><th>PID</th><th>Kind</th><th>Evidence</th>"
             "<th>Protocol</th><th>Destination</th><th>Outcome</th><th>Detail</th></tr>\n";
        for (const auto& n : r.networkEvents) {
            h << "<tr><td>" << escapeHtml(relativeTime(n.timestamp.value_or(0), origin)) << "</td><td>"
              << (n.pid ? std::to_string(*n.pid) : std::string()) << "</td><td>"
              << escapeHtml(std::string(enumName(n.kind))) << "</td><td>"
              << escapeHtml(std::string(enumName(n.evidence))) << "</td><td>" << escapeHtml(n.protocol)
              << "</td><td><code>" << escapeHtml(networkTarget(n)) << "</code></td><td>"
              << escapeHtml(std::string(enumName(n.outcome)) + (n.error.empty() ? "" : " (" + n.error + ")"))
              << "</td><td>" << escapeHtml(n.detail) << "</td></tr>\n";
        }
        h << "</table></div>\n";
    }

    // Host integrity
    h << "<h2 id=\"host\">Host integrity check <span class=\"tag\">observed</span></h2>\n<p>"
      << escapeHtml(r.hostIntegrity.note) << "</p>\n";
    if (!r.hostIntegrity.changes.empty()) {
        h << "<ul>\n";
        for (const auto& c : r.hostIntegrity.changes) {
            h << "<li><code>" << escapeHtml(c.path) << "</code>: " << escapeHtml(changeSummary(c)) << "</li>\n";
        }
        h << "</ul>\n";
    }
    h << "<details><summary>Checked host locations</summary><ul>\n";
    for (const auto& path : r.hostIntegrity.pathsChecked) {
        h << "<li><code>" << escapeHtml(path) << "</code></li>\n";
    }
    h << "</ul></details>\n";

    // Sandbox configuration
    h << "<h2 id=\"sandbox\">Sandbox configuration</h2>\n<table>\n";
    row("Read-only paths", joinArgs(r.sandbox.readOnlyPaths));
    row("Writable paths", joinArgs(r.sandbox.writablePaths));
    row("Seccomp", r.sandbox.seccompEnabled ? "enabled; blocked: " + joinArgs(r.sandbox.seccompBlocked) : "disabled");
    const auto& l = r.sandbox.limits;
    row("Limits", "timeout " + std::to_string(l.timeoutSeconds) + " s, memory " + formatBytes(l.memoryBytes) +
                      ", processes +" + std::to_string(l.maxProcesses) + ", file size " +
                      formatBytes(l.maxFileSizeBytes) + ", disk growth " + formatBytes(l.maxDiskBytes));
    for (const auto& note : r.sandbox.limitNotes) {
        row("Limit note", note);
    }
    h << "</table>\n";

    // Output
    h << "<h2 id=\"output\">Captured output <span class=\"tag\">untrusted</span></h2>\n";
    h << "<h3>stdout (" << escapeHtml(formatBytes(r.execution.stdoutBytes)) << ")</h3><pre>"
      << escapeHtml(r.execution.stdoutExcerpt) << "</pre>\n";
    h << "<h3>stderr (" << escapeHtml(formatBytes(r.execution.stderrBytes))
      << ", includes launcher diagnostics)</h3><pre>" << escapeHtml(r.execution.stderrExcerpt) << "</pre>\n";

    if (r.input.archive) {
        const auto& a = *r.input.archive;
        h << "<h2 id=\"archive\">Archive contents</h2>\n<p>" << a.entryCount << " entries, "
          << escapeHtml(formatBytes(a.totalBytes)) << (a.entriesTruncated ? " (list truncated)" : "") << "</p>\n"
          << "<details><summary>Entries</summary><table>\n<tr><th>Path</th><th>Type</th><th>Size</th><th>Mode</th></tr>\n";
        for (const auto& e : a.entries) {
            std::string type(enumName(e.type));
            if (!e.linkTarget.empty()) {
                type += " → " + e.linkTarget;
            }
            h << "<tr><td><code>" << escapeHtml(e.path) << "</code></td><td>" << escapeHtml(type) << "</td><td>"
              << escapeHtml(formatBytes(e.size)) << "</td><td>" << modeString(e.mode) << "</td></tr>\n";
        }
        h << "</table></details>\n";
    }
    h << "<p class=\"muted\">Generated by " << escapeHtml(r.applicationName) << " " << escapeHtml(r.applicationVersion)
      << " at " << escapeHtml(r.finishedAt) << ".</p>\n</body>\n</html>\n";
    return h.str();
}

std::string renderTextSummary(const AnalysisReport& r, bool detailed)
{
    std::ostringstream out;
    out << "TracePot report " << r.analysisId << " (schema " << r.schemaVersion << ")\n";
    out << "  Input:       " << r.input.fileName << " [" << enumName(r.input.kind) << ", "
        << formatBytes(r.input.sizeBytes) << "]\n";
    out << "  SHA-256:     " << r.input.sha256 << "\n";
    out << "  Entry point: " << r.input.entryPoint << "\n";
    out << "  Outcome:     " << describeTermination(r.execution) << "\n";
    char seconds[32];
    std::snprintf(seconds, sizeof(seconds), "%.2f s", r.execution.executionSeconds);
    out << "  Duration:    " << seconds << "\n";
    out << "  Network:     " << r.networkPolicy.mode << " (no external connectivity)\n";
    out << "  Tracing:     " << (r.sandbox.tracingEnabled ? r.sandbox.tracer : std::string("unavailable")) << "\n\n";

    std::size_t created = 0;
    std::size_t modified = 0;
    std::size_t deleted = 0;
    for (const auto& c : r.filesystemChanges) {
        (c.kind == ChangeKind::Created ? created : c.kind == ChangeKind::Deleted ? deleted : modified)++;
    }
    out << "Observed:\n";
    out << "  Processes:          " << r.processes.size() << "\n";
    out << "  Filesystem changes: " << r.filesystemChanges.size() << " (" << created << " created, " << modified
        << " modified, " << deleted << " deleted)\n";
    out << "  Network events:     " << r.networkEvents.size() << "\n";
    out << "  Host integrity:     " << r.hostIntegrity.changes.size() << " host changes in "
        << r.hostIntegrity.pathsChecked.size() << " checked locations\n\n";

    if (!r.persistence.empty()) {
        out << "Persistence-related findings (inferred; not automatically malicious):\n";
        for (const auto& f : r.persistence) {
            out << "  [" << enumName(f.category) << ", " << f.scope << "] " << f.path << " — " << f.action << ", "
                << f.outcome << "\n";
        }
        out << "\n";
    }
    if (!r.networkEvents.empty()) {
        out << "Network activity:\n";
        std::size_t shown = 0;
        for (const auto& n : r.networkEvents) {
            if (!detailed && ++shown > 15) {
                out << "  ... " << (r.networkEvents.size() - 15) << " more (use --details)\n";
                break;
            }
            out << "  " << enumName(n.kind) << " " << networkTarget(n) << " — " << enumName(n.outcome)
                << (n.error.empty() ? "" : " (" + n.error + ")") << " [" << enumName(n.evidence) << "]\n";
        }
        out << "\n";
    }
    if (detailed) {
        out << "Processes:\n";
        for (const auto& p : r.processes) {
            out << "  " << p.pid << " <- " << (p.ppid ? std::to_string(*p.ppid) : std::string("?")) << "  "
                << (p.executable().empty() ? "(fork)" : joinArgs(p.argv())) << "\n";
        }
        out << "\nFilesystem changes:\n";
        for (const auto& c : r.filesystemChanges) {
            out << "  " << changeSummary(c) << "  " << c.path << "\n";
        }
        out << "\n";
    }
    std::size_t warnings = 0;
    for (const auto& d : r.diagnostics) {
        if (d.severity != Severity::Info) {
            ++warnings;
            out << (warnings == 1 ? "Warnings:\n" : "") << "  [" << enumName(d.severity) << "] " << d.message << "\n";
        }
    }
    out << "\n" << r.disclaimer << "\n";
    return out.str();
}

}  // namespace tracepot
