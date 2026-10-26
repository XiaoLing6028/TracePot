// tracepot — command-line front end of TracePot. All analysis logic lives in tracepot_core and is
// shared with the GUI.

#include "Version.hpp"
#include "cli/CliOptions.hpp"
#include "core/analysis/Analyzer.hpp"
#include "core/reporting/ReportJson.hpp"
#include "core/reporting/ReportRender.hpp"
#include "core/sandbox/Readiness.hpp"
#include "core/util/FileUtil.hpp"

#include <csignal>
#include <cstdio>
#include <iostream>

#include <nlohmann/json.hpp>
#include <unistd.h>

namespace {

using namespace tracepot;
using namespace tracepot::cli;

// Signal handlers cannot capture state; this pointer is the one piece of global mutable state in
// the CLI. CancellationToken::cancel() is a lock-free atomic store and therefore signal-safe.
CancellationToken* gCancelToken = nullptr;

extern "C" void handleTerminationSignal(int /*signal*/)
{
    if (gCancelToken != nullptr) {
        gCancelToken->cancel();
    }
}

int exitCodeFor(ErrorCode code)
{
    switch (code) {
    case ErrorCode::InvalidArgument: return kExitUsage;
    case ErrorCode::InputNotFound:
    case ErrorCode::InputRejected:
    case ErrorCode::UnsupportedInput:
    case ErrorCode::ArchiveUnsafe:
    case ErrorCode::ArchiveMalformed:
    case ErrorCode::ArchiveLimitExceeded:
    case ErrorCode::EntryPointNotFound:
    case ErrorCode::ReportInvalid: return kExitInputRejected;
    case ErrorCode::SandboxUnavailable:
    case ErrorCode::ObserverUnavailable: return kExitSandboxUnavailable;
    case ErrorCode::Cancelled: return kExitInterrupted;
    default: return kExitAnalysisFailed;
    }
}

int reportError(const Error& error)
{
    std::cerr << "tracepot: error: " << error.message << "\n";
    if (!error.hint.empty()) {
        std::cerr << error.hint << (error.hint.back() == '\n' ? "" : "\n");
    }
    return exitCodeFor(error.code);
}

int runCheck(const Options& options)
{
    const Readiness readiness = checkReadiness();
    const bool ready = readiness.sandboxReady() && readiness.tracingReady();
    if (options.json) {
        nlohmann::json checks = nlohmann::json::array();
        for (const auto& check : readiness.checks) {
            checks.push_back({{"name", check.name},
                              {"ok", check.ok},
                              {"required", check.required},
                              {"detail", check.detail},
                              {"hint", check.hint}});
        }
        nlohmann::json out = {{"application", std::string(kApplicationName)},
                               {"version", std::string(kApplicationVersion)},
                               {"sandboxReady", readiness.sandboxReady()},
                               {"tracingReady", readiness.tracingReady()},
                               {"checks", checks}};
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "TracePot " << kApplicationVersion << " readiness check\n\n";
        for (const auto& check : readiness.checks) {
            const char* status = check.ok ? "  OK  " : (check.required ? " FAIL " : " WARN ");
            std::cout << "[" << status << "] " << check.name << ": " << check.detail << "\n";
            if (!check.ok && !check.hint.empty()) {
                std::cout << "         " << check.hint << "\n";
            }
        }
        std::cout << "\n"
                  << (ready ? "TracePot is ready to analyze inputs."
                            : "TracePot cannot analyze inputs until the failed checks are resolved.")
                  << "\n";
    }
    return ready ? kExitOk : kExitSandboxUnavailable;
}

int runAnalyze(Options& options)
{
    CancellationToken cancel;
    gCancelToken = &cancel;
    struct sigaction action {};
    action.sa_handler = handleTerminationSignal;
    sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);

    if (!options.quiet) {
        std::cerr << "TracePot " << kApplicationVersion << ": analyzing " << options.analysis.inputPath.string()
                  << "\n";
    }
    AnalysisStage lastStage = AnalysisStage::Done;
    double lastPrinted = -10;
    Analyzer analyzer(options.analysis);
    auto result = analyzer.run(cancel, [&](const ProgressUpdate& update) {
        if (options.quiet) {
            return;
        }
        if (update.stage != lastStage) {
            lastStage = update.stage;
            std::cerr << "  " << stageLabel(update.stage) << "...\n";
        } else if (update.stage == AnalysisStage::Running && update.elapsedSeconds - lastPrinted >= 2.0) {
            lastPrinted = update.elapsedSeconds;
            std::fprintf(stderr, "    %.0f s elapsed: %llu processes, %llu file events, %llu network events\n",
                         update.elapsedSeconds, static_cast<unsigned long long>(update.counts.processes),
                         static_cast<unsigned long long>(update.counts.fileEvents),
                         static_cast<unsigned long long>(update.counts.networkEvents));
        }
    });
    gCancelToken = nullptr;
    if (!result) {
        return reportError(result.error());
    }
    const AnalysisReport& report = result.value();

    if (auto made = makeDirectories(options.outputDir, 0755); !made) {
        return reportError(made.error());
    }
    const auto jsonPath = options.outputDir / (report.analysisId + ".json");
    const std::string json = serializeReport(report);
    if (auto written = writeTextFileAtomic(jsonPath, json); !written) {
        return reportError(written.error());
    }
    if (auto latest = writeTextFileAtomic(options.outputDir / "latest.json", json); !latest) {
        return reportError(latest.error());
    }
    std::filesystem::path htmlPath;
    if (options.writeHtml) {
        htmlPath = options.outputDir / (report.analysisId + ".html");
        if (auto written = writeTextFileAtomic(htmlPath, renderHtmlReport(report)); !written) {
            return reportError(written.error());
        }
    }
    std::cout << renderTextSummary(report, options.details) << "\n";
    std::cout << "JSON report: " << jsonPath.string() << "\n";
    if (!htmlPath.empty()) {
        std::cout << "HTML report: " << htmlPath.string() << "\n";
    }
    switch (report.execution.reason) {
    case TerminationReason::Cancelled: return kExitInterrupted;
    case TerminationReason::Timeout:
    case TerminationReason::ResourceLimit: return kExitSampleStopped;
    case TerminationReason::LaunchFailed: return kExitAnalysisFailed;
    default: return kExitOk;
    }
}

int runReport(const Options& options)
{
    auto loaded = loadReportFile(options.reportPath);
    if (!loaded) {
        return reportError(loaded.error());
    }
    if (!options.htmlOutput.empty()) {
        if (auto written = writeTextFileAtomic(options.htmlOutput, renderHtmlReport(loaded.value())); !written) {
            return reportError(written.error());
        }
        std::cerr << "HTML report written to " << options.htmlOutput.string() << "\n";
    }
    if (options.json) {
        std::cout << serializeReport(loaded.value());
    } else if (options.htmlOutput.empty() || options.details) {
        std::cout << renderTextSummary(loaded.value(), options.details);
    }
    return kExitOk;
}

}  // namespace

int main(int argc, char** argv)
{
    std::vector<std::string> args(argv + 1, argv + argc);
    auto parsed = parseCommandLine(args);
    if (!parsed) {
        std::cerr << "tracepot: " << parsed.error().message << "\n\n" << usageText();
        return kExitUsage;
    }
    Options& options = parsed.value();
    switch (options.command) {
    case Command::Help:
        std::cout << "TracePot " << kApplicationVersion << " — what did this installer actually do?\n\n"
                  << usageText();
        return kExitOk;
    case Command::Version:
        std::cout << kApplicationName << " " << kApplicationVersion << "\n";
        return kExitOk;
    case Command::Check:
        return runCheck(options);
    case Command::Analyze:
        return runAnalyze(options);
    case Command::Report:
        return runReport(options);
    }
    return kExitUsage;
}
