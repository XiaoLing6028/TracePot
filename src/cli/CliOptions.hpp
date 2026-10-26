#pragma once

#include "core/models/AnalysisConfig.hpp"
#include "core/models/Result.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace tracepot::cli {

enum class Command { Help, Version, Check, Analyze, Report };

// Process exit codes of the tracepot executable.
enum ExitCode : int {
    kExitOk = 0,
    kExitUsage = 1,
    kExitInputRejected = 2,      // unsupported/unsafe input or invalid report file
    kExitSandboxUnavailable = 3, // sandbox or tracer not usable (also: `check` found problems)
    kExitAnalysisFailed = 4,     // I/O or internal failure
    kExitInterrupted = 5,        // cancelled (SIGINT/SIGTERM); a partial report may have been written
    kExitSampleStopped = 6,      // report written, but the sample was stopped by a timeout or limit
};

struct Options {
    Command command = Command::Help;
    bool json = false;
    bool quiet = false;
    bool details = false;
    bool writeHtml = true;
    AnalysisConfig analysis;
    std::filesystem::path outputDir = "tracepot-results";
    std::filesystem::path reportPath;
    std::filesystem::path htmlOutput;
};

Result<Options> parseCommandLine(const std::vector<std::string>& args);

std::string usageText();

}  // namespace tracepot::cli
