#pragma once

#include "core/models/Report.hpp"

#include <string>

namespace tracepot {

// Self-contained HTML document (inline CSS, no scripts, all content escaped).
std::string renderHtmlReport(const AnalysisReport& report);

// Plain-text summary for the command line.
std::string renderTextSummary(const AnalysisReport& report, bool detailed = false);

// Short human-readable description of how the run ended.
std::string describeTermination(const ExecutionResult& execution);

std::string formatBytes(std::uint64_t bytes);

}  // namespace tracepot
