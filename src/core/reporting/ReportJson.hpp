#pragma once

#include "core/models/Report.hpp"
#include "core/models/Result.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace tracepot {

// Serializes a report to the versioned TracePot JSON format (schemas/tracepot-report-1.schema.json).
// Missing values are written as explicit nulls.
std::string serializeReport(const AnalysisReport& report, int indent = 2);

// Parses a report. Rejects documents that are not TracePot reports or whose schema major version
// differs from the one this build understands. Unknown fields are ignored (forward compatible
// within a major version).
Result<AnalysisReport> parseReport(std::string_view json);

// Writes a file atomically (temporary file + rename) without following symlinks at the destination.
Status writeTextFileAtomic(const std::filesystem::path& path, std::string_view content);

Result<AnalysisReport> loadReportFile(const std::filesystem::path& path);

}  // namespace tracepot
