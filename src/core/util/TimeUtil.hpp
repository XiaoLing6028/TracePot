#pragma once

#include <chrono>
#include <string>

namespace tracepot {

// ISO 8601 UTC timestamp with millisecond precision, e.g. 2026-01-02T03:04:05.678Z.
std::string isoTimestampUtc(std::chrono::system_clock::time_point time);
std::string isoTimestampFromEpoch(double epochSeconds);

double epochSeconds(std::chrono::system_clock::time_point time);

// Unique, filesystem-safe analysis identifier: tracepot-YYYYMMDDTHHMMSSZ-<random hex>.
std::string makeAnalysisId();

}  // namespace tracepot
