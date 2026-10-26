#pragma once

#include "core/analysis/Cancellation.hpp"
#include "core/models/AnalysisConfig.hpp"
#include "core/models/Report.hpp"
#include "core/models/Result.hpp"
#include "core/observers/TraceCollector.hpp"
#include "core/sandbox/Readiness.hpp"

#include <functional>
#include <optional>
#include <string>

namespace tracepot {

enum class AnalysisStage {
    Validating,
    PreparingWorkspace,
    CapturingBaseline,
    Running,
    Collecting,
    Comparing,
    Classifying,
    Finalizing,
    Done,
};

std::string_view stageLabel(AnalysisStage stage);

struct ProgressUpdate {
    AnalysisStage stage = AnalysisStage::Validating;
    double elapsedSeconds = 0;  // time since the sandboxed program started (Running and later)
    TraceCounts counts;
    std::string message;
};

using ProgressCallback = std::function<void(const ProgressUpdate&)>;

// Runs the complete analysis pipeline:
//   validate input -> prepare workspace -> baseline snapshots -> sandboxed execution with tracing
//   -> final snapshots and diff -> classification -> report -> workspace cleanup.
// Returns an error only if the sample was never executed (invalid input, unsafe archive,
// unavailable sandbox, cancellation before start). Once execution has started, a report is always
// produced — partial if the run was cancelled, timed out or hit a limit.
class Analyzer {
public:
    explicit Analyzer(AnalysisConfig config);

    // Reuses a previous readiness probe instead of probing again (the probe starts sandboxes).
    void setReadiness(Readiness readiness) { readiness_ = std::move(readiness); }

    Result<AnalysisReport> run(const CancellationToken& cancel, const ProgressCallback& progress = {});

private:
    AnalysisConfig config_;
    std::optional<Readiness> readiness_;
};

// Glob patterns (sandbox paths) whose reads are reported as credential/secret access attempts.
std::vector<std::string> defaultSensitiveReadPatterns();

}  // namespace tracepot
