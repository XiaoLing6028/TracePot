#include "core/models/Report.hpp"
#include "core/models/Result.hpp"

namespace tracepot {

std::string_view enumName(ErrorCode code)
{
    switch (code) {
    case ErrorCode::InvalidArgument: return "invalid-argument";
    case ErrorCode::InputNotFound: return "input-not-found";
    case ErrorCode::InputRejected: return "input-rejected";
    case ErrorCode::UnsupportedInput: return "unsupported-input";
    case ErrorCode::ArchiveUnsafe: return "archive-unsafe";
    case ErrorCode::ArchiveMalformed: return "archive-malformed";
    case ErrorCode::ArchiveLimitExceeded: return "archive-limit-exceeded";
    case ErrorCode::EntryPointNotFound: return "entry-point-not-found";
    case ErrorCode::SandboxUnavailable: return "sandbox-unavailable";
    case ErrorCode::ObserverUnavailable: return "observer-unavailable";
    case ErrorCode::LaunchFailed: return "launch-failed";
    case ErrorCode::Io: return "io-error";
    case ErrorCode::Cancelled: return "cancelled";
    case ErrorCode::ReportInvalid: return "report-invalid";
    case ErrorCode::Internal: return "internal-error";
    }
    return "unknown";
}

std::string Error::describe() const
{
    std::string text = message;
    if (!hint.empty()) {
        text += "\nHint: ";
        text += hint;
    }
    return text;
}

std::string ProcessRecord::executable() const
{
    for (auto it = execs.rbegin(); it != execs.rend(); ++it) {
        if (it->outcome == Outcome::Success) {
            return it->path;
        }
    }
    return {};
}

std::vector<std::string> ProcessRecord::argv() const
{
    for (auto it = execs.rbegin(); it != execs.rend(); ++it) {
        if (it->outcome == Outcome::Success) {
            return it->argv;
        }
    }
    return {};
}

std::string reportSchemaVersionString()
{
    return std::to_string(kReportSchemaMajor) + "." + std::to_string(kReportSchemaMinor);
}

std::string reportDisclaimer()
{
    return "TracePot reports behavior observed inside its sandbox during a single, time-limited run. "
           "The absence of suspicious observations does not mean the input is safe: code can detect "
           "analysis environments, wait, depend on network responses, or act through channels that "
           "were not observed.";
}

}  // namespace tracepot
