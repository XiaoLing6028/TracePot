#pragma once

#include "core/models/Result.hpp"
#include "core/models/Types.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

namespace tracepot {

struct InputInfo {
    std::filesystem::path path;
    InputKind kind = InputKind::Unsupported;
    std::string format;       // e.g. "shell script", "tar+gzip"
    std::string interpreter;  // shell name for scripts (sh, bash, ...)
    std::string reason;       // why an input is unsupported
    bool malformed = false;   // recognized as an archive but damaged (truncated, corrupt)
    std::uint64_t sizeBytes = 0;
};

inline constexpr std::uint64_t kMaxInputBytes = 2ULL * 1024 * 1024 * 1024;

// Detects the input type from its content (magic bytes / shebang) and extension.
// Never executes anything. Unsupported inputs are returned with kind == Unsupported and a reason.
Result<InputInfo> inspectInput(const std::filesystem::path& path);

// Detects the type of an in-memory header (first bytes of a file). Exposed for testing.
InputInfo classifyHeader(std::string_view header, const std::string& fileName);

// Returns the interpreter named by a shell script's shebang ("sh" when there is none and the
// file is a .sh script). Empty if the interpreter is not an allowed shell.
std::string shellInterpreterFor(std::string_view header, const std::string& fileName, std::string* rejected);

}  // namespace tracepot
