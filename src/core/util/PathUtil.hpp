#pragma once

#include "core/models/Result.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace tracepot {

// Normalizes a relative archive member path ("./a//b/" -> "a/b").
// Rejects absolute paths, ".." components, NUL bytes and empty results.
Result<std::string> normalizeArchivePath(std::string_view path);

// Lexically normalizes an absolute path: removes "." and empty components and resolves ".."
// (".." at the root stays at the root). Symlinks are not consulted.
std::string normalizeAbsolute(std::string_view path);

// Resolves `path` against `base` (an absolute directory) lexically.
std::string resolveAgainst(std::string_view base, std::string_view path);

// True if a symlink located in directory `linkDir` (relative to a root, "" for the root itself)
// with relative target `target` lexically resolves outside that root.
bool symlinkTargetEscapes(std::string_view linkDir, std::string_view target);

bool isValidUtf8(std::string_view text);

// Makes arbitrary bytes safe for display and JSON: valid UTF-8 is preserved, control characters
// and invalid bytes are rendered as escapes (\n, \t, \xNN). Prevents terminal/report injection.
std::string displaySafe(std::string_view bytes);

// Like displaySafe, but keeps newlines and tabs (for captured stdout/stderr excerpts).
std::string displaySafeMultiline(std::string_view bytes);

// Classifies a sandbox path into a coarse area used for filtering.
std::string sandboxArea(std::string_view path);

// XDG base directories (absolute paths only, as required by the specification).
std::filesystem::path xdgCacheHome();
std::filesystem::path xdgConfigHome();
std::filesystem::path tracepotCacheDir();
std::filesystem::path tracepotConfigDir();

// Real home directory of the invoking user ($HOME, falling back to the passwd entry).
std::filesystem::path hostHomeDirectory();

}  // namespace tracepot
