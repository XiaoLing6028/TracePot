#pragma once

#include "core/models/Limits.hpp"
#include "core/models/Report.hpp"
#include "core/models/Result.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace tracepot {

struct ExtractionResult {
    std::string format;
    std::vector<ArchiveEntrySummary> entries;
    std::uint64_t totalBytes = 0;
};

// Extracts a tar archive (any compression supported by libarchive) into `destination`, which must
// be an existing, empty directory. The whole archive is rejected — rather than silently skipping
// entries — if any member:
//   * has an absolute path or a ".." component,
//   * is a device node, FIFO or socket,
//   * is a symlink with an absolute target or a target that lexically escapes the root,
//   * is a hard link to something that is not an already-extracted regular file,
//   * would be written through a symlink or non-directory (checked component by component with
//     O_NOFOLLOW, so earlier members cannot redirect later ones),
//   * duplicates an existing member,
//   * exceeds entry-count, per-file, total-size, depth or path-length limits.
// Only permission bits (without setuid/setgid/sticky) are preserved; ownership, timestamps,
// ACLs and extended attributes are not restored.
Result<ExtractionResult> extractTarSafely(const std::filesystem::path& archivePath,
                                          const std::filesystem::path& destination, const ArchiveLimits& limits);

}  // namespace tracepot
