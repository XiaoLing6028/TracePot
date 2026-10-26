#pragma once

#include "core/models/Limits.hpp"
#include "core/models/Report.hpp"
#include "core/models/Result.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tracepot {

struct SnapshotEntry {
    FileMetadata meta;
    std::optional<std::string> text;  // content of small, valid UTF-8 text files
};

struct Snapshot {
    std::map<std::string, SnapshotEntry> entries;  // keyed by display path
    bool truncated = false;
    std::vector<std::string> warnings;
    std::uint64_t bytesHashed = 0;
    std::uint64_t textBytes = 0;
};

// A tree (or single file) to capture: the host location and the path under which entries are
// reported (e.g. host "<workspace>/root" reported as "/").
struct SnapshotRoot {
    std::filesystem::path hostPath;
    std::string displayPath;
};

struct SnapshotOptions {
    SnapshotLimits limits;
    bool captureText = true;
    // Optional ownership translation from host IDs to the IDs seen inside the sandbox.
    std::optional<std::pair<std::uint32_t, std::uint32_t>> uidMapping;
    std::optional<std::pair<std::uint32_t, std::uint32_t>> gidMapping;
};

// Captures metadata, SHA-256 hashes (within limits) and small text contents.
// Never follows symlinks and never opens non-regular files. Missing roots are skipped.
Snapshot takeSnapshot(const std::vector<SnapshotRoot>& roots, const SnapshotOptions& options);

struct TreeUsage {
    std::uint64_t bytes = 0;    // allocated blocks
    std::uint64_t entries = 0;
    bool truncated = false;     // stopped at maxEntries
};

// Fast metadata-only scan used by the disk watchdog while the sandbox is running.
TreeUsage measureTree(const std::filesystem::path& root, std::uint64_t maxEntries);

}  // namespace tracepot
