#pragma once

#include <cstddef>
#include <cstdint>

namespace tracepot {

inline constexpr std::uint64_t KiB = 1024;
inline constexpr std::uint64_t MiB = 1024 * KiB;
inline constexpr std::uint64_t GiB = 1024 * MiB;

// Limits applied to the sandboxed processes.
struct ResourceLimits {
    int timeoutSeconds = 120;
    std::uint64_t memoryBytes = 2 * GiB;       // RLIMIT_AS per process; 0 disables
    std::uint32_t maxProcesses = 256;          // additional processes (RLIMIT_NPROC); 0 disables
    std::uint64_t maxFileSizeBytes = 512 * MiB;  // RLIMIT_FSIZE; 0 disables
    std::uint64_t maxDiskBytes = 1 * GiB;      // total workspace growth, enforced by polling; 0 disables
    std::uint32_t maxOpenFiles = 1024;         // RLIMIT_NOFILE
};

// Limits applied while snapshotting the sandbox filesystem.
struct SnapshotLimits {
    std::uint64_t maxEntries = 200000;
    std::uint64_t maxHashFileBytes = 64 * MiB;
    std::uint64_t maxTotalHashBytes = 2 * GiB;
    std::uint64_t maxTextBytes = 64 * KiB;
    std::uint64_t maxTotalTextBytes = 32 * MiB;
    int maxDepth = 64;
};

// Limits applied when extracting archives on the host before execution.
struct ArchiveLimits {
    std::uint64_t maxEntries = 20000;
    std::uint64_t maxTotalBytes = 1 * GiB;
    std::uint64_t maxFileBytes = 512 * MiB;
    std::size_t maxPathLength = 1024;
    int maxDepth = 48;
};

// Limits on collected evidence and report size.
struct CollectionLimits {
    std::uint64_t maxEvents = 100000;
    std::uint64_t maxTraceBytes = 1 * GiB;
    std::uint64_t maxOutputExcerptBytes = 16 * KiB;
    std::uint64_t maxTextDiffBytes = 64 * KiB;
    std::size_t maxArchiveManifestEntries = 2000;
    SnapshotLimits snapshot;
    ArchiveLimits archive;
};

}  // namespace tracepot
