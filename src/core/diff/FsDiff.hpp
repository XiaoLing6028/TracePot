#pragma once

#include "core/diff/Snapshot.hpp"
#include "core/models/Report.hpp"

#include <cstddef>
#include <vector>

namespace tracepot {

struct DiffOptions {
    std::size_t maxTextDiffBytes = 65536;
    bool includeTextDiffs = true;
};

// Compares two snapshots. Directory timestamp/size changes are ignored because they only
// reflect changes to their contents, which are reported individually.
std::vector<FileChange> diffSnapshots(const Snapshot& before, const Snapshot& after, const DiffOptions& options);

}  // namespace tracepot
