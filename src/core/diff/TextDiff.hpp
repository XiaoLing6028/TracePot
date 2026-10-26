#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace tracepot {

struct TextDiffResult {
    std::string diff;
    bool truncated = false;
};

// Produces a unified diff (like `diff -u`) between two texts. The output is capped at maxBytes.
// For very large changed regions the diff falls back to "remove all, add all", which is still a
// correct (if non-minimal) diff.
TextDiffResult unifiedDiff(std::string_view before, std::string_view after, std::string_view labelBefore,
                           std::string_view labelAfter, std::size_t context = 3, std::size_t maxBytes = 65536);

}  // namespace tracepot
