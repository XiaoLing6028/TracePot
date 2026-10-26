#pragma once

#include "core/archive/SafeExtractor.hpp"
#include "core/models/Result.hpp"

#include <filesystem>
#include <string>

namespace tracepot {

struct EntryPoint {
    std::string relativePath;  // relative to the extraction root
    std::string interpreter;   // allowed shell name
};

// Chooses the shell script to execute from an extracted archive. An explicit request must name a
// regular file in the archive. Otherwise a single candidate named install.sh, setup.sh,
// installer.sh or install is searched at the top level or inside a single top-level directory.
Result<EntryPoint> resolveEntryPoint(const ExtractionResult& extraction, const std::filesystem::path& extractedRoot,
                                     const std::string& requested);

}  // namespace tracepot
