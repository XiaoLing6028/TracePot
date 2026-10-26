#pragma once

#include "core/models/Limits.hpp"
#include "core/models/Types.hpp"

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace tracepot {

// Everything needed to run one analysis. Shared by the CLI and the GUI.
struct AnalysisConfig {
    std::filesystem::path inputPath;

    // For archives: path of the shell script inside the archive to execute.
    // Empty means auto-detect (install.sh, setup.sh, installer.sh, install).
    std::string entryPoint;

    // Passed to the script as an argument vector; never joined into a shell string.
    std::vector<std::string> arguments;

    // Extra environment variables for the sandboxed process. Only names are written to reports.
    std::vector<std::pair<std::string, std::string>> environment;

    SandboxUser user = SandboxUser::Unprivileged;
    ResourceLimits limits;
    CollectionLimits collection;

    // When false, the analysis may run without the syscall tracer (filesystem diff only).
    // The report then records the missing observation explicitly.
    bool requireTracing = true;

    bool keepWorkspace = false;

    // Base directory for analysis workspaces. Empty means $XDG_CACHE_HOME/tracepot/runs.
    std::filesystem::path workspaceBase;

    // Additional glob patterns (sandbox paths, `~` = any home) to classify as persistence.
    std::vector<std::string> extraPersistencePatterns;

    // Location of the tracepot-limits helper. Empty means auto-detect next to the executable.
    std::filesystem::path helperPath;

    // Host home directory for the host-integrity check. Empty means $HOME.
    std::filesystem::path hostHome;
};

}  // namespace tracepot
