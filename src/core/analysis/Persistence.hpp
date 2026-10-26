#pragma once

#include "core/models/Report.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace tracepot {

struct PersistenceRule {
    std::string id;
    PersistenceCategory category = PersistenceCategory::Custom;
    std::string scope;  // user or system
    std::vector<std::string> patterns;  // globs; "~/" expands to every home directory
    std::string description;
};

const std::vector<PersistenceRule>& builtinPersistenceRules();

// Classifies observations that touch startup/persistence-related locations. A match means the
// location can cause code to run later (at login, boot, on a schedule, with privileges, ...);
// it is an inference about the location, not a verdict about intent.
class PersistenceClassifier {
public:
    explicit PersistenceClassifier(const std::vector<std::string>& extraPatterns = {});

    [[nodiscard]] const PersistenceRule* match(std::string_view sandboxPath) const;

    [[nodiscard]] std::vector<PersistenceFinding> classify(const std::vector<FileChange>& changes,
                                                           const std::vector<TraceEvent>& events,
                                                           const std::vector<ProcessRecord>& processes) const;

private:
    struct CompiledRule {
        PersistenceRule rule;
        std::vector<std::string> globs;
    };
    std::vector<CompiledRule> compiled_;
};

// Host files and directories compared before and after each analysis to verify that nothing
// reached the host's persistence locations.
std::vector<std::filesystem::path> hostPersistencePaths(const std::filesystem::path& home);

}  // namespace tracepot
