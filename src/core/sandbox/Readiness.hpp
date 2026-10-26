#pragma once

#include "core/sandbox/BwrapCommand.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace tracepot {

struct DependencyCheck {
    std::string name;
    bool ok = false;
    bool required = true;
    std::string detail;
    std::string hint;
};

// Result of probing the host for everything an analysis needs. The probes actually start a
// throwaway sandbox (and a traced one) instead of only checking that binaries exist.
struct Readiness {
    std::filesystem::path bwrapPath;
    std::filesystem::path stracePath;
    std::filesystem::path helperPath;
    BwrapFeatures bwrap;
    std::string straceVersion;
    bool straceSeccompBpf = false;
    bool stracePidnsTranslation = false;
    bool seccompAvailable = false;
    bool sandboxFunctional = false;
    bool tracingFunctional = false;
    bool runningAsRoot = false;
    std::vector<DependencyCheck> checks;

    [[nodiscard]] bool sandboxReady() const;
    [[nodiscard]] bool tracingReady() const;
    // Human-readable summary of failed required checks (with hints).
    [[nodiscard]] std::string failureSummary(bool includeTracing) const;
};

// Locates the tracepot-limits helper: an explicit override, next to the running executable, or in
// ../libexec/tracepot relative to it.
std::filesystem::path locateLimitsHelper(const std::filesystem::path& override = {});

Readiness checkReadiness(const std::filesystem::path& helperOverride = {});

}  // namespace tracepot
