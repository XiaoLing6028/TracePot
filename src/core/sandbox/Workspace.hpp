#pragma once

#include "core/models/Result.hpp"
#include "core/models/Types.hpp"
#include "core/util/FileUtil.hpp"

#include <filesystem>
#include <string>

namespace tracepot {

struct WorkspacePaths {
    std::filesystem::path runDir;     // <base>/<analysis id>, mode 0700
    std::filesystem::path rootDir;    // runDir/root: the sandbox's writable tree
    std::filesystem::path inputDir;   // runDir/input: pristine input copy (not visible in the sandbox)
    std::filesystem::path traceLog;   // runDir/trace/strace.log (not visible in the sandbox)
    std::filesystem::path stdoutLog;  // runDir/output/stdout.log
    std::filesystem::path stderrLog;  // runDir/output/stderr.log
};

// Private per-analysis directory tree. Removed on destruction unless keep() was requested.
// While a workspace exists, its owner holds an exclusive flock on <runDir>/.lock; a workspace
// whose lock is free belongs to an analysis that ended abnormally (e.g. TracePot was killed).
class Workspace {
public:
    static Result<Workspace> create(const std::filesystem::path& base, const std::string& analysisId);

    // Removes workspaces in `base` left behind by analyses that were killed (unlocked, not marked
    // as kept). Returns the number of removed workspaces.
    static std::size_t removeStale(const std::filesystem::path& base);

    Workspace(Workspace&& other) noexcept;
    Workspace& operator=(Workspace&& other) noexcept;
    Workspace(const Workspace&) = delete;
    Workspace& operator=(const Workspace&) = delete;
    ~Workspace();

    [[nodiscard]] const WorkspacePaths& paths() const { return paths_; }

    // Creates the sandbox filesystem skeleton: standard directories, a curated subset of the host's
    // /etc (world-readable, non-secret files only), synthesized passwd/group/hosts/hostname/
    // machine-id, and home directories populated from /etc/skel.
    Status populateSandboxRoot(SandboxUser user);

    // Kept workspaces are marked on disk so stale-workspace cleanup leaves them alone.
    void setKeep(bool keep);
    [[nodiscard]] bool kept() const { return keep_; }
    Status remove();

private:
    explicit Workspace(WorkspacePaths paths) : paths_(std::move(paths)) {}

    WorkspacePaths paths_;
    UniqueFd lock_;
    bool keep_ = false;
    bool removed_ = false;
};

}  // namespace tracepot
