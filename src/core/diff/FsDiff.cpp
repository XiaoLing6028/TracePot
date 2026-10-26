#include "core/diff/FsDiff.hpp"

#include "core/diff/TextDiff.hpp"
#include "core/util/PathUtil.hpp"

namespace tracepot {

namespace {

void attachTextDiff(FileChange& change, const SnapshotEntry* before, const SnapshotEntry* after,
                    const DiffOptions& options)
{
    if (!options.includeTextDiffs) {
        return;
    }
    const bool beforeText = before == nullptr || before->text.has_value();
    const bool afterText = after == nullptr || after->text.has_value();
    if (!beforeText || !afterText) {
        return;
    }
    const std::string empty;
    const std::string& a = before != nullptr ? *before->text : empty;
    const std::string& b = after != nullptr ? *after->text : empty;
    auto diff = unifiedDiff(a, b, before != nullptr ? "a" + change.path : std::string("/dev/null"),
                            after != nullptr ? "b" + change.path : std::string("/dev/null"), 3,
                            options.maxTextDiffBytes);
    if (!diff.diff.empty()) {
        change.textDiff = std::move(diff.diff);
        change.textDiffTruncated = diff.truncated;
    }
}

FileChange makeChange(const std::string& path, ChangeKind kind)
{
    FileChange change;
    change.path = path;
    change.kind = kind;
    change.area = sandboxArea(path);
    return change;
}

std::optional<FileChange> compareEntries(const std::string& path, const SnapshotEntry& before,
                                         const SnapshotEntry& after, const DiffOptions& options)
{
    const FileMetadata& a = before.meta;
    const FileMetadata& b = after.meta;
    FileChange change = makeChange(path, ChangeKind::Modified);
    auto& aspects = change.aspects;

    if (a.type != b.type) {
        aspects.emplace_back("type");
    } else {
        if (a.type == FileType::Regular) {
            if (a.sha256 && b.sha256) {
                if (*a.sha256 != *b.sha256) {
                    aspects.emplace_back("content");
                }
            } else if (a.size != b.size || a.mtimeNs != b.mtimeNs) {
                aspects.emplace_back("content");
                change.notes.emplace_back("content compared by size and modification time only (hash unavailable)");
            }
            if (a.size != b.size) {
                aspects.emplace_back("size");
            }
        }
        if (a.type == FileType::Symlink && a.linkTarget != b.linkTarget) {
            aspects.emplace_back("link-target");
        }
    }
    if (a.mode != b.mode) {
        aspects.emplace_back("permissions");
    }
    if (a.uid != b.uid || a.gid != b.gid) {
        aspects.emplace_back("ownership");
    }
    if (aspects.empty() && a.type != FileType::Directory && a.mtimeNs != b.mtimeNs) {
        aspects.emplace_back("timestamps");
    }
    if (aspects.empty()) {
        return std::nullopt;
    }
    change.before = a;
    change.after = b;
    if (a.type == FileType::Regular && b.type == FileType::Regular) {
        for (const auto& aspect : aspects) {
            if (aspect == "content") {
                attachTextDiff(change, &before, &after, options);
                break;
            }
        }
    }
    return change;
}

}  // namespace

std::vector<FileChange> diffSnapshots(const Snapshot& before, const Snapshot& after, const DiffOptions& options)
{
    std::vector<FileChange> changes;
    auto itBefore = before.entries.begin();
    auto itAfter = after.entries.begin();
    while (itBefore != before.entries.end() || itAfter != after.entries.end()) {
        if (itAfter == after.entries.end() ||
            (itBefore != before.entries.end() && itBefore->first < itAfter->first)) {
            if (!after.truncated) {  // with a truncated "after" snapshot, absence proves nothing
                FileChange change = makeChange(itBefore->first, ChangeKind::Deleted);
                change.before = itBefore->second.meta;
                if (itBefore->second.meta.type == FileType::Regular) {
                    attachTextDiff(change, &itBefore->second, nullptr, options);
                }
                changes.push_back(std::move(change));
            }
            ++itBefore;
        } else if (itBefore == before.entries.end() || itAfter->first < itBefore->first) {
            FileChange change = makeChange(itAfter->first, ChangeKind::Created);
            change.after = itAfter->second.meta;
            if (itAfter->second.meta.type == FileType::Regular) {
                attachTextDiff(change, nullptr, &itAfter->second, options);
            }
            changes.push_back(std::move(change));
            ++itAfter;
        } else {
            if (auto change = compareEntries(itAfter->first, itBefore->second, itAfter->second, options)) {
                changes.push_back(std::move(*change));
            }
            ++itBefore;
            ++itAfter;
        }
    }
    return changes;
}

}  // namespace tracepot
