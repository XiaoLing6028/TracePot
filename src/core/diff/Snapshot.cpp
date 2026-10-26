#include "core/diff/Snapshot.hpp"

#include "core/util/FileUtil.hpp"
#include "core/util/PathUtil.hpp"
#include "core/util/Sha256.hpp"

#include <array>
#include <cerrno>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

namespace {

FileType fileTypeFromMode(mode_t mode)
{
    if (S_ISREG(mode)) return FileType::Regular;
    if (S_ISDIR(mode)) return FileType::Directory;
    if (S_ISLNK(mode)) return FileType::Symlink;
    if (S_ISFIFO(mode)) return FileType::Fifo;
    if (S_ISSOCK(mode)) return FileType::Socket;
    if (S_ISCHR(mode)) return FileType::CharDevice;
    if (S_ISBLK(mode)) return FileType::BlockDevice;
    return FileType::Unknown;
}

std::string joinDisplay(const std::string& parent, std::string_view name)
{
    if (parent.empty() || parent == "/") {
        return "/" + std::string(name);
    }
    return parent + "/" + std::string(name);
}

std::vector<std::string> listDirectory(int dirFd)
{
    std::vector<std::string> names;
    const int dupFd = ::dup(dirFd);
    if (dupFd < 0) {
        return names;
    }
    DIR* dir = ::fdopendir(dupFd);
    if (dir == nullptr) {
        ::close(dupFd);
        return names;
    }
    while (struct dirent* entry = ::readdir(dir)) {
        const std::string_view name = entry->d_name;
        if (name != "." && name != "..") {
            names.emplace_back(name);
        }
    }
    ::closedir(dir);
    return names;
}

class Walker {
public:
    Walker(const SnapshotOptions& options, Snapshot& snapshot) : options_(options), snapshot_(snapshot) {}

    void captureRoot(const SnapshotRoot& root)
    {
        struct stat st {};
        if (::lstat(root.hostPath.c_str(), &st) != 0) {
            return;  // a missing root is not an error (e.g. an absent ~/.zshrc)
        }
        const std::string display = root.displayPath.empty() ? std::string("/") : root.displayPath;
        if (!S_ISDIR(st.st_mode)) {
            UniqueFd parent(::open(root.hostPath.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (parent) {
                record(parent.get(), root.hostPath.filename().string(), display, st);
            }
            return;
        }
        UniqueFd dirFd(::open(root.hostPath.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (!dirFd) {
            snapshot_.warnings.push_back("cannot open directory " + displaySafe(display) + ": " + errnoMessage(errno));
            return;
        }
        if (!addEntry(display, st, {})) {
            return;
        }
        walk(dirFd.get(), display, 1);
    }

private:
    bool addEntry(const std::string& display, const struct stat& st, SnapshotEntry entry)
    {
        if (snapshot_.entries.size() >= options_.limits.maxEntries) {
            if (!snapshot_.truncated) {
                snapshot_.warnings.push_back("snapshot entry limit reached; remaining entries were not captured");
            }
            snapshot_.truncated = true;
            return false;
        }
        FileMetadata& meta = entry.meta;
        meta.type = fileTypeFromMode(st.st_mode);
        meta.mode = static_cast<std::uint32_t>(st.st_mode & 07777);
        meta.uid = mapId(static_cast<std::uint32_t>(st.st_uid), options_.uidMapping);
        meta.gid = mapId(static_cast<std::uint32_t>(st.st_gid), options_.gidMapping);
        meta.size = static_cast<std::uint64_t>(st.st_size);
        meta.mtimeNs = static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
        snapshot_.entries.insert_or_assign(display, std::move(entry));
        return true;
    }

    static std::uint32_t mapId(std::uint32_t id, const std::optional<std::pair<std::uint32_t, std::uint32_t>>& map)
    {
        if (map && map->first == id) {
            return map->second;
        }
        return id;
    }

    void record(int dirFd, const std::string& name, const std::string& display, const struct stat& st)
    {
        SnapshotEntry entry;
        if (S_ISLNK(st.st_mode)) {
            std::array<char, 4097> target{};
            const ssize_t length = ::readlinkat(dirFd, name.c_str(), target.data(), target.size() - 1);
            if (length >= 0) {
                entry.meta.linkTarget = displaySafe(std::string_view(target.data(), static_cast<std::size_t>(length)));
            }
        } else if (S_ISREG(st.st_mode)) {
            hashRegular(dirFd, name, st, entry);
        }
        addEntry(display, st, std::move(entry));
    }

    void hashRegular(int dirFd, const std::string& name, const struct stat& st, SnapshotEntry& entry)
    {
        const auto size = static_cast<std::uint64_t>(st.st_size);
        const auto& limits = options_.limits;
        if (size > limits.maxHashFileBytes) {
            entry.meta.hashNote = "not hashed: file exceeds the per-file hashing limit";
            return;
        }
        if (snapshot_.bytesHashed + size > limits.maxTotalHashBytes) {
            entry.meta.hashNote = "not hashed: total hashing budget exhausted";
            return;
        }
        // O_NONBLOCK avoids hanging if the entry was swapped for a FIFO; fstat re-checks identity.
        UniqueFd fd(::openat(dirFd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK | O_CLOEXEC));
        if (!fd) {
            entry.meta.hashNote = std::string("not hashed: ") + errnoMessage(errno);
            return;
        }
        struct stat opened {};
        if (::fstat(fd.get(), &opened) != 0 || !S_ISREG(opened.st_mode) || opened.st_ino != st.st_ino ||
            opened.st_dev != st.st_dev) {
            entry.meta.hashNote = "not hashed: file changed while it was being captured";
            return;
        }
        const bool wantText = options_.captureText && size <= limits.maxTextBytes &&
                              snapshot_.textBytes + size <= limits.maxTotalTextBytes;
        std::string content;
        Sha256 hasher;
        std::array<char, 65536> buffer{};
        std::uint64_t total = 0;
        for (;;) {
            const ssize_t got = ::read(fd.get(), buffer.data(), buffer.size());
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                entry.meta.hashNote = std::string("not hashed: read error: ") + errnoMessage(errno);
                return;
            }
            if (got == 0) {
                break;
            }
            total += static_cast<std::uint64_t>(got);
            if (total > limits.maxHashFileBytes) {
                entry.meta.hashNote = "not hashed: file grew beyond the hashing limit";
                return;
            }
            hasher.update(buffer.data(), static_cast<std::size_t>(got));
            if (wantText) {
                content.append(buffer.data(), static_cast<std::size_t>(got));
            }
        }
        snapshot_.bytesHashed += total;
        entry.meta.sha256 = hasher.finalHex();
        if (wantText && content.size() <= limits.maxTextBytes && content.find('\0') == std::string::npos &&
            isValidUtf8(content)) {
            snapshot_.textBytes += content.size();
            entry.text = std::move(content);
        }
    }

    void walk(int dirFd, const std::string& display, int depth)
    {
        if (depth > options_.limits.maxDepth) {
            snapshot_.warnings.push_back("maximum directory depth reached at " + displaySafe(display));
            return;
        }
        for (const auto& name : listDirectory(dirFd)) {
            if (snapshot_.truncated) {
                return;
            }
            struct stat st {};
            if (::fstatat(dirFd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
                continue;  // removed concurrently
            }
            const std::string childDisplay = joinDisplay(display, displaySafe(name));
            if (!S_ISDIR(st.st_mode)) {
                record(dirFd, name, childDisplay, st);
                continue;
            }
            if (!addEntry(childDisplay, st, {})) {
                return;
            }
            UniqueFd child(::openat(dirFd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (!child) {
                snapshot_.warnings.push_back("directory not readable, contents not captured: " +
                                             displaySafe(childDisplay) + " (" + errnoMessage(errno) + ")");
                continue;
            }
            walk(child.get(), childDisplay, depth + 1);
        }
    }

    const SnapshotOptions& options_;
    Snapshot& snapshot_;
};

void measure(int dirFd, std::uint64_t maxEntries, TreeUsage& usage, int depth)
{
    if (depth > 256) {
        return;
    }
    for (const auto& name : listDirectory(dirFd)) {
        if (usage.entries >= maxEntries) {
            usage.truncated = true;
            return;
        }
        struct stat st {};
        if (::fstatat(dirFd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        ++usage.entries;
        usage.bytes += static_cast<std::uint64_t>(st.st_blocks) * 512;
        if (S_ISDIR(st.st_mode)) {
            UniqueFd child(::openat(dirFd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (child) {
                measure(child.get(), maxEntries, usage, depth + 1);
            }
        }
    }
}

}  // namespace

Snapshot takeSnapshot(const std::vector<SnapshotRoot>& roots, const SnapshotOptions& options)
{
    Snapshot snapshot;
    Walker walker(options, snapshot);
    for (const auto& root : roots) {
        walker.captureRoot(root);
    }
    return snapshot;
}

TreeUsage measureTree(const fs::path& root, std::uint64_t maxEntries)
{
    TreeUsage usage;
    UniqueFd dirFd(::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (dirFd) {
        measure(dirFd.get(), maxEntries, usage, 0);
    }
    return usage;
}

}  // namespace tracepot
