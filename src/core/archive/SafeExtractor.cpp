#include "core/archive/SafeExtractor.hpp"

#include "core/util/FileUtil.hpp"
#include "core/util/PathUtil.hpp"

#include <algorithm>
#include <cerrno>
#include <memory>

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

namespace {

struct ArchiveDeleter {
    void operator()(archive* a) const { archive_read_free(a); }
};
using ArchivePtr = std::unique_ptr<archive, ArchiveDeleter>;

Error unsafe(const std::string& member, const std::string& why)
{
    return makeError(ErrorCode::ArchiveUnsafe, "unsafe archive member '" + displaySafe(member) + "': " + why,
                     "TracePot rejects the whole archive instead of extracting it partially.");
}

std::vector<std::string> splitComponents(const std::string& path)
{
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto slash = path.find('/', start);
        const auto end = slash == std::string::npos ? path.size() : slash;
        if (end > start) {
            parts.push_back(path.substr(start, end - start));
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    return parts;
}

// Opens (creating as needed) the parent directory of `components` below rootFd, refusing to
// traverse symlinks or non-directories. Returns the parent fd.
Result<UniqueFd> openParent(int rootFd, const std::vector<std::string>& components, const std::string& member)
{
    UniqueFd current(::dup(rootFd));
    if (!current) {
        return makeError(ErrorCode::Io, "dup failed");
    }
    for (std::size_t i = 0; i + 1 < components.size(); ++i) {
        const std::string& name = components[i];
        UniqueFd next(::openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (!next && errno == ENOENT) {
            if (::mkdirat(current.get(), name.c_str(), 0755) != 0 && errno != EEXIST) {
                return makeError(ErrorCode::Io, "cannot create directory for " + displaySafe(member) + ": " +
                                                    errnoMessage(errno));
            }
            next.reset(::openat(current.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        }
        if (!next) {
            if (errno == ELOOP || errno == ENOTDIR) {
                return unsafe(member, "path traverses a symlink or a non-directory");
            }
            return makeError(ErrorCode::Io, "cannot open directory for " + displaySafe(member) + ": " +
                                                errnoMessage(errno));
        }
        current = std::move(next);
    }
    return current;
}

mode_t sanitizedMode(mode_t mode, bool directory)
{
    // Drop setuid/setgid/sticky and group/other write; keep the owner able to manage the tree.
    mode_t result = mode & 0755;
    result |= directory ? 0700 : 0600;
    return result;
}

Status writeAll(int fd, const void* data, std::size_t size, std::int64_t offset)
{
    const auto* bytes = static_cast<const char*>(data);
    while (size > 0) {
        const ssize_t written = ::pwrite(fd, bytes, size, offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "write failed during extraction: " + errnoMessage(errno));
        }
        bytes += written;
        size -= static_cast<std::size_t>(written);
        offset += written;
    }
    return {};
}

}  // namespace

Result<ExtractionResult> extractTarSafely(const fs::path& archivePath, const fs::path& destination,
                                          const ArchiveLimits& limits)
{
    UniqueFd rootFd(::open(destination.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!rootFd) {
        return makeError(ErrorCode::Io, "cannot open extraction directory: " + errnoMessage(errno));
    }
    UniqueFd archiveFd(::open(archivePath.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY));
    if (!archiveFd) {
        return makeError(ErrorCode::Io, "cannot open archive: " + errnoMessage(errno));
    }
    ArchivePtr reader(archive_read_new());
    if (!reader) {
        return makeError(ErrorCode::Internal, "libarchive initialization failed");
    }
    archive_read_support_filter_all(reader.get());
    archive_read_support_format_tar(reader.get());  // tar family only (ustar, pax, gnutar, v7)
    if (archive_read_open_fd(reader.get(), archiveFd.get(), 65536) != ARCHIVE_OK) {
        return makeError(ErrorCode::ArchiveMalformed,
                         std::string("cannot read archive: ") + archive_error_string(reader.get()));
    }

    ExtractionResult result;
    std::vector<char> buffer;
    for (;;) {
        archive_entry* entry = nullptr;
        const int status = archive_read_next_header(reader.get(), &entry);
        if (status == ARCHIVE_EOF) {
            break;
        }
        if (status != ARCHIVE_OK && status != ARCHIVE_WARN) {
            const char* message = archive_error_string(reader.get());
            return makeError(ErrorCode::ArchiveMalformed,
                             std::string("malformed archive: ") + (message != nullptr ? message : "unknown error"));
        }
        if (result.format.empty() && archive_format_name(reader.get()) != nullptr) {
            result.format = archive_format_name(reader.get());
        }
        if (result.entries.size() >= limits.maxEntries) {
            return makeError(ErrorCode::ArchiveLimitExceeded,
                             "archive has more than " + std::to_string(limits.maxEntries) + " entries");
        }
        const char* rawName = archive_entry_pathname(entry);
        if (rawName == nullptr) {
            return makeError(ErrorCode::ArchiveMalformed, "archive member without a usable name");
        }
        const std::string member = rawName;
        if (member.size() > limits.maxPathLength) {
            return unsafe(member.substr(0, 64) + "...", "path exceeds the maximum length");
        }
        auto normalized = normalizeArchivePath(member);
        if (!normalized) {
            if (normalized.error().code == ErrorCode::InvalidArgument) {
                continue;  // "./" root directory entry
            }
            return unsafe(member, normalized.error().message);
        }
        const std::string& relPath = normalized.value();
        const auto components = splitComponents(relPath);
        if (static_cast<int>(components.size()) > limits.maxDepth) {
            return unsafe(member, "path is nested too deeply");
        }
        const std::string& leaf = components.back();
        const std::string parentRel = relPath.size() > leaf.size() ? relPath.substr(0, relPath.size() - leaf.size() - 1)
                                                                   : std::string();

        ArchiveEntrySummary summary;
        summary.path = displaySafe(relPath);
        summary.mode = static_cast<std::uint32_t>(archive_entry_perm(entry));

        const char* hardlink = archive_entry_hardlink(entry);
        const auto fileType = archive_entry_filetype(entry);

        auto parent = openParent(rootFd.get(), components, member);
        if (!parent) {
            return parent.error();
        }
        const int parentFd = parent.value().get();

        if (hardlink != nullptr) {
            auto target = normalizeArchivePath(hardlink);
            if (!target) {
                return unsafe(member, "hard link target is unsafe: " + target.error().message);
            }
            const auto targetComponents = splitComponents(target.value());
            auto targetParent = openParent(rootFd.get(), targetComponents, member);
            if (!targetParent) {
                return targetParent.error();
            }
            struct stat st {};
            if (::fstatat(targetParent.value().get(), targetComponents.back().c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 ||
                !S_ISREG(st.st_mode)) {
                return unsafe(member, "hard link target is not a previously extracted regular file");
            }
            if (::linkat(targetParent.value().get(), targetComponents.back().c_str(), parentFd, leaf.c_str(), 0) != 0) {
                if (errno == EEXIST) {
                    return unsafe(member, "duplicate archive member");
                }
                return makeError(ErrorCode::Io, "cannot create hard link: " + errnoMessage(errno));
            }
            summary.type = FileType::Regular;
            summary.linkTarget = displaySafe(target.value());
            result.entries.push_back(std::move(summary));
            continue;
        }

        switch (fileType) {
        case AE_IFDIR: {
            if (::mkdirat(parentFd, leaf.c_str(), sanitizedMode(archive_entry_perm(entry), true)) != 0) {
                struct stat st {};
                if (errno != EEXIST || ::fstatat(parentFd, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 ||
                    !S_ISDIR(st.st_mode)) {
                    return unsafe(member, "directory conflicts with an existing member");
                }
            }
            summary.type = FileType::Directory;
            break;
        }
        case AE_IFLNK: {
            const char* target = archive_entry_symlink(entry);
            if (target == nullptr || target[0] == '\0') {
                return unsafe(member, "symlink without a target");
            }
            if (symlinkTargetEscapes(parentRel, target)) {
                return unsafe(member, std::string("symlink target escapes the extraction root: ") + displaySafe(target));
            }
            if (::symlinkat(target, parentFd, leaf.c_str()) != 0) {
                if (errno == EEXIST) {
                    return unsafe(member, "duplicate archive member");
                }
                return makeError(ErrorCode::Io, "cannot create symlink: " + errnoMessage(errno));
            }
            summary.type = FileType::Symlink;
            summary.linkTarget = displaySafe(target);
            break;
        }
        case AE_IFREG: {
            const auto declared = archive_entry_size_is_set(entry) ? archive_entry_size(entry) : 0;
            if (declared < 0 || static_cast<std::uint64_t>(declared) > limits.maxFileBytes) {
                return makeError(ErrorCode::ArchiveLimitExceeded, "archive member '" + displaySafe(member) +
                                                                      "' exceeds the per-file size limit");
            }
            UniqueFd out(::openat(parentFd, leaf.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
            if (!out) {
                if (errno == EEXIST || errno == ELOOP) {
                    return unsafe(member, "duplicate archive member or existing symlink at destination");
                }
                return makeError(ErrorCode::Io, "cannot create file: " + errnoMessage(errno));
            }
            std::uint64_t fileBytes = 0;
            for (;;) {
                const void* block = nullptr;
                std::size_t size = 0;
                la_int64_t offset = 0;
                const int dataStatus = archive_read_data_block(reader.get(), &block, &size, &offset);
                if (dataStatus == ARCHIVE_EOF) {
                    break;
                }
                if (dataStatus != ARCHIVE_OK && dataStatus != ARCHIVE_WARN) {
                    const char* message = archive_error_string(reader.get());
                    return makeError(ErrorCode::ArchiveMalformed,
                                     std::string("corrupt data: ") + (message != nullptr ? message : "unknown error"));
                }
                if (offset < 0) {
                    return makeError(ErrorCode::ArchiveMalformed, "negative data offset");
                }
                // Count the logical extent (offset + size) so sparse entries cannot bypass limits.
                const auto extent = static_cast<std::uint64_t>(offset) + size;
                fileBytes = std::max(fileBytes, extent);
                if (fileBytes > limits.maxFileBytes) {
                    return makeError(ErrorCode::ArchiveLimitExceeded, "archive member '" + displaySafe(member) +
                                                                          "' exceeds the per-file size limit");
                }
                if (result.totalBytes + size > limits.maxTotalBytes) {
                    return makeError(ErrorCode::ArchiveLimitExceeded, "archive expands beyond the total size limit");
                }
                result.totalBytes += size;
                if (auto written = writeAll(out.get(), block, size, offset); !written) {
                    return written.error();
                }
            }
            if (::ftruncate(out.get(), static_cast<off_t>(std::max<std::uint64_t>(
                                           fileBytes, static_cast<std::uint64_t>(declared)))) != 0) {
                return makeError(ErrorCode::Io, "cannot size extracted file");
            }
            ::fchmod(out.get(), sanitizedMode(archive_entry_perm(entry), false));
            summary.type = FileType::Regular;
            summary.size = fileBytes;
            break;
        }
        case AE_IFCHR:
        case AE_IFBLK:
            return unsafe(member, "device nodes are not allowed");
        case AE_IFIFO:
            return unsafe(member, "FIFOs are not allowed");
        case AE_IFSOCK:
            return unsafe(member, "sockets are not allowed");
        default:
            return unsafe(member, "unsupported member type");
        }
        result.entries.push_back(std::move(summary));
    }
    return result;
}

}  // namespace tracepot
