#include "core/util/FileUtil.hpp"

#include "core/util/Sha256.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

void UniqueFd::reset(int fd)
{
    if (fd_ >= 0) {
        ::close(fd_);
    }
    fd_ = fd;
}

std::string errnoMessage(int err)
{
    return std::strerror(err);
}

Status makeDirectories(const fs::path& path, mode_t mode)
{
    if (path.empty()) {
        return makeError(ErrorCode::InvalidArgument, "empty directory path");
    }
    fs::path current;
    for (const auto& part : path) {
        current /= part;
        if (current == current.root_path()) {
            continue;
        }
        if (::mkdir(current.c_str(), mode) == 0) {
            continue;
        }
        if (errno != EEXIST) {
            return makeError(ErrorCode::Io, "cannot create directory " + current.string() + ": " + errnoMessage(errno));
        }
        struct stat st {};
        if (::lstat(current.c_str(), &st) != 0) {
            return makeError(ErrorCode::Io, "cannot inspect " + current.string() + ": " + errnoMessage(errno));
        }
        // A symlinked parent is acceptable only for components that pre-exist outside our control
        // (e.g. /home -> /var/home on Fedora Silverblue); stat() resolves it.
        if (!S_ISDIR(st.st_mode)) {
            struct stat resolved {};
            if (::stat(current.c_str(), &resolved) != 0 || !S_ISDIR(resolved.st_mode)) {
                return makeError(ErrorCode::Io, current.string() + " exists and is not a directory");
            }
        }
    }
    return {};
}

Status writeFileSecure(const fs::path& path, std::string_view content, mode_t mode)
{
    UniqueFd fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, mode));
    if (!fd) {
        return makeError(ErrorCode::Io, "cannot write " + path.string() + ": " + errnoMessage(errno));
    }
    const char* data = content.data();
    std::size_t remaining = content.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd.get(), data, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "write failed for " + path.string() + ": " + errnoMessage(errno));
        }
        data += written;
        remaining -= static_cast<std::size_t>(written);
    }
    if (::fchmod(fd.get(), mode) != 0) {
        return makeError(ErrorCode::Io, "cannot set permissions on " + path.string());
    }
    return {};
}

Result<BoundedRead> readFileBounded(const fs::path& path, std::uint64_t maxBytes)
{
    UniqueFd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!fd) {
        return makeError(ErrorCode::Io, "cannot open " + path.string() + ": " + errnoMessage(errno));
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return makeError(ErrorCode::Io, path.string() + " is not a regular file");
    }
    BoundedRead result;
    result.totalSize = static_cast<std::uint64_t>(st.st_size);
    std::array<char, 65536> buffer{};
    while (result.data.size() < maxBytes) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), maxBytes - result.data.size()));
        const ssize_t got = ::read(fd.get(), buffer.data(), want);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "read failed for " + path.string() + ": " + errnoMessage(errno));
        }
        if (got == 0) {
            break;
        }
        result.data.append(buffer.data(), static_cast<std::size_t>(got));
    }
    result.truncated = result.totalSize > result.data.size();
    return result;
}

Result<std::string> copyFileWithHash(const fs::path& source, const fs::path& destination, mode_t mode,
                                     std::uint64_t maxBytes)
{
    // The user explicitly selected the source, so following a symlink to it is acceptable;
    // it must resolve to a regular file.
    UniqueFd in(::open(source.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!in) {
        return makeError(ErrorCode::InputNotFound, "cannot open " + source.string() + ": " + errnoMessage(errno));
    }
    struct stat st {};
    if (::fstat(in.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return makeError(ErrorCode::InputRejected, source.string() + " is not a regular file");
    }
    if (static_cast<std::uint64_t>(st.st_size) > maxBytes) {
        return makeError(ErrorCode::InputRejected, "input is larger than the configured limit");
    }
    UniqueFd out(::open(destination.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!out) {
        return makeError(ErrorCode::Io, "cannot create " + destination.string() + ": " + errnoMessage(errno));
    }
    Sha256 hasher;
    std::array<char, 65536> buffer{};
    std::uint64_t copied = 0;
    for (;;) {
        const ssize_t got = ::read(in.get(), buffer.data(), buffer.size());
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "read failed for " + source.string() + ": " + errnoMessage(errno));
        }
        if (got == 0) {
            break;
        }
        copied += static_cast<std::uint64_t>(got);
        if (copied > maxBytes) {
            return makeError(ErrorCode::InputRejected, "input grew beyond the configured limit while copying");
        }
        hasher.update(buffer.data(), static_cast<std::size_t>(got));
        const char* data = buffer.data();
        auto remaining = static_cast<std::size_t>(got);
        while (remaining > 0) {
            const ssize_t written = ::write(out.get(), data, remaining);
            if (written < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return makeError(ErrorCode::Io, "write failed for " + destination.string());
            }
            data += written;
            remaining -= static_cast<std::size_t>(written);
        }
    }
    if (::fchmod(out.get(), mode) != 0) {
        return makeError(ErrorCode::Io, "cannot set permissions on " + destination.string());
    }
    return hasher.finalHex();
}

namespace {

// Directories deeper than this are moved to the top of the tree before being emptied, so the
// number of simultaneously open descriptors stays bounded however deep the tree is.
constexpr int kMaxRemovalDepth = 32;

struct RemovalState {
    int rootFd = -1;
    std::vector<std::string> deferred;  // top-level names of relocated deep subtrees
    unsigned counter = 0;
    std::string firstError;
    bool ok = true;

    void fail(const std::string& what)
    {
        ok = false;
        if (firstError.empty()) {
            firstError = what;
        }
    }
};

// Removes the contents of dirFd (an open directory) recursively. Never follows symlinks:
// entries are opened relative to their parent with O_NOFOLLOW.
void removeContents(int dirFd, int depth, RemovalState& state)
{
    const int dupFd = ::dup(dirFd);
    if (dupFd < 0) {
        state.fail(errnoMessage(errno));
        return;
    }
    DIR* dir = ::fdopendir(dupFd);
    if (dir == nullptr) {
        ::close(dupFd);
        state.fail(errnoMessage(errno));
        return;
    }
    std::vector<std::string> names;
    while (struct dirent* entry = ::readdir(dir)) {
        const std::string_view name = entry->d_name;
        if (name != "." && name != "..") {
            names.emplace_back(name);
        }
    }
    ::closedir(dir);

    for (const auto& name : names) {
        struct stat st {};
        if (::fstatat(dirFd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            continue;
        }
        if (!S_ISDIR(st.st_mode)) {
            if (::unlinkat(dirFd, name.c_str(), 0) != 0 && errno != ENOENT) {
                state.fail(name + ": " + errnoMessage(errno));
            }
            continue;
        }
        // Restore owner access in case the analyzed code removed it.
        ::fchmodat(dirFd, name.c_str(), 0700, 0);
        if (depth >= kMaxRemovalDepth) {
            const std::string moved = ".tracepot-deep-" + std::to_string(state.counter++);
            if (::renameat(dirFd, name.c_str(), state.rootFd, moved.c_str()) == 0) {
                state.deferred.push_back(moved);
            } else {
                state.fail(name + ": " + errnoMessage(errno));
            }
            continue;
        }
        UniqueFd child(::openat(dirFd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (child) {
            removeContents(child.get(), depth + 1, state);
        }
        if (::unlinkat(dirFd, name.c_str(), AT_REMOVEDIR) != 0 && errno != ENOENT) {
            state.fail(name + ": " + errnoMessage(errno));
        }
    }
}

}  // namespace

Status removeTree(const fs::path& path)
{
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) {
        return errno == ENOENT ? Status{} : Status{makeError(ErrorCode::Io, "cannot inspect " + path.string())};
    }
    if (!S_ISDIR(st.st_mode)) {
        if (::unlink(path.c_str()) != 0) {
            return makeError(ErrorCode::Io, "cannot remove " + path.string() + ": " + errnoMessage(errno));
        }
        return {};
    }
    ::chmod(path.c_str(), 0700);
    UniqueFd dirFd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!dirFd) {
        return makeError(ErrorCode::Io, "cannot open " + path.string() + ": " + errnoMessage(errno));
    }
    RemovalState state;
    state.rootFd = dirFd.get();
    removeContents(dirFd.get(), 0, state);
    // Relocated deep subtrees are now shallow; each pass shortens the remaining depth.
    while (!state.deferred.empty()) {
        const std::string name = state.deferred.back();
        state.deferred.pop_back();
        UniqueFd child(::openat(dirFd.get(), name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (child) {
            removeContents(child.get(), 1, state);
        }
        if (::unlinkat(dirFd.get(), name.c_str(), AT_REMOVEDIR) != 0 && errno != ENOENT) {
            state.fail(name + ": " + errnoMessage(errno));
        }
    }
    dirFd.reset();
    if (::rmdir(path.c_str()) != 0 || !state.ok) {
        return makeError(ErrorCode::Io, "cannot completely remove " + path.string() +
                                            (state.firstError.empty() ? std::string() : ": " + state.firstError));
    }
    return {};
}

fs::path executableDirectory()
{
    std::error_code ec;
    const auto exe = fs::read_symlink("/proc/self/exe", ec);
    if (ec) {
        return {};
    }
    return exe.parent_path();
}

fs::path findSystemExecutable(std::string_view name)
{
    static constexpr std::array<std::string_view, 6> kDirs = {"/usr/bin", "/bin", "/usr/sbin",
                                                             "/sbin", "/usr/local/bin", "/usr/local/sbin"};
    for (const auto dir : kDirs) {
        fs::path candidate = fs::path(dir) / fs::path(name);
        if (::access(candidate.c_str(), X_OK) == 0) {
            struct stat st {};
            if (::stat(candidate.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
                return candidate;
            }
        }
    }
    return {};
}

}  // namespace tracepot
