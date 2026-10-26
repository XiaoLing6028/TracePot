#pragma once

#include "core/models/Result.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include <sys/types.h>

namespace tracepot {

// Owning file descriptor.
class UniqueFd {
public:
    UniqueFd() = default;
    explicit UniqueFd(int fd) : fd_(fd) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.release()) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept
    {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] int get() const { return fd_; }
    [[nodiscard]] bool valid() const { return fd_ >= 0; }
    explicit operator bool() const { return valid(); }

    int release()
    {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }
    void reset(int fd = -1);

private:
    int fd_ = -1;
};

std::string errnoMessage(int err);

// Creates a directory and missing parents with the given mode. Existing directories are accepted.
Status makeDirectories(const std::filesystem::path& path, mode_t mode = 0700);

// Writes a file without following symlinks, truncating any existing file.
Status writeFileSecure(const std::filesystem::path& path, std::string_view content, mode_t mode = 0600);

struct BoundedRead {
    std::string data;
    std::uint64_t totalSize = 0;
    bool truncated = false;
};

// Reads at most maxBytes from a regular file (symlinks are not followed).
Result<BoundedRead> readFileBounded(const std::filesystem::path& path, std::uint64_t maxBytes);

// Copies a regular file into a new destination (which must not exist) and returns its SHA-256.
Result<std::string> copyFileWithHash(const std::filesystem::path& source, const std::filesystem::path& destination,
                                     mode_t mode, std::uint64_t maxBytes);

// Recursively deletes a directory tree without following symlinks. Directories whose permissions
// were removed by analyzed code are made accessible again before deletion.
Status removeTree(const std::filesystem::path& path);

// Directory of the running executable (resolved via /proc/self/exe).
std::filesystem::path executableDirectory();

// Finds an executable in a fixed list of trusted system directories (not the caller's PATH,
// which may contain user-writable directories).
std::filesystem::path findSystemExecutable(std::string_view name);

}  // namespace tracepot
