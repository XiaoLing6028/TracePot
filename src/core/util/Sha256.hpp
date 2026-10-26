#pragma once

#include "core/models/Result.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace tracepot {

// Incremental SHA-256 backed by OpenSSL's EVP interface.
class Sha256 {
public:
    Sha256();
    ~Sha256();
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    Sha256(Sha256&&) noexcept;
    Sha256& operator=(Sha256&&) noexcept;

    void update(const void* data, std::size_t length);
    void update(std::string_view data) { update(data.data(), data.size()); }

    // Returns the lowercase hex digest. The object must not be updated afterwards.
    std::string finalHex();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

std::string sha256Hex(std::string_view data);

// Hashes a regular file without following symlinks.
Result<std::string> sha256File(const std::filesystem::path& path);

}  // namespace tracepot
