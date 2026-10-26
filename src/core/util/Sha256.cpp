#include "core/util/Sha256.hpp"

#include "core/util/FileUtil.hpp"

#include <array>
#include <cerrno>
#include <stdexcept>

#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

struct Sha256::Impl {
    EVP_MD_CTX* ctx = nullptr;
    bool finalized = false;
};

Sha256::Sha256() : impl_(std::make_unique<Impl>())
{
    impl_->ctx = EVP_MD_CTX_new();
    if (impl_->ctx == nullptr || EVP_DigestInit_ex(impl_->ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(impl_->ctx);
        throw std::runtime_error("OpenSSL SHA-256 initialization failed");
    }
}

Sha256::~Sha256()
{
    if (impl_) {
        EVP_MD_CTX_free(impl_->ctx);
    }
}

Sha256::Sha256(Sha256&&) noexcept = default;
Sha256& Sha256::operator=(Sha256&&) noexcept = default;

void Sha256::update(const void* data, std::size_t length)
{
    if (length > 0 && !impl_->finalized) {
        EVP_DigestUpdate(impl_->ctx, data, length);
    }
}

std::string Sha256::finalHex()
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (impl_->finalized || EVP_DigestFinal_ex(impl_->ctx, digest.data(), &length) != 1) {
        return {};
    }
    impl_->finalized = true;
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(length * 2);
    for (unsigned int i = 0; i < length; ++i) {
        hex.push_back(kHex[digest[i] >> 4]);
        hex.push_back(kHex[digest[i] & 0x0f]);
    }
    return hex;
}

std::string sha256Hex(std::string_view data)
{
    Sha256 hasher;
    hasher.update(data);
    return hasher.finalHex();
}

Result<std::string> sha256File(const std::filesystem::path& path)
{
    UniqueFd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!fd) {
        return makeError(ErrorCode::Io, "cannot open " + path.string() + ": " + errnoMessage(errno));
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return makeError(ErrorCode::Io, path.string() + " is not a regular file");
    }
    Sha256 hasher;
    std::array<char, 65536> buffer{};
    for (;;) {
        const ssize_t got = ::read(fd.get(), buffer.data(), buffer.size());
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "read failed for " + path.string());
        }
        if (got == 0) {
            break;
        }
        hasher.update(buffer.data(), static_cast<std::size_t>(got));
    }
    return hasher.finalHex();
}

}  // namespace tracepot
