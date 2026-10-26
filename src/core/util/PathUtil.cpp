#include "core/util/PathUtil.hpp"

#include <cstdint>
#include <cstdlib>
#include <vector>

#include <pwd.h>
#include <unistd.h>

namespace tracepot {

namespace {

std::vector<std::string_view> splitPath(std::string_view path)
{
    std::vector<std::string_view> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto slash = path.find('/', start);
        const auto end = slash == std::string_view::npos ? path.size() : slash;
        if (end > start) {
            parts.push_back(path.substr(start, end - start));
        }
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
    return parts;
}

std::string joinParts(const std::vector<std::string_view>& parts, bool absolute)
{
    std::string result = absolute ? "/" : "";
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            result += '/';
        }
        result += parts[i];
    }
    return result;
}

std::filesystem::path absoluteEnvPath(const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] != '/') {
        return {};
    }
    return std::filesystem::path(value);
}

}  // namespace

Result<std::string> normalizeArchivePath(std::string_view path)
{
    if (path.find('\0') != std::string_view::npos) {
        return makeError(ErrorCode::ArchiveUnsafe, "archive member name contains a NUL byte");
    }
    if (!path.empty() && path.front() == '/') {
        return makeError(ErrorCode::ArchiveUnsafe, "archive member uses an absolute path: " + std::string(path));
    }
    std::vector<std::string_view> kept;
    for (const auto part : splitPath(path)) {
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            return makeError(ErrorCode::ArchiveUnsafe,
                             "archive member contains a parent-directory component: " + std::string(path));
        }
        kept.push_back(part);
    }
    if (kept.empty()) {
        return makeError(ErrorCode::InvalidArgument, "archive member refers to the archive root");
    }
    return joinParts(kept, false);
}

std::string normalizeAbsolute(std::string_view path)
{
    std::vector<std::string_view> kept;
    for (const auto part : splitPath(path)) {
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            if (!kept.empty()) {
                kept.pop_back();
            }
            continue;
        }
        kept.push_back(part);
    }
    return joinParts(kept, true);
}

std::string resolveAgainst(std::string_view base, std::string_view path)
{
    if (!path.empty() && path.front() == '/') {
        return normalizeAbsolute(path);
    }
    std::string combined(base);
    combined += '/';
    combined += path;
    return normalizeAbsolute(combined);
}

bool symlinkTargetEscapes(std::string_view linkDir, std::string_view target)
{
    if (target.empty() || target.front() == '/') {
        return true;
    }
    long depth = static_cast<long>(splitPath(linkDir).size());
    for (const auto part : splitPath(target)) {
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            if (--depth < 0) {
                return true;
            }
        } else {
            ++depth;
        }
    }
    return false;
}

bool isValidUtf8(std::string_view text)
{
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        std::size_t extra = 0;
        std::uint32_t codepoint = 0;
        if (c < 0x80) {
            ++i;
            continue;
        }
        if ((c & 0xe0) == 0xc0) {
            extra = 1;
            codepoint = c & 0x1f;
        } else if ((c & 0xf0) == 0xe0) {
            extra = 2;
            codepoint = c & 0x0f;
        } else if ((c & 0xf8) == 0xf0) {
            extra = 3;
            codepoint = c & 0x07;
        } else {
            return false;
        }
        if (i + extra >= text.size()) {
            return false;  // truncated sequence
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cc = static_cast<unsigned char>(text[i + k]);
            if ((cc & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (cc & 0x3f);
        }
        // Reject overlong encodings, surrogates and out-of-range code points.
        if ((extra == 1 && codepoint < 0x80) || (extra == 2 && codepoint < 0x800) ||
            (extra == 3 && codepoint < 0x10000) || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

namespace {

std::string sanitizeForDisplay(std::string_view bytes, bool keepLayout)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size());
    std::size_t i = 0;
    auto escapeByte = [&out](unsigned char c) {
        out += "\\x";
        out += kHex[c >> 4];
        out += kHex[c & 0x0f];
    };
    while (i < bytes.size()) {
        const auto c = static_cast<unsigned char>(bytes[i]);
        if (c < 0x80) {
            if (keepLayout && (c == '\n' || c == '\t')) {
                out += static_cast<char>(c);
                ++i;
                continue;
            }
            switch (c) {
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    escapeByte(c);
                } else {
                    out += static_cast<char>(c);
                }
            }
            ++i;
            continue;
        }
        std::size_t length = 0;
        if ((c & 0xe0) == 0xc0) {
            length = 2;
        } else if ((c & 0xf0) == 0xe0) {
            length = 3;
        } else if ((c & 0xf8) == 0xf0) {
            length = 4;
        }
        if (length > 0 && i + length <= bytes.size() && isValidUtf8(bytes.substr(i, length))) {
            out.append(bytes.substr(i, length));
            i += length;
        } else {
            escapeByte(c);
            ++i;
        }
    }
    return out;
}

}  // namespace

std::string displaySafe(std::string_view bytes)
{
    return sanitizeForDisplay(bytes, false);
}

std::string displaySafeMultiline(std::string_view bytes)
{
    return sanitizeForDisplay(bytes, true);
}

std::string sandboxArea(std::string_view path)
{
    auto under = [path](std::string_view prefix) {
        return path == prefix || (path.size() > prefix.size() && path.substr(0, prefix.size()) == prefix &&
                                  path[prefix.size()] == '/');
    };
    if (under("/home") || under("/root")) {
        return "home";
    }
    if (under("/etc")) {
        return "system-config";
    }
    if (under("/tmp") || under("/var/tmp") || under("/dev/shm")) {
        return "temporary";
    }
    if (under("/run")) {
        return "runtime";
    }
    if (under("/work")) {
        return "work";
    }
    if (under("/opt") || under("/usr") || under("/var") || under("/srv")) {
        return "system-data";
    }
    return "other";
}

std::filesystem::path hostHomeDirectory()
{
    if (auto home = absoluteEnvPath("HOME"); !home.empty()) {
        return home;
    }
    if (const passwd* pw = ::getpwuid(::getuid()); pw != nullptr && pw->pw_dir != nullptr) {
        return std::filesystem::path(pw->pw_dir);
    }
    return {};
}

std::filesystem::path xdgCacheHome()
{
    if (auto path = absoluteEnvPath("XDG_CACHE_HOME"); !path.empty()) {
        return path;
    }
    const auto home = hostHomeDirectory();
    return home.empty() ? std::filesystem::path("/tmp") : home / ".cache";
}

std::filesystem::path xdgConfigHome()
{
    if (auto path = absoluteEnvPath("XDG_CONFIG_HOME"); !path.empty()) {
        return path;
    }
    const auto home = hostHomeDirectory();
    return home.empty() ? std::filesystem::path("/tmp") : home / ".config";
}

std::filesystem::path tracepotCacheDir()
{
    return xdgCacheHome() / "tracepot";
}

std::filesystem::path tracepotConfigDir()
{
    return xdgConfigHome() / "tracepot";
}

}  // namespace tracepot
