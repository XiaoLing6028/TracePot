#include "core/archive/InputInspector.hpp"

#include "core/util/FileUtil.hpp"

#include <array>
#include <cerrno>

#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

namespace {

constexpr std::array<std::string_view, 7> kAllowedShells = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash"};

bool startsWith(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool endsWith(std::string_view text, std::string_view suffix)
{
    return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

bool looksTextual(std::string_view header)
{
    return header.find('\0') == std::string_view::npos;
}

std::string compressionName(std::string_view header)
{
    if (startsWith(header, "\x1f\x8b")) return "gzip";
    if (startsWith(header, "BZh")) return "bzip2";
    if (startsWith(header, std::string_view("\xfd" "7zXZ\0", 6))) return "xz";
    if (startsWith(header, "\x28\xb5\x2f\xfd")) return "zstd";
    if (startsWith(header, "LZIP")) return "lzip";
    return {};
}

bool hasUstarMagic(std::string_view header)
{
    return header.size() >= 262 && header.substr(257, 5) == "ustar";
}

enum class TarCheck { Tar, NotTar, Damaged };

// Uses libarchive (tar formats only) to confirm that a compressed stream really holds a tar archive.
TarCheck confirmTarArchive(const fs::path& path, std::string* detail)
{
    archive* reader = archive_read_new();
    if (reader == nullptr) {
        return TarCheck::NotTar;
    }
    archive_read_support_filter_all(reader);
    archive_read_support_format_tar(reader);
    int status = archive_read_open_filename(reader, path.c_str(), 65536);
    if (status == ARCHIVE_OK) {
        archive_entry* entry = nullptr;
        status = archive_read_next_header(reader, &entry);
    }
    TarCheck result = TarCheck::Tar;
    if (status != ARCHIVE_OK && status != ARCHIVE_WARN && status != ARCHIVE_EOF) {
        // libarchive reports "not this format" as ARCHIVE_ERRNO_FILE_FORMAT, which its private header
        // defines as EILSEQ. Anything else (truncated or corrupt compressed data) is a damaged archive.
        result = archive_errno(reader) == EILSEQ ? TarCheck::NotTar : TarCheck::Damaged;
        if (detail != nullptr && archive_error_string(reader) != nullptr) {
            *detail = archive_error_string(reader);
        }
    }
    archive_read_free(reader);
    return result;
}

}  // namespace

std::string shellInterpreterFor(std::string_view header, const std::string& fileName, std::string* rejected)
{
    if (startsWith(header, "#!")) {
        auto lineEnd = header.find('\n');
        std::string_view line = header.substr(2, lineEnd == std::string_view::npos ? std::string_view::npos : lineEnd - 2);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
            line.remove_prefix(1);
        }
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
            line.remove_suffix(1);
        }
        auto nextToken = [&line]() {
            const auto end = line.find_first_of(" \t");
            std::string_view token = line.substr(0, end);
            line = end == std::string_view::npos ? std::string_view() : line.substr(end);
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
                line.remove_prefix(1);
            }
            return token;
        };
        std::string_view program = nextToken();
        auto baseName = [](std::string_view p) {
            const auto slash = p.rfind('/');
            return slash == std::string_view::npos ? p : p.substr(slash + 1);
        };
        std::string_view name = baseName(program);
        if (name == "env") {
            std::string_view arg = nextToken();
            while (startsWith(arg, "-")) {  // e.g. "env -S bash"
                arg = nextToken();
            }
            name = baseName(arg);
        }
        for (const auto shell : kAllowedShells) {
            if (name == shell) {
                return std::string(shell);
            }
        }
        if (rejected != nullptr) {
            *rejected = std::string(name.empty() ? program : name);
        }
        return {};
    }
    if (endsWith(fileName, ".sh") && looksTextual(header)) {
        return "sh";
    }
    return {};
}

InputInfo classifyHeader(std::string_view header, const std::string& fileName)
{
    InputInfo info;
    info.kind = InputKind::Unsupported;

    if (startsWith(header, "\x7f" "ELF")) {
        const bool appImage = header.size() > 10 && header[8] == 'A' && header[9] == 'I';
        info.format = appImage ? "AppImage" : "ELF executable";
        info.reason = appImage ? "AppImage bundles are native executables; TracePot does not execute binary "
                                 "installers implicitly. Analyze them in a disposable virtual machine."
                               : "Native ELF executables are not supported; TracePot does not execute binary "
                                 "installers implicitly. Analyze them in a disposable virtual machine.";
        return info;
    }
    if (startsWith(header, "PK\x03\x04")) {
        info.format = "zip";
        info.reason = "ZIP archives are not supported in this version; only tar archives are.";
        return info;
    }
    if (startsWith(header, "\xed\xab\xee\xdb")) {
        info.format = "rpm";
        info.reason = "RPM packages are not supported; their scriptlets would require a package manager.";
        return info;
    }
    if (startsWith(header, "!<arch>\ndebian")) {
        info.format = "deb";
        info.reason = "Debian packages are not supported; their maintainer scripts would require dpkg.";
        return info;
    }
    if (startsWith(header, "7z\xbc\xaf\x27\x1c") || startsWith(header, "Rar!")) {
        info.format = "7z/rar";
        info.reason = "7z and RAR archives are not supported; only tar archives are.";
        return info;
    }
    if (const auto compression = compressionName(header); !compression.empty()) {
        info.kind = InputKind::TarArchive;
        info.format = "tar+" + compression;
        return info;
    }
    if (hasUstarMagic(header)) {
        info.kind = InputKind::TarArchive;
        info.format = "tar";
        return info;
    }
    std::string rejectedInterpreter;
    const auto shell = shellInterpreterFor(header, fileName, &rejectedInterpreter);
    if (!shell.empty()) {
        info.kind = InputKind::ShellScript;
        info.format = "shell script";
        info.interpreter = shell;
        return info;
    }
    if (!rejectedInterpreter.empty()) {
        info.format = "script";
        info.reason = "Script interpreter '" + rejectedInterpreter +
                      "' is not supported; TracePot currently executes POSIX-family shell scripts only.";
        return info;
    }
    info.format = looksTextual(header) ? "text" : "binary";
    info.reason = "Unrecognized input. Supported inputs are shell scripts (with a shell shebang or a .sh "
                  "extension) and tar archives (optionally gzip, bzip2, xz, zstd or lzip compressed).";
    return info;
}

Result<InputInfo> inspectInput(const fs::path& path)
{
    UniqueFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK));
    if (!fd) {
        return makeError(ErrorCode::InputNotFound, "cannot open input " + path.string() + ": " + errnoMessage(errno),
                         "Check that the file exists and is readable.");
    }
    struct stat st {};
    if (::fstat(fd.get(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return makeError(ErrorCode::InputRejected, path.string() + " is not a regular file");
    }
    if (static_cast<std::uint64_t>(st.st_size) > kMaxInputBytes) {
        return makeError(ErrorCode::InputRejected, "input is larger than 2 GiB");
    }
    std::array<char, 4096> buffer{};
    std::size_t total = 0;
    while (total < buffer.size()) {
        const ssize_t got = ::read(fd.get(), buffer.data() + total, buffer.size() - total);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return makeError(ErrorCode::Io, "cannot read input: " + errnoMessage(errno));
        }
        if (got == 0) {
            break;
        }
        total += static_cast<std::size_t>(got);
    }
    InputInfo info = classifyHeader(std::string_view(buffer.data(), total), path.filename().string());
    info.path = path;
    info.sizeBytes = static_cast<std::uint64_t>(st.st_size);
    if (info.kind == InputKind::TarArchive) {
        std::string detail;
        const TarCheck check = confirmTarArchive(path, &detail);
        if (check == TarCheck::NotTar) {
            info.kind = InputKind::Unsupported;
            info.reason = info.format == "tar" ? "The file looks like a tar archive but cannot be read."
                                               : "The file is " + info.format.substr(4) +
                                                     "-compressed but does not contain a tar archive.";
        } else if (check == TarCheck::Damaged) {
            info.kind = InputKind::Unsupported;
            info.malformed = true;
            info.reason = "The archive is damaged and cannot be read" + (detail.empty() ? "" : ": " + detail) + ".";
        }
    }
    if (info.kind == InputKind::ShellScript && total == 0) {
        info.kind = InputKind::Unsupported;
        info.reason = "The script is empty.";
    }
    return info;
}

}  // namespace tracepot
