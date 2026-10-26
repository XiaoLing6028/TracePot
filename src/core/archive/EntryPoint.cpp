#include "core/archive/EntryPoint.hpp"

#include "core/archive/InputInspector.hpp"
#include "core/util/FileUtil.hpp"
#include "core/util/PathUtil.hpp"

#include <algorithm>
#include <array>
#include <set>

namespace tracepot {

namespace {

constexpr std::array<std::string_view, 4> kCandidateNames = {"install.sh", "setup.sh", "installer.sh", "install"};

Result<std::string> interpreterFor(const std::filesystem::path& file, const std::string& name)
{
    auto head = readFileBounded(file, 4096);
    if (!head) {
        return head.error();
    }
    const std::string& data = head.value().data;
    std::string rejected;
    auto shell = shellInterpreterFor(data, name, &rejected);
    if (!shell.empty()) {
        return shell;
    }
    if (!rejected.empty()) {
        return makeError(ErrorCode::UnsupportedInput,
                         "entry point uses unsupported interpreter '" + rejected + "'",
                         "TracePot executes POSIX-family shell scripts only.");
    }
    if (data.find('\0') != std::string::npos || data.substr(0, 4) == "\x7f" "ELF") {
        return makeError(ErrorCode::UnsupportedInput, "entry point is not a shell script",
                         "Binary entry points are not executed implicitly.");
    }
    return std::string("sh");  // text without a shebang is run by /bin/sh, like the kernel's fallback
}

}  // namespace

Result<EntryPoint> resolveEntryPoint(const ExtractionResult& extraction, const std::filesystem::path& extractedRoot,
                                     const std::string& requested)
{
    auto isRegularMember = [&extraction](const std::string& path) {
        return std::any_of(extraction.entries.begin(), extraction.entries.end(), [&](const ArchiveEntrySummary& e) {
            return e.path == path && e.type == FileType::Regular && e.linkTarget.empty();
        });
    };

    std::string chosen;
    if (!requested.empty()) {
        auto normalized = normalizeArchivePath(requested);
        if (!normalized) {
            return makeError(ErrorCode::EntryPointNotFound, "invalid entry point: " + normalized.error().message);
        }
        if (!isRegularMember(normalized.value())) {
            return makeError(ErrorCode::EntryPointNotFound,
                             "entry point '" + displaySafe(requested) + "' is not a regular file in the archive");
        }
        chosen = normalized.value();
    } else {
        std::set<std::string> topLevel;
        for (const auto& entry : extraction.entries) {
            topLevel.insert(entry.path.substr(0, entry.path.find('/')));
        }
        std::vector<std::string> prefixes = {""};
        if (topLevel.size() == 1) {
            prefixes.push_back(*topLevel.begin() + "/");
        }
        std::vector<std::string> candidates;
        for (const auto& prefix : prefixes) {
            for (const auto name : kCandidateNames) {
                const std::string path = prefix + std::string(name);
                if (isRegularMember(path)) {
                    candidates.push_back(path);
                }
            }
        }
        if (candidates.empty()) {
            return makeError(ErrorCode::EntryPointNotFound, "no installer script found in the archive",
                             "Specify the script to run with --entry <path-in-archive>.");
        }
        if (candidates.size() > 1) {
            std::string list;
            for (const auto& c : candidates) {
                list += (list.empty() ? "" : ", ") + c;
            }
            return makeError(ErrorCode::EntryPointNotFound, "several possible installer scripts found: " + list,
                             "Choose one with --entry <path-in-archive>.");
        }
        chosen = candidates.front();
    }
    const auto name = chosen.substr(chosen.rfind('/') == std::string::npos ? 0 : chosen.rfind('/') + 1);
    auto interpreter = interpreterFor(extractedRoot / chosen, name);
    if (!interpreter) {
        return interpreter.error();
    }
    return EntryPoint{chosen, interpreter.value()};
}

}  // namespace tracepot
