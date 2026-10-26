#pragma once

#include <QString>

#include <filesystem>
#include <string>
#include <vector>

namespace tracepot::test {

void writeFile(const std::filesystem::path& path, const std::string& content, unsigned mode = 0644);
std::string readFile(const std::filesystem::path& path);

// Builds tar archives (optionally gzip-compressed) with arbitrary, possibly hostile, members.
class ArchiveBuilder {
public:
    enum class Kind { File, Directory, Symlink, Hardlink, CharDevice, Fifo };

    struct Member {
        Kind kind = Kind::File;
        std::string path;
        std::string content;  // file content, or link target for links
        unsigned mode = 0644;
    };

    ArchiveBuilder& file(const std::string& path, const std::string& content, unsigned mode = 0644);
    ArchiveBuilder& directory(const std::string& path, unsigned mode = 0755);
    ArchiveBuilder& symlink(const std::string& path, const std::string& target);
    ArchiveBuilder& hardlink(const std::string& path, const std::string& target);
    ArchiveBuilder& charDevice(const std::string& path);
    ArchiveBuilder& fifo(const std::string& path);

    // Writes the archive; returns false on libarchive errors.
    bool write(const std::filesystem::path& destination, bool gzip = true) const;

private:
    std::vector<Member> members_;
};

std::filesystem::path fixturesDir();
std::filesystem::path fixtureScript(const std::string& name);

}  // namespace tracepot::test
