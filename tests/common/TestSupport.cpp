#include "common/TestSupport.hpp"

#include <fstream>
#include <memory>
#include <sstream>

#include <archive.h>
#include <archive_entry.h>
#include <sys/stat.h>

namespace tracepot::test {

void writeFile(const std::filesystem::path& path, const std::string& content, unsigned mode)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    out.close();
    ::chmod(path.c_str(), mode);
}

std::string readFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

ArchiveBuilder& ArchiveBuilder::file(const std::string& path, const std::string& content, unsigned mode)
{
    members_.push_back({Kind::File, path, content, mode});
    return *this;
}

ArchiveBuilder& ArchiveBuilder::directory(const std::string& path, unsigned mode)
{
    members_.push_back({Kind::Directory, path, {}, mode});
    return *this;
}

ArchiveBuilder& ArchiveBuilder::symlink(const std::string& path, const std::string& target)
{
    members_.push_back({Kind::Symlink, path, target, 0777});
    return *this;
}

ArchiveBuilder& ArchiveBuilder::hardlink(const std::string& path, const std::string& target)
{
    members_.push_back({Kind::Hardlink, path, target, 0644});
    return *this;
}

ArchiveBuilder& ArchiveBuilder::charDevice(const std::string& path)
{
    members_.push_back({Kind::CharDevice, path, {}, 0666});
    return *this;
}

ArchiveBuilder& ArchiveBuilder::fifo(const std::string& path)
{
    members_.push_back({Kind::Fifo, path, {}, 0644});
    return *this;
}

bool ArchiveBuilder::write(const std::filesystem::path& destination, bool gzip) const
{
    std::unique_ptr<archive, decltype(&archive_write_free)> writer(archive_write_new(), archive_write_free);
    archive_write_set_format_pax_restricted(writer.get());
    if (gzip) {
        archive_write_add_filter_gzip(writer.get());
    }
    if (archive_write_open_filename(writer.get(), destination.c_str()) != ARCHIVE_OK) {
        return false;
    }
    for (const auto& member : members_) {
        std::unique_ptr<archive_entry, decltype(&archive_entry_free)> entry(archive_entry_new(), archive_entry_free);
        archive_entry_set_pathname(entry.get(), member.path.c_str());
        archive_entry_set_perm(entry.get(), member.mode);
        archive_entry_set_mtime(entry.get(), 1700000000, 0);
        switch (member.kind) {
        case Kind::File:
            archive_entry_set_filetype(entry.get(), AE_IFREG);
            archive_entry_set_size(entry.get(), static_cast<la_int64_t>(member.content.size()));
            break;
        case Kind::Directory:
            archive_entry_set_filetype(entry.get(), AE_IFDIR);
            break;
        case Kind::Symlink:
            archive_entry_set_filetype(entry.get(), AE_IFLNK);
            archive_entry_set_symlink(entry.get(), member.content.c_str());
            break;
        case Kind::Hardlink:
            archive_entry_set_filetype(entry.get(), AE_IFREG);
            archive_entry_set_hardlink(entry.get(), member.content.c_str());
            archive_entry_set_size(entry.get(), 0);
            break;
        case Kind::CharDevice:
            archive_entry_set_filetype(entry.get(), AE_IFCHR);
            archive_entry_set_rdevmajor(entry.get(), 1);
            archive_entry_set_rdevminor(entry.get(), 3);
            break;
        case Kind::Fifo:
            archive_entry_set_filetype(entry.get(), AE_IFIFO);
            break;
        }
        if (archive_write_header(writer.get(), entry.get()) != ARCHIVE_OK) {
            return false;
        }
        if (member.kind == Kind::File && !member.content.empty()) {
            archive_write_data(writer.get(), member.content.data(), member.content.size());
        }
    }
    return archive_write_close(writer.get()) == ARCHIVE_OK;
}

std::filesystem::path fixturesDir()
{
    return std::filesystem::path(TRACEPOT_FIXTURES_DIR);
}

std::filesystem::path fixtureScript(const std::string& name)
{
    return fixturesDir() / "scripts" / name;
}

}  // namespace tracepot::test
