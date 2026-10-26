#include "core/sandbox/Workspace.hpp"

#include "core/sandbox/BwrapCommand.hpp"
#include "core/util/FileUtil.hpp"

#include <array>
#include <cerrno>
#include <cstdint>

#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

namespace tracepot {

namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t kMaxCopiedFileBytes = 1024ULL * 1024;

// Host /etc entries copied into the sandbox. Only world-readable regular files (and symlinks,
// copied as links) are taken, so files that hold secrets (shadow, sudoers, private keys, ...) are
// never copied even when TracePot runs as root. Package-manager and /etc/environment files are
// deliberately excluded because they can carry proxy or repository credentials while still being
// world-readable.
constexpr std::array<std::string_view, 29> kEtcEntries = {
    "os-release", "lsb-release", "debian_version", "fedora-release", "redhat-release", "system-release",
    "system-release-cpe", "issue", "ld.so.cache", "ld.so.conf", "ld.so.conf.d", "nsswitch.conf", "host.conf",
    "gai.conf", "localtime", "timezone", "shells", "profile", "profile.d", "bash.bashrc", "bashrc", "inputrc",
    "login.defs", "alternatives", "skel", "zsh", "mime.types", "protocols", "services",
};

// Empty directories commonly targeted by installers; created so writes there can succeed
// (simulated-root mode) and be observed.
constexpr std::array<std::string_view, 21> kEtcDirectories = {
    "systemd/system", "systemd/user", "xdg/autostart", "cron.d", "cron.hourly", "cron.daily", "cron.weekly",
    "cron.monthly", "init.d", "sudoers.d", "profile.d", "modules-load.d", "modprobe.d", "udev/rules.d",
    "ld.so.conf.d", "pam.d", "environment.d", "apt/sources.list.d", "apt/trusted.gpg.d", "apt/keyrings",
    "yum.repos.d",
};

void copyHostEntry(const fs::path& source, const fs::path& destination, int depth)
{
    struct stat st {};
    if (::lstat(source.c_str(), &st) != 0 || depth > 4) {
        return;
    }
    if (S_ISLNK(st.st_mode)) {
        std::error_code ec;
        const auto target = fs::read_symlink(source, ec);
        // Best effort: a link that cannot be copied is simply absent from the sandbox's /etc.
        if (!ec && ::symlink(target.c_str(), destination.c_str()) != 0) {
            return;
        }
        return;
    }
    if (S_ISREG(st.st_mode)) {
        if ((st.st_mode & S_IROTH) == 0 || static_cast<std::uint64_t>(st.st_size) > kMaxCopiedFileBytes) {
            return;
        }
        auto content = readFileBounded(source, kMaxCopiedFileBytes);
        if (content) {
            (void)writeFileSecure(destination, content.value().data, 0644);
        }
        return;
    }
    if (S_ISDIR(st.st_mode) && (st.st_mode & S_IROTH) != 0) {
        if (::mkdir(destination.c_str(), 0755) != 0 && errno != EEXIST) {
            return;
        }
        std::error_code ec;
        for (const auto& entry : fs::directory_iterator(source, fs::directory_options::skip_permission_denied, ec)) {
            copyHostEntry(entry.path(), destination / entry.path().filename(), depth + 1);
        }
    }
}

std::string randomHex(std::size_t bytes)
{
    std::string data(bytes, '\0');
    if (::getrandom(data.data(), data.size(), 0) != static_cast<ssize_t>(data.size())) {
        data.assign(bytes, '\x5a');
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    for (const char c : data) {
        const auto byte = static_cast<unsigned char>(c);
        hex += kHex[byte >> 4];
        hex += kHex[byte & 0x0f];
    }
    return hex;
}

Status ensureFile(const fs::path& path, std::string_view content)
{
    struct stat st {};
    if (::lstat(path.c_str(), &st) == 0) {
        return {};
    }
    return writeFileSecure(path, content, 0644);
}

Status populateHome(const fs::path& home)
{
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/etc/skel", fs::directory_options::skip_permission_denied, ec)) {
        copyHostEntry(entry.path(), home / entry.path().filename(), 1);
    }
    if (auto s = ensureFile(home / ".profile", "# ~/.profile (TracePot sandbox skeleton)\n"); !s) {
        return s;
    }
    if (auto s = ensureFile(home / ".bashrc", "# ~/.bashrc (TracePot sandbox skeleton)\n"); !s) {
        return s;
    }
    for (const auto* dir : {".config", ".local", ".local/share", ".local/bin", ".cache"}) {
        if (auto s = makeDirectories(home / dir, 0755); !s) {
            return s;
        }
    }
    return {};
}

}  // namespace

Result<Workspace> Workspace::create(const fs::path& base, const std::string& analysisId)
{
    if (analysisId.empty() || analysisId.find('/') != std::string::npos || analysisId.front() == '.') {
        return makeError(ErrorCode::InvalidArgument, "invalid analysis identifier");
    }
    if (auto s = makeDirectories(base, 0700); !s) {
        return s.error();
    }
    WorkspacePaths paths;
    paths.runDir = base / analysisId;
    // mkdir (not mkdir -p) so an existing directory — or a planted symlink — is an error.
    if (::mkdir(paths.runDir.c_str(), 0700) != 0) {
        return makeError(ErrorCode::Io, "cannot create workspace " + paths.runDir.string() + ": " + errnoMessage(errno));
    }
    ::chmod(paths.runDir.c_str(), 0700);
    // The lock is taken under a temporary name and then renamed into place, so stale-workspace
    // cleanup in another process can never observe an unlocked ".lock" for a live workspace.
    const fs::path pendingLock = paths.runDir / ".lock.pending";
    UniqueFd lock(::open(pendingLock.c_str(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
    if (!lock || ::flock(lock.get(), LOCK_EX | LOCK_NB) != 0 ||
        ::rename(pendingLock.c_str(), (paths.runDir / ".lock").c_str()) != 0) {
        const int err = errno;
        (void)removeTree(paths.runDir);
        return makeError(ErrorCode::Io, "cannot lock workspace " + paths.runDir.string() + ": " + errnoMessage(err));
    }
    paths.rootDir = paths.runDir / "root";
    paths.inputDir = paths.runDir / "input";
    paths.traceLog = paths.runDir / "trace" / "strace.log";
    paths.stdoutLog = paths.runDir / "output" / "stdout.log";
    paths.stderrLog = paths.runDir / "output" / "stderr.log";
    Workspace workspace(paths);
    workspace.lock_ = std::move(lock);
    for (const auto& dir : {paths.rootDir, paths.inputDir, paths.runDir / "trace", paths.runDir / "output"}) {
        if (::mkdir(dir.c_str(), 0700) != 0) {
            return makeError(ErrorCode::Io, "cannot create " + dir.string() + ": " + errnoMessage(errno));
        }
    }
    return workspace;
}

Workspace::Workspace(Workspace&& other) noexcept
    : paths_(std::move(other.paths_)), lock_(std::move(other.lock_)), keep_(other.keep_), removed_(other.removed_)
{
    other.removed_ = true;
}

Workspace& Workspace::operator=(Workspace&& other) noexcept
{
    if (this != &other) {
        if (!keep_ && !removed_) {
            (void)remove();
        }
        paths_ = std::move(other.paths_);
        lock_ = std::move(other.lock_);
        keep_ = other.keep_;
        removed_ = other.removed_;
        other.removed_ = true;
    }
    return *this;
}

Workspace::~Workspace()
{
    if (!keep_ && !removed_) {
        (void)remove();
    }
}

void Workspace::setKeep(bool keep)
{
    keep_ = keep;
    const auto marker = paths_.runDir / ".keep";
    if (keep) {
        (void)writeFileSecure(marker, "kept by request\n", 0600);
    } else {
        ::unlink(marker.c_str());
    }
}

std::size_t Workspace::removeStale(const fs::path& base)
{
    std::size_t removed = 0;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(base, ec)) {
        const std::string name = entry.path().filename().string();
        if (name.rfind("tracepot-", 0) != 0 || !entry.is_directory(ec) || entry.is_symlink(ec)) {
            continue;
        }
        if (fs::exists(entry.path() / ".keep", ec)) {
            continue;
        }
        UniqueFd lock(::open((entry.path() / ".lock").c_str(), O_RDWR | O_NOFOLLOW | O_CLOEXEC));
        if (!lock || ::flock(lock.get(), LOCK_EX | LOCK_NB) != 0) {
            continue;  // in use by a running analysis (or not a TracePot workspace)
        }
        if (removeTree(entry.path())) {
            ++removed;
        }
    }
    return removed;
}

Status Workspace::remove()
{
    if (removed_ || paths_.runDir.empty()) {
        return {};
    }
    removed_ = true;
    return removeTree(paths_.runDir);
}

Status Workspace::populateSandboxRoot(SandboxUser user)
{
    const fs::path& root = paths_.rootDir;
    ::chmod(root.c_str(), 0755);
    struct Dir {
        const char* path;
        mode_t mode;
    };
    const std::string userHome = "home/" + std::string(kSandboxUserName);
    const std::string runUser = "run/user/" + std::to_string(kSandboxUserUid);
    const std::array<Dir, 25> dirs = {{
        {"etc", 0755}, {"home", 0755}, {userHome.c_str(), 0755}, {"root", 0700}, {"tmp", 01777},
        {"var", 0755}, {"var/tmp", 01777}, {"var/lib", 0755}, {"var/log", 0755}, {"var/cache", 0755},
        {"var/spool", 0755}, {"var/spool/cron", 0755}, {"var/spool/cron/crontabs", 0755}, {"opt", 0755},
        {"usr/local", 0755}, {"usr/local/bin", 0755}, {"usr/local/sbin", 0755}, {"usr/local/lib", 0755},
        {"usr/local/share", 0755}, {"usr/local/etc", 0755}, {"usr/local/include", 0755}, {"run", 0755},
        {"run/user", 0755}, {runUser.c_str(), 0700}, {"work", 0755},
    }};
    for (const auto& dir : dirs) {
        const fs::path path = root / dir.path;
        if (auto s = makeDirectories(path, 0755); !s) {
            return s;
        }
        ::chmod(path.c_str(), dir.mode);
    }
    // In unprivileged mode the sandbox user owns these through the user-namespace mapping, so the
    // read-only bind mounts (not permission bits) are what keeps system directories unmodifiable.

    const fs::path etc = root / "etc";
    for (const auto name : kEtcEntries) {
        copyHostEntry(fs::path("/etc") / name, etc / name, 1);
    }
    for (const auto name : kEtcDirectories) {
        if (auto s = makeDirectories(etc / name, 0755); !s) {
            return s;
        }
    }
    const std::string shell = ::access("/usr/bin/bash", X_OK) == 0 ? "/bin/bash" : "/bin/sh";
    const std::string uid = std::to_string(kSandboxUserUid);
    const std::string passwd = "root:x:0:0:root:/root:" + shell + "\n" + std::string(kSandboxUserName) + ":x:" + uid +
                               ":" + uid + ":TracePot sandbox user:/home/" + std::string(kSandboxUserName) + ":" +
                               shell + "\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n";
    const std::string group = "root:x:0:\n" + std::string(kSandboxUserName) + ":x:" + uid + ":\nnogroup:x:65534:\n";
    const std::string hosts = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t" +
                              std::string(kSandboxHostname) + "\n";
    for (const auto& [name, content] : std::array<std::pair<const char*, std::string>, 5>{{
             {"passwd", passwd},
             {"group", group},
             {"hosts", hosts},
             {"hostname", std::string(kSandboxHostname) + "\n"},
             // A random machine-id prevents the sample from reading the host's identifier.
             {"machine-id", randomHex(16) + "\n"},
         }}) {
        ::unlink((etc / name).c_str());
        if (auto s = writeFileSecure(etc / name, content, 0644); !s) {
            return s;
        }
    }

    if (auto s = populateHome(root / userHome); !s) {
        return s;
    }
    if (auto s = populateHome(root / "root"); !s) {
        return s;
    }
    (void)user;  // both homes exist in both modes; the mode only changes mounts and identity
    return {};
}

}  // namespace tracepot
