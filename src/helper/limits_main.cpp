// tracepot-limits: applies resource limits, closes stray descriptors and executes a program.
//
// TracePot runs `strace ... -- tracepot-limits [limits] -- bwrap ...` so the limits apply to the
// sandbox but not to strace itself (RLIMIT_FSIZE would otherwise truncate the trace log).
// Usage:
//   tracepot-limits [--as BYTES] [--fsize BYTES] [--nofile N] [--nproc-extra N] [--core BYTES]
//                   [--keep-fd N]... -- /absolute/program [args...]

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

[[noreturn]] void fail(const std::string& message)
{
    std::fprintf(stderr, "tracepot-limits: %s\n", message.c_str());
    std::_Exit(127);
}

unsigned long long parseNumber(const char* text)
{
    errno = 0;
    char* end = nullptr;
    const unsigned long long value = std::strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        fail(std::string("invalid number: ") + text);
    }
    return value;
}

void setLimit(int resource, unsigned long long value, const char* name)
{
    struct rlimit current {};
    if (::getrlimit(resource, &current) != 0) {
        fail(std::string("getrlimit failed for ") + name);
    }
    rlim_t wanted = static_cast<rlim_t>(value);
    if (current.rlim_max != RLIM_INFINITY && wanted > current.rlim_max) {
        wanted = current.rlim_max;  // cannot raise the hard limit; keep the stricter one
    }
    const struct rlimit limit {wanted, wanted};
    if (::setrlimit(resource, &limit) != 0) {
        fail(std::string("setrlimit failed for ") + name + ": " + std::strerror(errno));
    }
}

// RLIMIT_NPROC counts all processes of the real UID, so the limit is the current count plus the
// allowance for the sandbox.
unsigned long long countOwnProcesses()
{
    const uid_t uid = ::getuid();
    unsigned long long count = 0;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc", ec)) {
        const std::string name = entry.path().filename().string();
        if (name.empty() || name.find_first_not_of("0123456789") != std::string::npos) {
            continue;
        }
        struct stat st {};
        if (::stat(entry.path().c_str(), &st) == 0 && st.st_uid == uid) {
            ++count;
        }
    }
    return count;
}

}  // namespace

int main(int argc, char** argv)
{
    std::set<int> keep;
    int index = 1;
    struct Pending {
        int resource;
        unsigned long long value;
        const char* name;
    };
    std::vector<Pending> limits;
    unsigned long long nprocExtra = 0;
    for (; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--") {
            ++index;
            break;
        }
        if (index + 1 >= argc) {
            fail("missing value for " + arg);
        }
        const char* value = argv[++index];
        if (arg == "--as") {
            limits.push_back({RLIMIT_AS, parseNumber(value), "RLIMIT_AS"});
        } else if (arg == "--fsize") {
            limits.push_back({RLIMIT_FSIZE, parseNumber(value), "RLIMIT_FSIZE"});
        } else if (arg == "--nofile") {
            limits.push_back({RLIMIT_NOFILE, parseNumber(value), "RLIMIT_NOFILE"});
        } else if (arg == "--core") {
            limits.push_back({RLIMIT_CORE, parseNumber(value), "RLIMIT_CORE"});
        } else if (arg == "--nproc-extra") {
            nprocExtra = parseNumber(value);
        } else if (arg == "--keep-fd") {
            keep.insert(static_cast<int>(parseNumber(value)));
        } else {
            fail("unknown option " + arg);
        }
    }
    if (index >= argc || argv[index][0] != '/') {
        fail("an absolute program path is required after --");
    }
    if (nprocExtra > 0) {
        limits.push_back({RLIMIT_NPROC, countOwnProcesses() + nprocExtra, "RLIMIT_NPROC"});
    }
    for (const auto& limit : limits) {
        setLimit(limit.resource, limit.value, limit.name);
    }

    // Close every inherited descriptor except stdio and explicitly kept ones (e.g. the seccomp
    // program for bubblewrap), so nothing from the host leaks into the sandbox.
    std::vector<int> open;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd", ec)) {
        const int fd = std::atoi(entry.path().filename().c_str());
        if (fd > 2 && keep.count(fd) == 0) {
            open.push_back(fd);
        }
    }
    for (const int fd : open) {
        ::close(fd);
    }
    ::umask(022);
    ::execv(argv[index], &argv[index]);
    fail(std::string("cannot execute ") + argv[index] + ": " + std::strerror(errno));
}
