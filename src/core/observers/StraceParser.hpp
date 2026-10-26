#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tracepot {

// One line of `strace -f -ttt -y --pidns-translation` output, classified but not yet merged.
// Strace output is treated as untrusted: file names, argv strings and buffers are controlled by
// the analyzed code. Parsing therefore relies only on strace's escaping guarantees (quotes and
// angle brackets inside strings/paths are always escaped) and never on content heuristics.
struct StraceLine {
    enum class Kind { Syscall, Unfinished, Resumed, Signal, Exited, Killed };
    Kind kind = Kind::Syscall;
    int pid = 0;
    double timestamp = 0;
    std::string name;  // syscall or signal name
    std::string text;  // Syscall: full "name(args) = ret"; Unfinished: "name(partial"; Resumed: remainder
    int exitCode = 0;
    bool coreDumped = false;
};

std::optional<StraceLine> parseStraceLine(std::string_view line);

struct SyscallRecord {
    int pid = 0;
    double timestamp = 0;
    std::string name;
    std::vector<std::string> args;  // raw top-level argument tokens
    bool returnKnown = false;
    long long returnValue = 0;
    std::string errnoName;          // e.g. ENOENT when the call failed
    std::string returnDecoration;   // decoded fd path of the returned descriptor (with -y)
    std::optional<long long> translatedPid;  // "/* N in strace's PID NS */"

    [[nodiscard]] bool succeeded() const { return returnKnown && returnValue >= 0 && errnoName.empty(); }
};

// Parses "name(args) = ret".
std::optional<SyscallRecord> parseSyscallText(std::string_view text);

// Splits an argument list at top-level commas.
std::vector<std::string> splitArguments(std::string_view args);

// Decodes a strace-quoted string token ("...", optionally followed by ... when truncated).
std::optional<std::string> decodeQuotedString(std::string_view token, bool* truncated = nullptr);

// Decodes a C-style escaped byte sequence without surrounding quotes.
std::string decodeEscapes(std::string_view text);

struct FdRef {
    bool atFdcwd = false;
    int fd = -1;
    std::string path;               // decoded decoration (file path), if any
    std::optional<std::uint64_t> socketInode;
};

// Parses descriptor tokens such as `3</work/x>`, `AT_FDCWD</work>`, `5<socket:[1234]>` or `3`.
FdRef parseFdToken(std::string_view token);

// Parses a strace string array: ["a", "b", ...].
std::vector<std::string> parseStringArray(std::string_view token, bool* truncated = nullptr);

struct SockAddr {
    std::string family;  // AF_INET, AF_INET6, AF_UNIX, AF_NETLINK, ...
    std::string address; // IP address or unix path ("@name" for abstract sockets)
    std::optional<int> port;
};

std::optional<SockAddr> parseSockAddr(std::string_view token);

// Merges unfinished/resumed pairs per PID and yields complete records.
class StraceAssembler {
public:
    // Returns a complete record when the line completes a syscall; nullopt otherwise.
    std::optional<SyscallRecord> push(const StraceLine& line);
    void forget(int pid) { pending_.erase(pid); }

private:
    struct Pending {
        double timestamp;
        std::string text;
    };
    std::map<int, Pending> pending_;
};

}  // namespace tracepot
