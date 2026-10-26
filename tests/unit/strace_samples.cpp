#include "unit/strace_samples.hpp"

namespace samples {

const char* const kOpenatLine = R"(1301  1793006449.069854 openat(AT_FDCWD</work>, "out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</work/out.txt>)";
const char* const kConnectRefused = R"(connect(3<socket:[5360]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused))";
const char* const kOpenDeletedFile = R"(openat(AT_FDCWD</work>, "x", O_RDONLY) = 3</work/x (deleted)>)";
const char* const kHostileFileName = R"(openat(AT_FDCWD</work>, "a,b>c \"q\" <x>.txt", O_WRONLY|O_CREAT, 0666) = 3</work/a,b\76c \"q\" \74x\76.txt>)";
const char* const kFakeReturnInName = R"(unlink("x\") = 0 /* fake */, (") = -1 ENOENT (No such file or directory))";
const char* const kControlCharacterName = R"(mkdir("nl\nline\33[31m", 0777) = 0)";
const char* const kOctalUtf8 = R"(\303\274n\303\257)";
const char* const kOctalDnsPayload = R"(h\0\1\7example\3com\0)";
const char* const kHexEscapes = R"(\x41\x4a)";
const char* const kSimpleEscapes = R"(\\ \" \t)";
const char* const kTruncatedString = R"("abc"...)";
const char* const kArgvArray = R"(["sh", "-c", "echo \"a, b\"; ls [x]"])";
const char* const kInet6Address = R"({sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0})";
const char* const kUnixAddress = R"({sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"})";
const char* const kAbstractUnixAddress = R"({sa_family=AF_UNIX, sun_path=@"/tmp/.X11-unix/X0"})";
const char* const kStructuredArguments = R"(3</a,b>, {x=1, y=[2, 3]}, "s,t", f(a, b) /* c, d */)";
const char* const kUnfinishedExecve = R"(1350  1.0 execve("/usr/bin/touch", ["touch", "x"], 0x55 /* 9 vars */ <unfinished ...>)";

}  // namespace samples
