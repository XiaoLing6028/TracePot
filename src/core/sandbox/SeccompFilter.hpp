#pragma once

#include "core/models/Result.hpp"
#include "core/util/FileUtil.hpp"

#include <string>
#include <vector>

namespace tracepot {

struct SeccompProgram {
    UniqueFd fd;  // memfd holding the BPF program, positioned at offset 0
    std::vector<std::string> blocked;  // human-readable list of blocked operations
};

// Builds a deny-list seccomp filter (default allow) loaded by bubblewrap inside the sandbox.
// It reduces kernel attack surface and keeps the syscall trace meaningful:
//   * kernel keyring, BPF, perf, userfaultfd, module loading, kexec, mount, open_by_handle_at,
//     NUMA memory policy and other rarely needed interfaces fail with EPERM;
//   * io_uring fails with ENOSYS (io_uring operations are invisible to ptrace-based tracing);
//   * creating nested user namespaces fails (unshare/clone with CLONE_NEWUSER), and clone3 fails
//     with ENOSYS so the C library falls back to clone(), whose flags can be inspected;
//   * TIOCSTI/TIOCLINUX ioctls (terminal input injection) fail with EPERM;
//   * socket families other than AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK fail with EAFNOSUPPORT.
// Syscalls denied by this filter are not visible in the trace (seccomp runs before ptrace stops).
Result<SeccompProgram> buildSeccompProgram();

}  // namespace tracepot
