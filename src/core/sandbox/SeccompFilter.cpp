#include "core/sandbox/SeccompFilter.hpp"

#include <array>
#include <cerrno>
#include <memory>

#include <fcntl.h>
#include <linux/sched.h>
#include <seccomp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tracepot {

namespace {

struct SeccompDeleter {
    void operator()(scmp_filter_ctx ctx) const { seccomp_release(ctx); }
};
using SeccompCtx = std::unique_ptr<void, SeccompDeleter>;

constexpr std::array<const char*, 24> kEpermSyscalls = {
    "syslog",        "uselib",          "acct",          "quotactl",        "add_key",
    "keyctl",        "request_key",     "move_pages",    "mbind",           "get_mempolicy",
    "set_mempolicy", "migrate_pages",   "perf_event_open", "userfaultfd",   "bpf",
    "kexec_load",    "kexec_file_load", "init_module",   "finit_module",    "delete_module",
    "open_by_handle_at", "mount",       "umount2",       "pivot_root",
};

constexpr std::array<const char*, 3> kEnosysSyscalls = {"io_uring_setup", "io_uring_enter", "io_uring_register"};

}  // namespace

Result<SeccompProgram> buildSeccompProgram()
{
    SeccompCtx ctx(seccomp_init(SCMP_ACT_ALLOW));
    if (!ctx) {
        return makeError(ErrorCode::SandboxUnavailable, "seccomp_init failed");
    }
    // Apply the same rules to the 32-bit ABIs on x86-64; otherwise int 0x80 syscalls would
    // hit the "bad architecture" action and kill 32-bit programs.
    if (seccomp_arch_native() == SCMP_ARCH_X86_64) {
        seccomp_arch_add(ctx.get(), SCMP_ARCH_X86);
        seccomp_arch_add(ctx.get(), SCMP_ARCH_X32);
    }

    SeccompProgram program;
    auto block = [&](const char* name, std::uint32_t action, const std::string& label, unsigned argCount,
                     const scmp_arg_cmp* args) {
        const int nr = seccomp_syscall_resolve_name(name);
        if (nr == __NR_SCMP_ERROR) {
            return;  // not available on this architecture
        }
        const int rc = argCount == 0 ? seccomp_rule_add(ctx.get(), action, nr, 0)
                                     : seccomp_rule_add_array(ctx.get(), action, nr, argCount, args);
        if (rc == 0) {
            program.blocked.push_back(label);
        }
    };

    for (const char* name : kEpermSyscalls) {
        block(name, SCMP_ACT_ERRNO(EPERM), name, 0, nullptr);
    }
    for (const char* name : kEnosysSyscalls) {
        block(name, SCMP_ACT_ERRNO(ENOSYS), name, 0, nullptr);
    }
    block("clone3", SCMP_ACT_ERRNO(ENOSYS), "clone3", 0, nullptr);

    const scmp_arg_cmp newUserArg0 = SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER);
    block("unshare", SCMP_ACT_ERRNO(EPERM), "unshare(CLONE_NEWUSER)", 1, &newUserArg0);
    // clone's flags are the first argument on x86-64 and aarch64 (s390 differs; unsupported here).
    block("clone", SCMP_ACT_ERRNO(EPERM), "clone(CLONE_NEWUSER)", 1, &newUserArg0);

    const scmp_arg_cmp tiocsti = SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, TIOCSTI);
    const scmp_arg_cmp tioclinux = SCMP_A1(SCMP_CMP_MASKED_EQ, 0xFFFFFFFFu, TIOCLINUX);
    block("ioctl", SCMP_ACT_ERRNO(EPERM), "ioctl(TIOCSTI)", 1, &tiocsti);
    block("ioctl", SCMP_ACT_ERRNO(EPERM), "ioctl(TIOCLINUX)", 1, &tioclinux);

    bool socketRuleAdded = false;
    for (int family = 0; family < AF_MAX; ++family) {
        if (family == AF_UNIX || family == AF_INET || family == AF_INET6 || family == AF_NETLINK) {
            continue;
        }
        const scmp_arg_cmp familyArg = SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(family));
        const int nr = seccomp_syscall_resolve_name("socket");
        if (nr != __NR_SCMP_ERROR &&
            seccomp_rule_add_array(ctx.get(), SCMP_ACT_ERRNO(EAFNOSUPPORT), nr, 1, &familyArg) == 0) {
            socketRuleAdded = true;
        }
    }
    const scmp_arg_cmp highFamilies = SCMP_A0(SCMP_CMP_GE, static_cast<scmp_datum_t>(AF_MAX));
    const int socketNr = seccomp_syscall_resolve_name("socket");
    if (socketNr != __NR_SCMP_ERROR) {
        seccomp_rule_add_array(ctx.get(), SCMP_ACT_ERRNO(EAFNOSUPPORT), socketNr, 1, &highFamilies);
    }
    if (socketRuleAdded) {
        program.blocked.emplace_back("socket(families other than unix/inet/inet6/netlink)");
    }

    program.fd.reset(::memfd_create("tracepot-seccomp", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (!program.fd) {
        return makeError(ErrorCode::SandboxUnavailable, "memfd_create failed: " + errnoMessage(errno));
    }
    if (seccomp_export_bpf(ctx.get(), program.fd.get()) != 0) {
        return makeError(ErrorCode::SandboxUnavailable, "cannot export the seccomp filter");
    }
    // Seal the program so nothing that inherits the descriptor can alter it.
    ::fcntl(program.fd.get(), F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    ::lseek(program.fd.get(), 0, SEEK_SET);
    return program;
}

}  // namespace tracepot
