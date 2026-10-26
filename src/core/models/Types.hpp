#pragma once

#include <array>
#include <optional>
#include <string_view>
#include <utility>

namespace tracepot {

// How a piece of information in a report was obtained.
enum class EvidenceKind {
    Observed,   // directly recorded by an observer (syscall trace, filesystem diff, runtime)
    Inferred,   // derived by classification rules from observations
    Missing,    // an observation that could not be made
    Error,      // collection failed
};

enum class ObservationSource {
    SyscallTrace,
    FilesystemDiff,
    SandboxRuntime,
    HostIntegrityCheck,
    InputInspection,
    CommandLine,
};

enum class Outcome { Success, Failed, Unknown };

enum class FileType { Regular, Directory, Symlink, Fifo, Socket, CharDevice, BlockDevice, Unknown };

enum class EventType {
    ProcessSpawn,
    ProcessExec,
    ProcessExit,
    FileWrite,
    FileDelete,
    FileRename,
    DirectoryCreate,
    DirectoryDelete,
    SymlinkCreate,
    HardlinkCreate,
    PermissionChange,
    OwnershipChange,
    FileTruncate,
    SensitiveRead,
    NetworkConnect,
    NetworkBind,
    NetworkListen,
    NetworkSend,
};

enum class TerminationReason {
    NotStarted,
    Exited,
    Signaled,
    Timeout,
    Cancelled,
    ResourceLimit,
    LaunchFailed,
};

enum class ChangeKind { Created, Deleted, Modified };

enum class Severity { Info, Warning, Error };

enum class DiagnosticKind {
    Limitation,  // something TracePot cannot observe or guarantee
    Warning,     // something the user should pay attention to
    Error,       // an analysis step failed
    Note,        // neutral context
};

enum class NetworkEventKind {
    DnsQuery,
    Connect,
    Datagram,
    Bind,
    Listen,
    LocalSocket,
    InferredDestination,
};

enum class InputKind { ShellScript, TarArchive, Unsupported };

enum class SandboxUser { Unprivileged, SimulatedRoot };

enum class PersistenceCategory {
    ShellStartup,
    XdgAutostart,
    SystemdUnit,
    Cron,
    SysVInit,
    Sudoers,
    SshAccess,
    DynamicLinker,
    UdevRule,
    Pam,
    KernelModule,
    PackageRepository,
    PersistenceCommand,
    Custom,
};

// Bidirectional enum <-> stable string mapping used for reports and display.
template <typename E>
struct EnumNames;

#define TRACEPOT_ENUM_NAMES(Enum, ...)                                                   \
    template <>                                                                          \
    struct EnumNames<Enum> {                                                             \
        static constexpr auto entries = std::to_array<std::pair<Enum, std::string_view>>( \
            {__VA_ARGS__});                                                              \
    }

TRACEPOT_ENUM_NAMES(EvidenceKind, {EvidenceKind::Observed, "observed"}, {EvidenceKind::Inferred, "inferred"},
                    {EvidenceKind::Missing, "missing"}, {EvidenceKind::Error, "error"});
TRACEPOT_ENUM_NAMES(ObservationSource, {ObservationSource::SyscallTrace, "syscall-trace"},
                    {ObservationSource::FilesystemDiff, "filesystem-diff"},
                    {ObservationSource::SandboxRuntime, "sandbox-runtime"},
                    {ObservationSource::HostIntegrityCheck, "host-integrity-check"},
                    {ObservationSource::InputInspection, "input-inspection"},
                    {ObservationSource::CommandLine, "command-line"});
TRACEPOT_ENUM_NAMES(Outcome, {Outcome::Success, "success"}, {Outcome::Failed, "failed"},
                    {Outcome::Unknown, "unknown"});
TRACEPOT_ENUM_NAMES(FileType, {FileType::Regular, "file"}, {FileType::Directory, "directory"},
                    {FileType::Symlink, "symlink"}, {FileType::Fifo, "fifo"}, {FileType::Socket, "socket"},
                    {FileType::CharDevice, "char-device"}, {FileType::BlockDevice, "block-device"},
                    {FileType::Unknown, "unknown"});
TRACEPOT_ENUM_NAMES(EventType, {EventType::ProcessSpawn, "process-spawn"}, {EventType::ProcessExec, "process-exec"},
                    {EventType::ProcessExit, "process-exit"}, {EventType::FileWrite, "file-write"},
                    {EventType::FileDelete, "file-delete"}, {EventType::FileRename, "file-rename"},
                    {EventType::DirectoryCreate, "directory-create"},
                    {EventType::DirectoryDelete, "directory-delete"},
                    {EventType::SymlinkCreate, "symlink-create"}, {EventType::HardlinkCreate, "hardlink-create"},
                    {EventType::PermissionChange, "permission-change"},
                    {EventType::OwnershipChange, "ownership-change"}, {EventType::FileTruncate, "file-truncate"},
                    {EventType::SensitiveRead, "sensitive-read"}, {EventType::NetworkConnect, "network-connect"},
                    {EventType::NetworkBind, "network-bind"}, {EventType::NetworkListen, "network-listen"},
                    {EventType::NetworkSend, "network-send"});
TRACEPOT_ENUM_NAMES(TerminationReason, {TerminationReason::NotStarted, "not-started"},
                    {TerminationReason::Exited, "exited"}, {TerminationReason::Signaled, "signaled"},
                    {TerminationReason::Timeout, "timeout"}, {TerminationReason::Cancelled, "cancelled"},
                    {TerminationReason::ResourceLimit, "resource-limit"},
                    {TerminationReason::LaunchFailed, "launch-failed"});
TRACEPOT_ENUM_NAMES(ChangeKind, {ChangeKind::Created, "created"}, {ChangeKind::Deleted, "deleted"},
                    {ChangeKind::Modified, "modified"});
TRACEPOT_ENUM_NAMES(Severity, {Severity::Info, "info"}, {Severity::Warning, "warning"}, {Severity::Error, "error"});
TRACEPOT_ENUM_NAMES(DiagnosticKind, {DiagnosticKind::Limitation, "limitation"},
                    {DiagnosticKind::Warning, "warning"}, {DiagnosticKind::Error, "error"},
                    {DiagnosticKind::Note, "note"});
TRACEPOT_ENUM_NAMES(NetworkEventKind, {NetworkEventKind::DnsQuery, "dns-query"},
                    {NetworkEventKind::Connect, "connect"}, {NetworkEventKind::Datagram, "datagram"},
                    {NetworkEventKind::Bind, "bind"}, {NetworkEventKind::Listen, "listen"},
                    {NetworkEventKind::LocalSocket, "local-socket"},
                    {NetworkEventKind::InferredDestination, "inferred-destination"});
TRACEPOT_ENUM_NAMES(InputKind, {InputKind::ShellScript, "shell-script"}, {InputKind::TarArchive, "tar-archive"},
                    {InputKind::Unsupported, "unsupported"});
TRACEPOT_ENUM_NAMES(SandboxUser, {SandboxUser::Unprivileged, "unprivileged"},
                    {SandboxUser::SimulatedRoot, "simulated-root"});
TRACEPOT_ENUM_NAMES(PersistenceCategory, {PersistenceCategory::ShellStartup, "shell-startup"},
                    {PersistenceCategory::XdgAutostart, "xdg-autostart"},
                    {PersistenceCategory::SystemdUnit, "systemd-unit"}, {PersistenceCategory::Cron, "cron"},
                    {PersistenceCategory::SysVInit, "sysv-init"}, {PersistenceCategory::Sudoers, "sudoers"},
                    {PersistenceCategory::SshAccess, "ssh-access"},
                    {PersistenceCategory::DynamicLinker, "dynamic-linker"},
                    {PersistenceCategory::UdevRule, "udev-rule"}, {PersistenceCategory::Pam, "pam"},
                    {PersistenceCategory::KernelModule, "kernel-module"},
                    {PersistenceCategory::PackageRepository, "package-repository"},
                    {PersistenceCategory::PersistenceCommand, "persistence-command"},
                    {PersistenceCategory::Custom, "custom"});

#undef TRACEPOT_ENUM_NAMES

template <typename E>
constexpr std::string_view enumName(E value)
{
    for (const auto& [enumValue, name] : EnumNames<E>::entries) {
        if (enumValue == value) {
            return name;
        }
    }
    return "unknown";
}

template <typename E>
constexpr std::optional<E> parseEnum(std::string_view text)
{
    for (const auto& [enumValue, name] : EnumNames<E>::entries) {
        if (name == text) {
            return enumValue;
        }
    }
    return std::nullopt;
}

}  // namespace tracepot
