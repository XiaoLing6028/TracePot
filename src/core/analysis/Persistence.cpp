#include "core/analysis/Persistence.hpp"

#include "core/util/Glob.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <set>

namespace tracepot {

namespace {

std::vector<std::string> expandHome(const std::string& pattern)
{
    if (pattern.rfind("~/", 0) == 0) {
        const std::string rest = pattern.substr(1);
        return {"/home/*" + rest, "/root" + rest};
    }
    return {pattern};
}

std::string baseName(const std::string& path)
{
    const auto slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool isMutation(EventType type)
{
    switch (type) {
    case EventType::FileWrite:
    case EventType::FileDelete:
    case EventType::FileRename:
    case EventType::SymlinkCreate:
    case EventType::HardlinkCreate:
    case EventType::PermissionChange:
    case EventType::OwnershipChange:
    case EventType::FileTruncate:
        return true;
    default:
        return false;
    }
}

// Commands that register code for later execution. Only invocations with these verbs count.
bool isPersistenceCommand(const std::vector<std::string>& argv, std::string& reason)
{
    if (argv.empty()) {
        return false;
    }
    const std::string tool = baseName(argv.front());
    auto hasArg = [&argv](std::initializer_list<std::string_view> words) {
        return std::any_of(argv.begin() + 1, argv.end(), [&](const std::string& arg) {
            return std::find(words.begin(), words.end(), arg) != words.end();
        });
    };
    if (tool == "systemctl" &&
        hasArg({"enable", "reenable", "link", "preset", "start", "restart", "edit", "set-default", "daemon-reload",
                "add-wants", "add-requires", "unmask", "mask"})) {
        reason = "service manager registration";
        return true;
    }
    if (tool == "crontab" && !hasArg({"-l"})) {
        reason = "crontab installation";
        return true;
    }
    if (tool == "at" || tool == "batch") {
        reason = "deferred job scheduling";
        return true;
    }
    if (tool == "update-rc.d" || tool == "chkconfig" || tool == "rc-update" ||
        (tool == "service" && argv.size() > 1)) {
        reason = "init script registration";
        return true;
    }
    if (tool == "loginctl" && hasArg({"enable-linger"})) {
        reason = "user lingering (services keep running after logout)";
        return true;
    }
    return false;
}

}  // namespace

const std::vector<PersistenceRule>& builtinPersistenceRules()
{
    static const std::vector<PersistenceRule> rules = {
        {"shell-startup-user", PersistenceCategory::ShellStartup, "user",
         {"~/.bashrc", "~/.bash_profile", "~/.bash_login", "~/.bash_logout", "~/.profile", "~/.zshrc", "~/.zshenv",
          "~/.zprofile", "~/.zlogin", "~/.config/fish/config.fish", "~/.config/fish/conf.d/**", "~/.pam_environment",
          "~/.config/environment.d/**", "~/.xprofile", "~/.xinitrc", "~/.xsession"},
         "user shell or session startup file (runs at login or when a shell starts)"},
        {"shell-startup-system", PersistenceCategory::ShellStartup, "system",
         {"/etc/profile", "/etc/profile.d/**", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zsh/**", "/etc/zshrc",
          "/etc/zprofile", "/etc/zshenv", "/etc/environment", "/etc/environment.d/**", "/etc/fish/**"},
         "system-wide shell or session startup file"},
        {"xdg-autostart-user", PersistenceCategory::XdgAutostart, "user", {"~/.config/autostart/**"},
         "XDG autostart entry (runs when the user's desktop session starts)"},
        {"xdg-autostart-system", PersistenceCategory::XdgAutostart, "system", {"/etc/xdg/autostart/**"},
         "system-wide XDG autostart entry"},
        {"systemd-user-unit", PersistenceCategory::SystemdUnit, "user",
         {"~/.config/systemd/user/**", "~/.local/share/systemd/user/**"}, "systemd user unit"},
        {"systemd-system-unit", PersistenceCategory::SystemdUnit, "system",
         {"/etc/systemd/system/**", "/etc/systemd/user/**", "/usr/local/lib/systemd/**", "/run/systemd/system/**",
          "/etc/systemd/system-generators/**", "/etc/systemd/user-generators/**"},
         "systemd system or global user unit"},
        {"cron-system", PersistenceCategory::Cron, "system",
         {"/etc/crontab", "/etc/cron.d/**", "/etc/cron.hourly/**", "/etc/cron.daily/**", "/etc/cron.weekly/**",
          "/etc/cron.monthly/**", "/etc/anacrontab"},
         "system cron schedule"},
        {"cron-user", PersistenceCategory::Cron, "user", {"/var/spool/cron/**"}, "per-user crontab"},
        {"sysv-init", PersistenceCategory::SysVInit, "system",
         {"/etc/init.d/**", "/etc/rc.local", "/etc/rc?.d/**", "/etc/rc.d/**"}, "SysV init or rc script"},
        {"sudoers", PersistenceCategory::Sudoers, "system", {"/etc/sudoers", "/etc/sudoers.d/**"},
         "sudo privilege configuration"},
        {"ssh-user", PersistenceCategory::SshAccess, "user",
         {"~/.ssh/authorized_keys", "~/.ssh/authorized_keys2", "~/.ssh/rc", "~/.ssh/config"},
         "SSH access or client configuration"},
        {"ssh-system", PersistenceCategory::SshAccess, "system",
         {"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/**", "/etc/ssh/sshrc"}, "SSH server configuration"},
        {"dynamic-linker", PersistenceCategory::DynamicLinker, "system",
         {"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d/**"},
         "dynamic linker configuration (library preloading or search paths)"},
        {"udev-rule", PersistenceCategory::UdevRule, "system", {"/etc/udev/rules.d/**"},
         "udev rule (runs on device events)"},
        {"pam", PersistenceCategory::Pam, "system", {"/etc/pam.d/**", "/etc/security/**"},
         "PAM authentication configuration"},
        {"kernel-module", PersistenceCategory::KernelModule, "system",
         {"/etc/modules", "/etc/modules-load.d/**", "/etc/modprobe.d/**"}, "kernel module loading configuration"},
        {"package-repository", PersistenceCategory::PackageRepository, "system",
         {"/etc/apt/sources.list", "/etc/apt/sources.list.d/**", "/etc/apt/trusted.gpg.d/**", "/etc/apt/keyrings/**",
          "/etc/yum.repos.d/**", "/etc/zypp/repos.d/**", "/etc/pacman.conf", "/etc/pacman.d/**"},
         "package repository or signing key (affects future software updates)"},
    };
    return rules;
}

PersistenceClassifier::PersistenceClassifier(const std::vector<std::string>& extraPatterns)
{
    auto compile = [this](const PersistenceRule& rule) {
        CompiledRule compiled{rule, {}};
        for (const auto& pattern : rule.patterns) {
            for (auto& glob : expandHome(pattern)) {
                compiled.globs.push_back(std::move(glob));
            }
        }
        compiled_.push_back(std::move(compiled));
    };
    for (const auto& rule : builtinPersistenceRules()) {
        compile(rule);
    }
    if (!extraPatterns.empty()) {
        PersistenceRule custom;
        custom.id = "custom";
        custom.category = PersistenceCategory::Custom;
        custom.scope = "configured";
        custom.patterns = extraPatterns;
        custom.description = "user-configured startup location";
        compile(custom);
    }
}

const PersistenceRule* PersistenceClassifier::match(std::string_view sandboxPath) const
{
    for (const auto& compiled : compiled_) {
        for (const auto& glob : compiled.globs) {
            if (globMatch(glob, sandboxPath)) {
                return &compiled.rule;
            }
        }
    }
    return nullptr;
}

std::vector<PersistenceFinding> PersistenceClassifier::classify(const std::vector<FileChange>& changes,
                                                                const std::vector<TraceEvent>& events,
                                                                const std::vector<ProcessRecord>& processes) const
{
    std::vector<PersistenceFinding> findings;
    std::set<std::string> changedPaths;
    std::map<std::string, std::set<int>> writers;
    for (const auto& event : events) {
        if (isMutation(event.type) && event.outcome == Outcome::Success) {
            writers[event.path].insert(event.pid);
            if (!event.targetPath.empty() && event.type == EventType::FileRename) {
                writers[event.targetPath].insert(event.pid);
            }
        }
    }

    for (const auto& change : changes) {
        const bool isDirectory = (change.after && change.after->type == FileType::Directory) ||
                                 (!change.after && change.before && change.before->type == FileType::Directory);
        if (isDirectory) {
            continue;  // an empty directory does not run anything by itself
        }
        const PersistenceRule* rule = match(change.path);
        if (rule == nullptr) {
            continue;
        }
        PersistenceFinding finding;
        finding.category = rule->category;
        finding.scope = rule->scope;
        finding.path = change.path;
        finding.action = std::string(enumName(change.kind));
        finding.outcome = "applied-in-sandbox";
        finding.ruleId = rule->id;
        finding.description = rule->description;
        finding.basis.push_back(ObservationSource::FilesystemDiff);
        if (const auto it = writers.find(change.path); it != writers.end()) {
            finding.basis.push_back(ObservationSource::SyscallTrace);
            finding.pids.assign(it->second.begin(), it->second.end());
        }
        changedPaths.insert(change.path);
        findings.push_back(std::move(finding));
    }

    // Trace-only evidence: failed attempts (e.g. EROFS in unprivileged mode) and writes that left
    // no net change in the final filesystem state.
    std::map<std::string, std::size_t> traceFindings;
    for (const auto& event : events) {
        if (!isMutation(event.type)) {
            continue;
        }
        const std::string& path = event.type == EventType::FileRename && !event.targetPath.empty() ? event.targetPath
                                                                                                    : event.path;
        if (changedPaths.count(path) != 0) {
            continue;
        }
        const PersistenceRule* rule = match(path);
        if (rule == nullptr) {
            continue;
        }
        const std::string outcome = event.outcome == Outcome::Failed
                                        ? "attempt-failed" + (event.error.empty() ? std::string() : " (" + event.error + ")")
                                        : "attempt-observed";
        const std::string key = path + "|" + outcome;
        if (const auto it = traceFindings.find(key); it != traceFindings.end()) {
            auto& pids = findings[it->second].pids;
            if (std::find(pids.begin(), pids.end(), event.pid) == pids.end()) {
                pids.push_back(event.pid);
            }
            continue;
        }
        PersistenceFinding finding;
        finding.category = rule->category;
        finding.scope = rule->scope;
        finding.path = path;
        finding.action = "write-attempt";
        finding.outcome = outcome;
        finding.ruleId = rule->id;
        finding.description = rule->description + (event.outcome == Outcome::Failed
                                                       ? "; the operation failed inside the sandbox"
                                                       : "; written during the run but absent from the final state");
        finding.basis.push_back(ObservationSource::SyscallTrace);
        finding.pids.push_back(event.pid);
        traceFindings[key] = findings.size();
        findings.push_back(std::move(finding));
    }

    for (const auto& process : processes) {
        for (const auto& exec : process.execs) {
            std::string reason;
            if (!isPersistenceCommand(exec.argv, reason)) {
                continue;
            }
            PersistenceFinding finding;
            finding.category = PersistenceCategory::PersistenceCommand;
            finding.scope = std::find(exec.argv.begin(), exec.argv.end(), "--user") != exec.argv.end() ? "user"
                                                                                                         : "system";
            finding.path = exec.path;
            finding.action = "command";
            finding.outcome = exec.outcome == Outcome::Success ? "command-executed" : "command-failed";
            finding.ruleId = "persistence-command";
            std::string commandLine;
            for (const auto& arg : exec.argv) {
                commandLine += (commandLine.empty() ? "" : " ") + arg;
            }
            if (commandLine.size() > 300) {
                commandLine.resize(300);
                commandLine += "...";
            }
            finding.description = reason + ": " + commandLine;
            finding.basis.push_back(ObservationSource::SyscallTrace);
            finding.pids.push_back(process.pid);
            findings.push_back(std::move(finding));
        }
    }
    return findings;
}

std::vector<std::filesystem::path> hostPersistencePaths(const std::filesystem::path& home)
{
    std::vector<std::filesystem::path> paths;
    if (!home.empty()) {
        for (const auto* rel : {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zshenv", ".zprofile",
                                ".config/autostart", ".config/systemd/user", ".config/environment.d",
                                ".local/share/systemd/user", ".config/fish/config.fish", ".ssh/authorized_keys"}) {
            paths.push_back(home / rel);
        }
    }
    for (const auto* abs : {"/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/bashrc", "/etc/environment",
                            "/etc/systemd/system", "/etc/systemd/user", "/etc/xdg/autostart", "/etc/cron.d",
                            "/etc/crontab", "/etc/ld.so.preload", "/etc/sudoers.d"}) {
        paths.emplace_back(abs);
    }
    return paths;
}

}  // namespace tracepot
