// End-to-end tests: purpose-built, harmless fixtures run inside the real sandbox and the resulting
// reports are checked for the specific observations each fixture must produce. Skipped (not
// failed) on hosts where the sandbox or tracer is unavailable.

#include "common/TestSupport.hpp"
#include "core/analysis/Analyzer.hpp"
#include "core/util/Sha256.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>
#include <functional>

using namespace tracepot;
namespace fs = std::filesystem;

namespace {

const FileChange* findChange(const AnalysisReport& r, const std::string& path)
{
    for (const auto& c : r.filesystemChanges) {
        if (c.path == path) {
            return &c;
        }
    }
    return nullptr;
}

// Finds the process that successfully executed `exe` at any point (a process can exec repeatedly).
const ProcessRecord* findProcessByExe(const AnalysisReport& r, const std::string& exe)
{
    for (const auto& p : r.processes) {
        for (const auto& exec : p.execs) {
            if (exec.path == exe && exec.outcome == Outcome::Success) {
                return &p;
            }
        }
    }
    return nullptr;
}

const PersistenceFinding* findPersistence(const AnalysisReport& r, const std::string& path)
{
    for (const auto& f : r.persistence) {
        if (f.path == path) {
            return &f;
        }
    }
    return nullptr;
}

bool hasAspect(const FileChange& c, const std::string& aspect)
{
    return std::find(c.aspects.begin(), c.aspects.end(), aspect) != c.aspects.end();
}

}  // namespace

class TestIntegrationAnalysis : public QObject {
    Q_OBJECT

private:
    std::optional<Readiness> readiness_;
    QTemporaryDir workspaceBase_;
    QTemporaryDir fakeHome_;
    QTemporaryDir inputs_;

    Result<AnalysisReport> analyze(const fs::path& input, const std::function<void(AnalysisConfig&)>& configure = {},
                                   const ProgressCallback& progress = {}, CancellationToken* token = nullptr)
    {
        AnalysisConfig config;
        config.inputPath = input;
        config.workspaceBase = workspaceBase_.path().toStdString();
        config.hostHome = fakeHome_.path().toStdString();
        config.limits.timeoutSeconds = 60;
        if (configure) {
            configure(config);
        }
        Analyzer analyzer(config);
        analyzer.setReadiness(*readiness_);
        CancellationToken local;
        return analyzer.run(token != nullptr ? *token : local, progress);
    }

    static void expectReport(const Result<AnalysisReport>& result)
    {
        QVERIFY2(result.ok(), result.ok() ? "" : result.error().describe().c_str());
        QVERIFY(result->sandbox.tracingEnabled);
        // Nothing may ever reach the (fake) host home or the host's system persistence locations.
        QVERIFY(result->hostIntegrity.performed);
        QVERIFY2(result->hostIntegrity.changes.empty(), result->hostIntegrity.changes.empty()
                                                             ? ""
                                                             : result->hostIntegrity.changes.front().path.c_str());
    }

private slots:
    void initTestCase()
    {
        readiness_ = checkReadiness();
        if (!(readiness_->sandboxReady() && readiness_->tracingReady())) {
            QSKIP(qPrintable(QStringLiteral("sandbox/tracer not available on this host:\n") +
                             QString::fromStdString(readiness_->failureSummary(true))));
        }
        test::writeFile(fs::path(fakeHome_.path().toStdString()) / ".bashrc", "# fake host bashrc\n");
    }

    void fileCreation()
    {
        const auto result = analyze(test::fixtureScript("create_file.sh"));
        expectReport(result);
        const auto& r = result.value();
        QCOMPARE(r.execution.reason, TerminationReason::Exited);
        QCOMPARE(*r.execution.exitCode, 0);
        const auto* created = findChange(r, "/work/created.txt");
        QVERIFY(created != nullptr);
        QCOMPARE(created->kind, ChangeKind::Created);
        QCOMPARE(QString::fromStdString(*created->after->sha256),
                 QString::fromStdString(sha256Hex("created by TracePot fixture\n")));
        QVERIFY(!created->attributedPids.empty());  // the trace saw the writing process
        QVERIFY(findChange(r, "/work/ünï cödé.txt") != nullptr);
        QCOMPARE(QString::fromStdString(r.input.sha256),
                 QString::fromStdString(sha256File(test::fixtureScript("create_file.sh")).value()));
    }

    void fileModificationDeletionAndPermissions()
    {
        const fs::path archive = fs::path(inputs_.path().toStdString()) / "modify.tar.gz";
        QVERIFY(test::ArchiveBuilder()
                    .directory("tracepot-fixture")
                    .file("tracepot-fixture/install.sh",
                          "#!/bin/sh\ncd \"$(dirname \"$0\")\"\necho version=2 > config.txt\nrm remove-me.txt\n"
                          "chmod 700 tool.sh\n",
                          0755)
                    .file("tracepot-fixture/config.txt", "version=1\n")
                    .file("tracepot-fixture/remove-me.txt", "bye\n")
                    .file("tracepot-fixture/tool.sh", "#!/bin/sh\n", 0755)
                    .write(archive));
        const auto result = analyze(archive);
        expectReport(result);
        const auto& r = result.value();
        QVERIFY(r.input.archive.has_value());
        QCOMPARE(r.input.archive->entryCount, std::uint64_t{5});
        QCOMPARE(QString::fromStdString(r.input.entryPoint), QStringLiteral("/work/tracepot-fixture/install.sh"));

        const auto* modified = findChange(r, "/work/tracepot-fixture/config.txt");
        QVERIFY(modified != nullptr);
        QCOMPARE(modified->kind, ChangeKind::Modified);
        QVERIFY(hasAspect(*modified, "content"));
        QVERIFY(modified->textDiff.has_value());
        QVERIFY(modified->textDiff->find("-version=1\n+version=2") != std::string::npos);

        const auto* deleted = findChange(r, "/work/tracepot-fixture/remove-me.txt");
        QVERIFY(deleted != nullptr);
        QCOMPARE(deleted->kind, ChangeKind::Deleted);

        const auto* chmodded = findChange(r, "/work/tracepot-fixture/tool.sh");
        QVERIFY(chmodded != nullptr);
        QVERIFY(hasAspect(*chmodded, "permissions"));
        QCOMPARE(chmodded->before->mode, 0755u);
        QCOMPARE(chmodded->after->mode, 0700u);
        QVERIFY(std::any_of(r.events.begin(), r.events.end(), [](const TraceEvent& e) {
            return e.type == EventType::PermissionChange && e.path == "/work/tracepot-fixture/tool.sh" &&
                   e.detail == "0700";
        }));
    }

    void directoriesAndSymlinks()
    {
        const auto result = analyze(test::fixtureScript("dirs_and_links.sh"));
        expectReport(result);
        const auto& r = result.value();
        const auto* nested = findChange(r, "/work/nested/deeper");
        QVERIFY(nested != nullptr);
        QCOMPARE(nested->after->type, FileType::Directory);
        const auto* link = findChange(r, "/work/nested/link");
        QVERIFY(link != nullptr);
        QCOMPARE(link->after->type, FileType::Symlink);
        QCOMPARE(QString::fromStdString(link->after->linkTarget), QStringLiteral("../link-target.txt"));
        QVERIFY(std::any_of(r.events.begin(), r.events.end(), [](const TraceEvent& e) {
            return e.type == EventType::SymlinkCreate && e.path == "/work/nested/link";
        }));
    }

    void childProcessExecution()
    {
        const auto result = analyze(test::fixtureScript("child_process.sh"));
        expectReport(result);
        const auto& r = result.value();
        QCOMPARE(*r.execution.exitCode, 4);
        QCOMPARE(r.execution.reason, TerminationReason::Exited);
        const ProcessRecord* entry = nullptr;
        for (const auto& p : r.processes) {
            if (!p.ppid) {
                entry = &p;
            }
        }
        QVERIFY(entry != nullptr);
        QCOMPARE(*entry->exitCode, 4);
        const auto* env = findProcessByExe(r, "/usr/bin/env");
        QVERIFY(env != nullptr);
        QCOMPARE(*env->ppid, entry->pid);
        QCOMPARE(QString::fromStdString(env->execs.front().argv.at(1)), QStringLiteral("true"));
        // env replaced itself with true: same process, later exec (after PATH lookups that failed).
        QCOMPARE(findProcessByExe(r, "/usr/bin/true"), env);
        QCOMPARE(QString::fromStdString(env->executable()), QStringLiteral("/usr/bin/true"));
        bool sawChildShell = false;
        for (const auto& p : r.processes) {
            const auto argv = p.argv();
            if (argv.size() >= 3 && argv[1] == "-c" && argv[2] == "echo from-child") {
                sawChildShell = true;
                QCOMPARE(*p.ppid, entry->pid);
            }
        }
        QVERIFY(sawChildShell);
        QVERIFY(findChange(r, "/work/child-output.txt") != nullptr);
    }

    void networkAttemptsUnderIsolation()
    {
        if (::access("/usr/bin/bash", X_OK) != 0) {
            QSKIP("bash is required for /dev/tcp");
        }
        const auto result = analyze(test::fixtureScript("network_attempts.sh"));
        expectReport(result);
        const auto& r = result.value();
        QCOMPARE(QString::fromStdString(r.networkPolicy.mode), QStringLiteral("isolated"));
        QVERIFY(!r.networkPolicy.externalConnectivity);
        const auto connect = std::find_if(r.networkEvents.begin(), r.networkEvents.end(), [](const NetworkEvent& n) {
            return n.kind == NetworkEventKind::Connect && n.address == "198.51.100.7";
        });
        QVERIFY(connect != r.networkEvents.end());
        QCOMPARE(*connect->port, 443);
        QCOMPARE(connect->outcome, Outcome::Failed);
        QCOMPARE(QString::fromStdString(connect->error), QStringLiteral("ENETUNREACH"));
        QCOMPARE(connect->evidence, EvidenceKind::Observed);
        const bool sawDns = std::any_of(r.networkEvents.begin(), r.networkEvents.end(), [](const NetworkEvent& n) {
            return n.kind == NetworkEventKind::DnsQuery && n.hostname == "tracepot-fixture.invalid";
        });
        QVERIFY(sawDns);
    }

    void userPersistenceStaysInSandbox()
    {
        const auto result = analyze(test::fixtureScript("user_persistence.sh"));
        expectReport(result);
        const auto& r = result.value();
        const auto* autostart = findPersistence(r, "/home/tracepot/.config/autostart/tracepot-fixture.desktop");
        QVERIFY(autostart != nullptr);
        QCOMPARE(autostart->category, PersistenceCategory::XdgAutostart);
        QCOMPARE(QString::fromStdString(autostart->outcome), QStringLiteral("applied-in-sandbox"));
        const auto* unit = findPersistence(r, "/home/tracepot/.config/systemd/user/tracepot-fixture.service");
        QVERIFY(unit != nullptr);
        QCOMPARE(unit->category, PersistenceCategory::SystemdUnit);
        QCOMPARE(QString::fromStdString(unit->scope), QStringLiteral("user"));
        const auto* bashrc = findPersistence(r, "/home/tracepot/.bashrc");
        QVERIFY(bashrc != nullptr);
        QVERIFY(std::find(bashrc->basis.begin(), bashrc->basis.end(), ObservationSource::SyscallTrace) != bashrc->basis.end());
        // The fake host home was not touched.
        const fs::path home = fakeHome_.path().toStdString();
        QVERIFY(!fs::exists(home / ".config/autostart"));
        QCOMPARE(test::readFile(home / ".bashrc"), std::string("# fake host bashrc\n"));
    }

    void systemPersistenceInSimulatedRoot()
    {
        const auto result = analyze(test::fixtureScript("system_persistence.sh"),
                                    [](AnalysisConfig& c) { c.user = SandboxUser::SimulatedRoot; });
        expectReport(result);
        const auto& r = result.value();
        QCOMPARE(r.sandbox.user, SandboxUser::SimulatedRoot);
        const auto* unit = findPersistence(r, "/etc/systemd/system/tracepot-fixture.service");
        QVERIFY(unit != nullptr);
        QCOMPARE(QString::fromStdString(unit->scope), QStringLiteral("system"));
        QCOMPARE(QString::fromStdString(unit->outcome), QStringLiteral("applied-in-sandbox"));
        const auto* cron = findPersistence(r, "/etc/cron.d/tracepot-fixture");
        QVERIFY(cron != nullptr);
        QCOMPARE(cron->category, PersistenceCategory::Cron);
        QVERIFY(!fs::exists("/etc/systemd/system/tracepot-fixture.service"));
        QVERIFY(!fs::exists("/etc/cron.d/tracepot-fixture"));
    }

    void systemPersistenceBlockedWhenUnprivileged()
    {
        const auto result = analyze(test::fixtureScript("system_persistence.sh"));
        expectReport(result);
        const auto& r = result.value();
        const auto* cron = findPersistence(r, "/etc/cron.d/tracepot-fixture");
        QVERIFY(cron != nullptr);
        QVERIFY2(QString::fromStdString(cron->outcome).startsWith(QStringLiteral("attempt-failed")), cron->outcome.c_str());
        QVERIFY(findChange(r, "/etc/cron.d/tracepot-fixture") == nullptr);
        QVERIFY(r.execution.stdoutExcerpt.find("cron not written") != std::string::npos);
    }

    void timeoutTerminatesSandbox()
    {
        QElapsedTimer timer;
        timer.start();
        const auto result = analyze(test::fixtureScript("sleep_long.sh"), [](AnalysisConfig& c) { c.limits.timeoutSeconds = 2; });
        expectReport(result);
        const auto& r = result.value();
        QCOMPARE(r.execution.reason, TerminationReason::Timeout);
        QVERIFY(r.execution.executionSeconds >= 2.0 && r.execution.executionSeconds < 10.0);
        QVERIFY(timer.elapsed() < 30000);
        QVERIFY(std::any_of(r.resourceLimitEvents.begin(), r.resourceLimitEvents.end(),
                            [](const ResourceLimitEvent& e) { return e.limit == "wall-clock-timeout"; }));
        const auto* sleep = findProcessByExe(r, "/usr/bin/sleep");
        QVERIFY(sleep != nullptr);
        QCOMPARE(QString::fromStdString(sleep->signal), QStringLiteral("SIGKILL"));
        QVERIFY(r.execution.stdoutExcerpt.find("started") != std::string::npos);
        QVERIFY(r.execution.stdoutExcerpt.find("finished") == std::string::npos);
    }

    void cancellationProducesPartialReport()
    {
        CancellationToken token;
        const auto result = analyze(
            test::fixtureScript("sleep_long.sh"), {},
            [&token](const ProgressUpdate& update) {
                if (update.stage == AnalysisStage::Running && update.elapsedSeconds > 0.5) {
                    token.cancel();
                }
            },
            &token);
        expectReport(result);
        QCOMPARE(result->execution.reason, TerminationReason::Cancelled);
        QVERIFY(result->execution.executionSeconds < 10.0);
        QVERIFY(findProcessByExe(result.value(), "/usr/bin/sleep") != nullptr);
    }

    void cancellationBeforeStart()
    {
        CancellationToken token;
        token.cancel();
        const auto result = analyze(test::fixtureScript("create_file.sh"), {}, {}, &token);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::Cancelled);
    }

    void backgroundProcessesTornDown()
    {
        QElapsedTimer timer;
        timer.start();
        const auto result = analyze(test::fixtureScript("background_process.sh"));
        expectReport(result);
        QVERIFY(timer.elapsed() < 30000);  // the 300 s background sleep did not keep the run alive
        const auto* sleep = findProcessByExe(result.value(), "/usr/bin/sleep");
        QVERIFY(sleep != nullptr);
        QVERIFY(sleep->terminatedAtTeardown);
        QCOMPARE(result->execution.reason, TerminationReason::Exited);
    }

    void hostIsNotVisibleInsideSandbox()
    {
        const fs::path marker = fs::path(inputs_.path().toStdString()) / "host-marker.txt";
        test::writeFile(marker, "host data");
        const std::string home = fakeHome_.path().toStdString();
        const auto result = analyze(test::fixtureScript("isolation_probe.sh"), [&](AnalysisConfig& c) {
            c.arguments = {marker.string(), home, "/run/dbus/system_bus_socket", "/sys/kernel"};
        });
        expectReport(result);
        const auto* probe = findChange(result.value(), "/work/probe-result.txt");
        QVERIFY(probe != nullptr && probe->textDiff.has_value());
        const std::string& diff = *probe->textDiff;
        QVERIFY2(diff.find("visible") == std::string::npos, diff.c_str());
        QVERIFY(diff.find("+absent " + marker.string()) != std::string::npos);
        QVERIFY(diff.find("+tracepot-sandbox") != std::string::npos);
    }

    void fileSizeLimitEnforced()
    {
        const auto result = analyze(test::fixtureScript("large_file.sh"),
                                    [](AnalysisConfig& c) { c.limits.maxFileSizeBytes = 1 * MiB; });
        expectReport(result);
        const auto& r = result.value();
        QVERIFY(std::any_of(r.resourceLimitEvents.begin(), r.resourceLimitEvents.end(),
                            [](const ResourceLimitEvent& e) { return e.limit == "file-size"; }));
        const auto* large = findChange(r, "/work/large.bin");
        QVERIFY(large != nullptr);
        QVERIFY(large->after->size <= 1 * MiB);
        const auto* head = findProcessByExe(r, "/usr/bin/head");
        QVERIFY(head != nullptr);
        QCOMPARE(QString::fromStdString(head->signal), QStringLiteral("SIGXFSZ"));
    }

    void maliciousArchivesAreNeverExecuted()
    {
        const fs::path dir = inputs_.path().toStdString();
        const std::string payload = "#!/bin/sh\necho executed > /work/executed.txt\n";
        struct Case {
            std::string name;
            test::ArchiveBuilder builder;
            ErrorCode expected;
        };
        std::vector<Case> cases;
        cases.push_back({"traversal", test::ArchiveBuilder().file("install.sh", payload).file("../../escape.txt", "x"),
                         ErrorCode::ArchiveUnsafe});
        cases.push_back({"absolute", test::ArchiveBuilder().file("install.sh", payload).file("/tmp/tracepot-abs.txt", "x"),
                         ErrorCode::ArchiveUnsafe});
        cases.push_back({"symlink", test::ArchiveBuilder().file("install.sh", payload).symlink("etc", "/etc"),
                         ErrorCode::ArchiveUnsafe});
        cases.push_back({"through-link",
                         test::ArchiveBuilder().file("install.sh", payload).directory("d").symlink("l", "d").file("l/x", "x"),
                         ErrorCode::ArchiveUnsafe});
        cases.push_back({"device", test::ArchiveBuilder().file("install.sh", payload).charDevice("null"),
                         ErrorCode::ArchiveUnsafe});
        cases.push_back({"no-entry", test::ArchiveBuilder().file("README", "x"), ErrorCode::EntryPointNotFound});
        for (const auto& c : cases) {
            const fs::path archive = dir / (c.name + ".tar.gz");
            QVERIFY(c.builder.write(archive));
            const auto result = analyze(archive);
            QVERIFY2(!result.ok(), c.name.c_str());
            QCOMPARE(result.error().code, c.expected);
        }
        QVERIFY(!fs::exists("/tmp/tracepot-abs.txt"));
        QVERIFY(!fs::exists(dir.parent_path() / "escape.txt"));

        // Corrupted compressed stream.
        const fs::path good = dir / "good-for-corruption.tar.gz";
        QVERIFY(test::ArchiveBuilder().file("install.sh", payload).file("blob", std::string(200000, 'z')).write(good));
        const std::string bytes = test::readFile(good);
        const fs::path corrupt = dir / "corrupt.tar.gz";
        test::writeFile(corrupt, bytes.substr(0, bytes.size() / 2));
        const auto result = analyze(corrupt);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveMalformed);
    }

    void unsupportedInputsRejected()
    {
        auto elf = analyze("/usr/bin/true");
        QVERIFY(!elf.ok());
        QCOMPARE(elf.error().code, ErrorCode::UnsupportedInput);
        const fs::path python = fs::path(inputs_.path().toStdString()) / "tool.py";
        test::writeFile(python, "#!/usr/bin/env python3\nprint('x')\n");
        auto py = analyze(python);
        QVERIFY(!py.ok());
        QCOMPARE(py.error().code, ErrorCode::UnsupportedInput);
    }

    void workspacesAreCleanedUp()
    {
        QVERIFY(fs::is_empty(workspaceBase_.path().toStdString()));
    }
};

QTEST_GUILESS_MAIN(TestIntegrationAnalysis)
#include "tst_integration_analysis.moc"
