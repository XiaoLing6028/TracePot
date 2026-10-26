#include "core/analysis/Persistence.hpp"

#include <QtTest>

using namespace tracepot;

namespace {

FileChange change(const std::string& path, ChangeKind kind, FileType type = FileType::Regular)
{
    FileChange c;
    c.path = path;
    c.kind = kind;
    FileMetadata meta;
    meta.type = type;
    if (kind == ChangeKind::Deleted) {
        c.before = meta;
    } else {
        c.after = meta;
    }
    return c;
}

TraceEvent writeEvent(int pid, const std::string& path, Outcome outcome, const std::string& error = {})
{
    TraceEvent e;
    e.pid = pid;
    e.type = EventType::FileWrite;
    e.syscall = "openat";
    e.path = path;
    e.outcome = outcome;
    e.error = error;
    return e;
}

ProcessRecord process(int pid, std::vector<std::string> argv)
{
    ProcessRecord p;
    p.pid = pid;
    ExecRecord exec;
    exec.path = argv.front();
    exec.argv = std::move(argv);
    exec.outcome = Outcome::Success;
    p.execs.push_back(exec);
    return p;
}

}  // namespace

class TestPersistence : public QObject {
    Q_OBJECT

private slots:
    void ruleMatching_data()
    {
        QTest::addColumn<QString>("path");
        QTest::addColumn<QString>("category");
        QTest::addColumn<QString>("scope");
        QTest::newRow("bashrc") << "/home/tracepot/.bashrc" << "shell-startup" << "user";
        QTest::newRow("root profile") << "/root/.profile" << "shell-startup" << "user";
        QTest::newRow("profile.d") << "/etc/profile.d/tool.sh" << "shell-startup" << "system";
        QTest::newRow("autostart") << "/home/tracepot/.config/autostart/a.desktop" << "xdg-autostart" << "user";
        QTest::newRow("xdg system") << "/etc/xdg/autostart/a.desktop" << "xdg-autostart" << "system";
        QTest::newRow("user unit") << "/home/tracepot/.config/systemd/user/a.service" << "systemd-unit" << "user";
        QTest::newRow("system unit") << "/etc/systemd/system/multi-user.target.wants/a.service" << "systemd-unit"
                                     << "system";
        QTest::newRow("cron.d") << "/etc/cron.d/job" << "cron" << "system";
        QTest::newRow("user crontab") << "/var/spool/cron/crontabs/tracepot" << "cron" << "user";
        QTest::newRow("rc.local") << "/etc/rc.local" << "sysv-init" << "system";
        QTest::newRow("sudoers.d") << "/etc/sudoers.d/tool" << "sudoers" << "system";
        QTest::newRow("authorized_keys") << "/root/.ssh/authorized_keys" << "ssh-access" << "user";
        QTest::newRow("ld preload") << "/etc/ld.so.preload" << "dynamic-linker" << "system";
        QTest::newRow("apt source") << "/etc/apt/sources.list.d/vendor.list" << "package-repository" << "system";
    }

    void ruleMatching()
    {
        QFETCH(QString, path);
        QFETCH(QString, category);
        QFETCH(QString, scope);
        PersistenceClassifier classifier;
        const auto* rule = classifier.match(path.toStdString());
        QVERIFY2(rule != nullptr, qPrintable(path));
        QCOMPARE(QString::fromStdString(std::string(enumName(rule->category))), category);
        QCOMPARE(QString::fromStdString(rule->scope), scope);
    }

    void nonPersistencePathsDoNotMatch()
    {
        PersistenceClassifier classifier;
        for (const char* path : {"/home/tracepot/.local/bin/tool", "/home/tracepot/.config/app/settings.ini",
                                 "/work/install.sh", "/tmp/x", "/opt/vendor/bin/app", "/home/tracepot/.bashrc.bak"}) {
            QVERIFY2(classifier.match(path) == nullptr, path);
        }
    }

    void customPatterns()
    {
        PersistenceClassifier classifier({"/opt/vendor/hooks/**", "~/.vendorrc"});
        const auto* rule = classifier.match("/opt/vendor/hooks/start.sh");
        QVERIFY(rule != nullptr);
        QCOMPARE(rule->category, PersistenceCategory::Custom);
        QVERIFY(classifier.match("/home/tracepot/.vendorrc") != nullptr);
        QVERIFY(classifier.match("/root/.vendorrc") != nullptr);
        // Copying the classifier keeps its rules valid.
        const PersistenceClassifier copy = classifier;
        QVERIFY(copy.match("/opt/vendor/hooks/x") != nullptr);
    }

    void classifiesObservations()
    {
        PersistenceClassifier classifier;
        std::vector<FileChange> changes = {
            change("/home/tracepot/.config/autostart", ChangeKind::Created, FileType::Directory),
            change("/home/tracepot/.config/autostart/tool.desktop", ChangeKind::Created),
            change("/home/tracepot/.bashrc", ChangeKind::Modified),
            change("/work/notes.txt", ChangeKind::Created),
        };
        std::vector<TraceEvent> events = {
            writeEvent(10, "/home/tracepot/.bashrc", Outcome::Success),
            writeEvent(11, "/etc/cron.d/job", Outcome::Failed, "EROFS"),
            writeEvent(12, "/etc/cron.d/job", Outcome::Failed, "EROFS"),
            writeEvent(13, "/etc/profile.d/tmp.sh", Outcome::Success),  // written then removed
        };
        std::vector<ProcessRecord> processes = {
            process(20, {"/usr/bin/systemctl", "--user", "enable", "tool.service"}),
            process(21, {"/usr/bin/systemctl", "status"}),
            process(22, {"/usr/bin/crontab", "-l"}),
            process(23, {"/usr/bin/crontab", "/tmp/jobs"}),
        };
        const auto findings = classifier.classify(changes, events, processes);

        auto find = [&](const std::string& path, const std::string& outcomePrefix) -> const PersistenceFinding* {
            for (const auto& f : findings) {
                if (f.path == path && f.outcome.rfind(outcomePrefix, 0) == 0) {
                    return &f;
                }
            }
            return nullptr;
        };
        QCOMPARE(findings.size(), std::size_t{6});
        QVERIFY(find("/home/tracepot/.config/autostart", "") == nullptr);  // directories are not findings
        const auto* autostart = find("/home/tracepot/.config/autostart/tool.desktop", "applied-in-sandbox");
        QVERIFY(autostart != nullptr);
        QCOMPARE(autostart->category, PersistenceCategory::XdgAutostart);
        const auto* bashrc = find("/home/tracepot/.bashrc", "applied-in-sandbox");
        QVERIFY(bashrc != nullptr);
        QCOMPARE(bashrc->pids, std::vector<int>{10});
        QCOMPARE(bashrc->basis.size(), std::size_t{2});
        const auto* cron = find("/etc/cron.d/job", "attempt-failed");
        QVERIFY(cron != nullptr);
        QCOMPARE(cron->pids, (std::vector<int>{11, 12}));  // deduplicated into one finding
        QVERIFY(cron->outcome.find("EROFS") != std::string::npos);
        QVERIFY(find("/etc/profile.d/tmp.sh", "attempt-observed") != nullptr);
        const auto* systemctl = find("/usr/bin/systemctl", "command-executed");
        QVERIFY(systemctl != nullptr);
        QCOMPARE(QString::fromStdString(systemctl->scope), QStringLiteral("user"));
        QVERIFY(find("/usr/bin/crontab", "command-executed") != nullptr);
    }

    void hostPathsIncludeHomeAndSystemLocations()
    {
        const auto paths = hostPersistencePaths("/home/alice");
        auto contains = [&](const std::string& p) {
            return std::find(paths.begin(), paths.end(), std::filesystem::path(p)) != paths.end();
        };
        QVERIFY(contains("/home/alice/.bashrc"));
        QVERIFY(contains("/home/alice/.config/autostart"));
        QVERIFY(contains("/home/alice/.config/systemd/user"));
        QVERIFY(contains("/etc/systemd/system"));
        QVERIFY(contains("/etc/cron.d"));
    }
};

QTEST_GUILESS_MAIN(TestPersistence)
#include "tst_persistence.moc"
