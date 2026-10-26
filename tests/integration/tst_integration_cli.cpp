// Runs the real `tracepot` executable and checks exit codes and produced files.

#include "common/TestSupport.hpp"
#include "core/reporting/ReportJson.hpp"
#include "core/sandbox/Readiness.hpp"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>

using namespace tracepot;
namespace fs = std::filesystem;

class TestIntegrationCli : public QObject {
    Q_OBJECT

private:
    QTemporaryDir work_;
    bool ready_ = false;

    struct Run {
        int exitCode = -1;
        QString out;
        QString err;
    };

    Run tracepot(const QStringList& args, int timeoutMs = 120000)
    {
        QProcess process;
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(QStringLiteral("XDG_CACHE_HOME"), work_.path() + QStringLiteral("/cache"));
        process.setProcessEnvironment(env);
        process.setWorkingDirectory(work_.path());
        process.start(QStringLiteral(TRACEPOT_CLI_PATH), args);
        if (!process.waitForFinished(timeoutMs)) {
            process.kill();
            process.waitForFinished();
        }
        return {process.exitCode(), QString::fromUtf8(process.readAllStandardOutput()),
                QString::fromUtf8(process.readAllStandardError())};
    }

private slots:
    void initTestCase()
    {
        const auto readiness = checkReadiness();
        ready_ = readiness.sandboxReady() && readiness.tracingReady();
    }

    void versionAndHelp()
    {
        auto version = tracepot({QStringLiteral("version")});
        QCOMPARE(version.exitCode, 0);
        QVERIFY(version.out.startsWith(QStringLiteral("TracePot ")));
        auto help = tracepot({QStringLiteral("help")});
        QCOMPARE(help.exitCode, 0);
        QVERIFY(help.out.contains(QStringLiteral("tracepot analyze")));
    }

    void usageErrors()
    {
        QCOMPARE(tracepot({QStringLiteral("analyze")}).exitCode, 1);
        QCOMPARE(tracepot({QStringLiteral("analyze"), QStringLiteral("x.sh"), QStringLiteral("--bogus")}).exitCode, 1);
        QCOMPARE(tracepot({QStringLiteral("nonsense")}).exitCode, 1);
    }

    void checkCommand()
    {
        auto check = tracepot({QStringLiteral("check"), QStringLiteral("--json")});
        QCOMPARE(check.exitCode, ready_ ? 0 : 3);
        QVERIFY(check.out.contains(QStringLiteral("\"sandboxReady\"")));
    }

    void rejectsUnsupportedInput()
    {
        auto elf = tracepot({QStringLiteral("analyze"), QStringLiteral("/usr/bin/true")});
        QCOMPARE(elf.exitCode, ready_ ? 2 : 3);
        QVERIFY(elf.err.contains(QStringLiteral("error")));
    }

    void analyzeAndReport()
    {
        if (!ready_) {
            QSKIP("sandbox/tracer not available on this host");
        }
        const QString output = work_.path() + QStringLiteral("/results");
        auto analyze = tracepot({QStringLiteral("analyze"),
                                 QString::fromStdString(test::fixtureScript("child_process.sh").string()),
                                 QStringLiteral("--timeout"), QStringLiteral("60"), QStringLiteral("--output"), output,
                                 QStringLiteral("--quiet")});
        QVERIFY2(analyze.exitCode == 0, qPrintable(analyze.err));
        QVERIFY(analyze.out.contains(QStringLiteral("exited with status 4")));
        const fs::path latest = output.toStdString() + "/latest.json";
        QVERIFY(fs::exists(latest));
        auto report = loadReportFile(latest);
        QVERIFY(report.ok());
        QVERIFY(fs::exists(output.toStdString() + "/" + report->analysisId + ".html"));
        QVERIFY(fs::exists(output.toStdString() + "/" + report->analysisId + ".json"));
        // The CLI never leaves workspaces behind.
        QVERIFY(fs::is_empty(work_.path().toStdString() + "/cache/tracepot/runs"));

        auto summary = tracepot({QStringLiteral("report"), QString::fromStdString(latest.string())});
        QCOMPARE(summary.exitCode, 0);
        QVERIFY(summary.out.contains(QString::fromStdString(report->analysisId)));
        const QString html = work_.path() + QStringLiteral("/converted.html");
        auto convert = tracepot({QStringLiteral("report"), QString::fromStdString(latest.string()), QStringLiteral("--html"), html});
        QCOMPARE(convert.exitCode, 0);
        QVERIFY(fs::exists(html.toStdString()));
    }

    void timeoutExitCode()
    {
        if (!ready_) {
            QSKIP("sandbox/tracer not available on this host");
        }
        auto run = tracepot({QStringLiteral("analyze"), QString::fromStdString(test::fixtureScript("sleep_long.sh").string()),
                             QStringLiteral("--timeout"), QStringLiteral("1"), QStringLiteral("--output"),
                             work_.path() + QStringLiteral("/timeout"), QStringLiteral("--quiet"), QStringLiteral("--no-html")});
        QCOMPARE(run.exitCode, 6);
        QVERIFY(run.out.contains(QStringLiteral("timeout")));
    }

    void killedCliLeavesNoSandboxBehind()
    {
        if (!ready_) {
            QSKIP("sandbox/tracer not available on this host");
        }
        const QString script = QString::fromStdString(test::fixtureScript("sleep_long.sh").string());
        QProcess process;
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(QStringLiteral("XDG_CACHE_HOME"), work_.path() + QStringLiteral("/crash-cache"));
        process.setProcessEnvironment(env);
        process.start(QStringLiteral(TRACEPOT_CLI_PATH),
                      {QStringLiteral("analyze"), script, QStringLiteral("--timeout"), QStringLiteral("120"),
                       QStringLiteral("--output"), work_.path() + QStringLiteral("/crash"), QStringLiteral("--quiet")});
        QVERIFY(process.waitForStarted());
        // Matches every process whose command line mentions the sandboxed script: bubblewrap and
        // the shell running inside the sandbox.
        auto sandboxedPids = []() {
            QList<int> pids;
            for (const auto& entry : QDir(QStringLiteral("/proc")).entryList(QDir::Dirs)) {
                bool numeric = false;
                const int pid = entry.toInt(&numeric);
                QFile cmdline(QStringLiteral("/proc/%1/cmdline").arg(entry));
                if (numeric && cmdline.open(QIODevice::ReadOnly) &&
                    cmdline.readAll().contains("/work/sleep_long.sh")) {
                    QFile stat(QStringLiteral("/proc/%1/stat").arg(entry));
                    if (stat.open(QIODevice::ReadOnly)) {
                        const QByteArray content = stat.readAll();
                        const int close = content.lastIndexOf(')');
                        if (close > 0 && close + 2 < content.size() && content.at(close + 2) != 'Z') {
                            pids << pid;
                        }
                    }
                }
            }
            return pids;
        };
        // Kill as soon as bubblewrap appears: this deliberately hits the start-up window in which
        // bubblewrap has not yet armed its own parent-death handling.
        QTRY_VERIFY_WITH_TIMEOUT(!sandboxedPids().isEmpty(), 20000);
        process.kill();  // SIGKILL: TracePot gets no chance to clean up
        QVERIFY(process.waitForFinished(10000));
        // PR_SET_PDEATHSIG (TracePot -> strace -> launcher/bwrap) and bubblewrap's
        // --die-with-parent take the whole sandbox down.
        QElapsedTimer waited;
        waited.start();
        while (!sandboxedPids().isEmpty() && waited.elapsed() < 10000) {
            QTest::qWait(100);
        }
        if (!sandboxedPids().isEmpty()) {
            QString survivors;
            for (const int pid : sandboxedPids()) {
                QFile stat(QStringLiteral("/proc/%1/stat").arg(pid));
                stat.open(QIODevice::ReadOnly);
                survivors += QString::fromUtf8(stat.readAll()) + QLatin1Char('\n');
            }
            QFAIL(qPrintable(QStringLiteral("sandbox processes survived:\n") + survivors));
        }

        // The abandoned workspace is unlocked and removed by the next analysis.
        const QString runs = work_.path() + QStringLiteral("/crash-cache/tracepot/runs");
        QCOMPARE(QDir(runs).entryList(QDir::Dirs | QDir::NoDotAndDotDot).size(), 1);
        QProcess next;
        next.setProcessEnvironment(env);
        next.start(QStringLiteral(TRACEPOT_CLI_PATH),
                   {QStringLiteral("analyze"), QString::fromStdString(test::fixtureScript("create_file.sh").string()),
                    QStringLiteral("--output"), work_.path() + QStringLiteral("/crash"), QStringLiteral("--quiet"),
                    QStringLiteral("--no-html")});
        QVERIFY(next.waitForFinished(120000));
        QCOMPARE(next.exitCode(), 0);
        QVERIFY(QDir(runs).entryList(QDir::Dirs | QDir::NoDotAndDotDot).isEmpty());
        auto report = loadReportFile(work_.path().toStdString() + "/crash/latest.json");
        QVERIFY(report.ok());
        QVERIFY(std::any_of(report->diagnostics.begin(), report->diagnostics.end(),
                            [](const Diagnostic& d) { return d.code == "stale-workspaces"; }));
    }

    void invalidReport()
    {
        const fs::path bogus = work_.path().toStdString() + "/bogus.json";
        test::writeFile(bogus, "{\"schema\": \"something-else\"}");
        auto run = tracepot({QStringLiteral("report"), QString::fromStdString(bogus.string())});
        QCOMPARE(run.exitCode, 2);
        QVERIFY(run.err.contains(QStringLiteral("not a TracePot report")));
    }
};

QTEST_GUILESS_MAIN(TestIntegrationCli)
#include "tst_integration_cli.moc"
