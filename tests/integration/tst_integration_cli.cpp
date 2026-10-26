// Runs the real `tracepot` executable and checks exit codes and produced files.

#include "common/TestSupport.hpp"
#include "core/reporting/ReportJson.hpp"
#include "core/sandbox/Readiness.hpp"

#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>

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
