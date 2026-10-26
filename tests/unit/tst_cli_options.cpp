#include "cli/CliOptions.hpp"

#include <QtTest>

using namespace tracepot;
using namespace tracepot::cli;

class TestCliOptions : public QObject {
    Q_OBJECT

private slots:
    void commands()
    {
        QCOMPARE(parseCommandLine({}).value().command, Command::Help);
        QCOMPARE(parseCommandLine({"--help"}).value().command, Command::Help);
        QCOMPARE(parseCommandLine({"version"}).value().command, Command::Version);
        auto check = parseCommandLine({"check", "--json"});
        QCOMPARE(check->command, Command::Check);
        QVERIFY(check->json);
        auto report = parseCommandLine({"report", "results/latest.json", "--html", "out.html"});
        QCOMPARE(report->command, Command::Report);
        QCOMPARE(QString::fromStdString(report->reportPath.string()), QStringLiteral("results/latest.json"));
        QCOMPARE(QString::fromStdString(report->htmlOutput.string()), QStringLiteral("out.html"));
    }

    void analyzeOptions()
    {
        auto parsed = parseCommandLine({"analyze", "./package.tar.gz", "--timeout", "60", "--entry", "pkg/install.sh",
                                        "--arg", "--prefix=/opt", "--env", "FOO=a=b", "--as-root", "--memory", "512",
                                        "--max-processes", "64", "--max-file-size", "16", "--max-disk", "100",
                                        "--persistence-pattern", "~/.myrc", "--output", "out", "--no-html",
                                        "--keep-workspace", "--quiet", "--", "--literal", "-x"});
        QVERIFY2(parsed.ok(), parsed.ok() ? "" : parsed.error().message.c_str());
        const auto& o = parsed.value();
        const auto& c = o.analysis;
        QCOMPARE(o.command, Command::Analyze);
        QCOMPARE(QString::fromStdString(c.inputPath.string()), QStringLiteral("./package.tar.gz"));
        QCOMPARE(c.limits.timeoutSeconds, 60);
        QCOMPARE(QString::fromStdString(c.entryPoint), QStringLiteral("pkg/install.sh"));
        QCOMPARE(c.arguments, (std::vector<std::string>{"--prefix=/opt", "--literal", "-x"}));
        QCOMPARE(c.environment.size(), std::size_t{1});
        QCOMPARE(QString::fromStdString(c.environment.front().second), QStringLiteral("a=b"));
        QCOMPARE(c.user, SandboxUser::SimulatedRoot);
        QCOMPARE(c.limits.memoryBytes, 512 * MiB);
        QCOMPARE(c.limits.maxProcesses, 64u);
        QCOMPARE(c.limits.maxFileSizeBytes, 16 * MiB);
        QCOMPARE(c.limits.maxDiskBytes, 100 * MiB);
        QCOMPARE(c.extraPersistencePatterns.size(), std::size_t{1});
        QVERIFY(c.keepWorkspace);
        QVERIFY(c.requireTracing);
        QVERIFY(!o.writeHtml);
        QVERIFY(o.quiet);
        QCOMPARE(QString::fromStdString(o.outputDir.string()), QStringLiteral("out"));
    }

    void defaults()
    {
        auto parsed = parseCommandLine({"analyze", "installer.sh"});
        QVERIFY(parsed.ok());
        QCOMPARE(parsed->analysis.limits.timeoutSeconds, 120);
        QCOMPARE(parsed->analysis.user, SandboxUser::Unprivileged);
        QCOMPARE(QString::fromStdString(parsed->outputDir.string()), QStringLiteral("tracepot-results"));
        QVERIFY(parsed->writeHtml);
    }

    void errors_data()
    {
        QTest::addColumn<QStringList>("args");
        QTest::newRow("unknown command") << QStringList{"frobnicate"};
        QTest::newRow("missing input") << QStringList{"analyze"};
        QTest::newRow("two inputs") << QStringList{"analyze", "a.sh", "b.sh"};
        QTest::newRow("unknown option") << QStringList{"analyze", "a.sh", "--bogus"};
        QTest::newRow("bad timeout") << QStringList{"analyze", "a.sh", "--timeout", "abc"};
        QTest::newRow("zero timeout") << QStringList{"analyze", "a.sh", "--timeout", "0"};
        QTest::newRow("negative") << QStringList{"analyze", "a.sh", "--memory", "-5"};
        QTest::newRow("missing value") << QStringList{"analyze", "a.sh", "--timeout"};
        QTest::newRow("bad env") << QStringList{"analyze", "a.sh", "--env", "NOVALUE"};
        QTest::newRow("relative pattern") << QStringList{"analyze", "a.sh", "--persistence-pattern", "etc/x"};
        QTest::newRow("check args") << QStringList{"check", "extra"};
        QTest::newRow("report missing") << QStringList{"report"};
    }

    void errors()
    {
        QFETCH(QStringList, args);
        std::vector<std::string> argv;
        for (const auto& a : args) {
            argv.push_back(a.toStdString());
        }
        QVERIFY(!parseCommandLine(argv).ok());
    }
};

QTEST_GUILESS_MAIN(TestCliOptions)
#include "tst_cli_options.moc"
