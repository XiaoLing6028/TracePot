#include "common/TestSupport.hpp"
#include "core/sandbox/Readiness.hpp"
#include "gui/MainWindow.hpp"
#include "gui/widgets/ResultsView.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalSpy>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableView>
#include <QTemporaryDir>
#include <QTextBrowser>
#include <QtTest>

using namespace tracepot;
using namespace tracepot::gui;

class TestGuiMainWindow : public QObject {
    Q_OBJECT

private:
    QTemporaryDir tmp_;
    std::optional<Readiness> realReadiness_;

    static Readiness fakeReadiness()
    {
        Readiness r;
        r.bwrapPath = "/usr/bin/bwrap";
        r.helperPath = "/usr/libexec/tracepot/tracepot-limits";
        r.stracePath = "/usr/bin/strace";
        r.sandboxFunctional = true;
        r.tracingFunctional = true;
        r.seccompAvailable = true;
        r.checks = {{"bubblewrap (bwrap)", true, true, "test double", ""}};
        return r;
    }

    template <typename T>
    static T* child(const MainWindow& window, const char* name)
    {
        auto* widget = window.findChild<T*>(QString::fromLatin1(name));
        if (widget == nullptr) {
            qFatal("missing widget %s", name);
        }
        return widget;
    }

    bool sandboxReady()
    {
        if (!realReadiness_) {
            realReadiness_ = checkReadiness();
        }
        return realReadiness_->sandboxReady() && realReadiness_->tracingReady();
    }

private slots:
    void initTestCase()
    {
        // Keep settings and auto-saved reports inside the test directory.
        qputenv("XDG_CONFIG_HOME", (tmp_.path() + QStringLiteral("/config")).toUtf8());
        qputenv("XDG_DATA_HOME", (tmp_.path() + QStringLiteral("/data")).toUtf8());
        qputenv("XDG_CACHE_HOME", (tmp_.path() + QStringLiteral("/cache")).toUtf8());
        qRegisterMetaType<ReportPtr>();
    }

    void createsMainWindow()
    {
        MainWindow window(nullptr, false);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        QCOMPARE(window.windowTitle(), QStringLiteral("TracePot"));
        QVERIFY(child<QLabel>(window, "riskBanner")->text().contains(QStringLiteral("virtual machine")));
        QVERIFY(child<QLabel>(window, "networkPolicyLabel")->text().contains(QStringLiteral("isolated")));
        QVERIFY(!child<QPushButton>(window, "startButton")->isEnabled());  // no input, no readiness
        QVERIFY(!child<QPushButton>(window, "cancelButton")->isEnabled());
        QCOMPARE(window.resultsView()->tabs()->count(), 7);
        QVERIFY(!window.isAnalysisRunning());
    }

    void validatesInput()
    {
        MainWindow window(nullptr, false);
        window.setReadiness(fakeReadiness());
        auto* type = child<QLabel>(window, "inputTypeLabel");
        auto* start = child<QPushButton>(window, "startButton");
        auto* entry = child<QLineEdit>(window, "entryPointEdit");

        window.setInputPath(tmp_.path() + QStringLiteral("/does-not-exist.sh"));
        QVERIFY(type->text().startsWith(QStringLiteral("Error")));
        QVERIFY(!start->isEnabled());

        window.setInputPath(QStringLiteral("/usr/bin/true"));
        QVERIFY(type->text().contains(QStringLiteral("Unsupported")));
        QVERIFY(!start->isEnabled());

        window.setInputPath(QString::fromStdString(test::fixtureScript("create_file.sh").string()));
        QVERIFY(type->text().contains(QStringLiteral("Shell script")));
        QVERIFY(start->isEnabled());
        QVERIFY(!entry->isEnabled());
        QVERIFY(window.windowTitle().contains(QStringLiteral("create_file.sh")));

        const std::filesystem::path archive = tmp_.path().toStdString() + "/pkg.tar.gz";
        QVERIFY(test::ArchiveBuilder().file("install.sh", "#!/bin/sh\n").write(archive));
        window.setInputPath(QString::fromStdString(archive.string()));
        QVERIFY(type->text().contains(QStringLiteral("Tar archive")));
        QVERIFY(entry->isEnabled());

        // Without a successful readiness check nothing can be started.
        Readiness notReady = fakeReadiness();
        notReady.sandboxFunctional = false;
        window.setReadiness(notReady);
        QVERIFY(!start->isEnabled());
        QVERIFY(child<QLabel>(window, "readinessLabel")->text().contains(QStringLiteral("Not ready")));
    }

    void configReflectsControls()
    {
        MainWindow window(nullptr, false);
        window.setInputPath(QString::fromStdString(test::fixtureScript("create_file.sh").string()));
        child<QSpinBox>(window, "timeoutSpin")->setValue(42);
        child<QPlainTextEdit>(window, "argumentsEdit")->setPlainText(QStringLiteral("--one\na b c"));
        child<QPlainTextEdit>(window, "environmentEdit")->setPlainText(QStringLiteral("FOO=bar=baz"));
        child<QCheckBox>(window, "simulateRootCheck")->setChecked(true);
        const auto config = window.currentConfig();
        QCOMPARE(config.limits.timeoutSeconds, 42);
        QCOMPARE(config.arguments, (std::vector<std::string>{"--one", "a b c"}));
        QCOMPARE(config.environment.size(), std::size_t{1});
        QCOMPARE(QString::fromStdString(config.environment.front().second), QStringLiteral("bar=baz"));
        QCOMPARE(config.user, SandboxUser::SimulatedRoot);
    }

    void loadsSampleReport()
    {
        MainWindow window(nullptr, false);
        QVERIFY(window.loadReportFile(QString::fromStdString((test::fixturesDir() / "sample-report.json").string())));
        auto* results = window.resultsView();
        QCOMPARE(results->fileModel()->rowCount(), 4);
        QCOMPARE(results->processModel()->rowCount(), 2);
        QCOMPARE(results->networkModel()->rowCount(), 2);
        QCOMPARE(results->persistenceModel()->rowCount(), 2);
        QVERIFY(results->diagnosticsModel()->rowCount() >= 3);
        QVERIFY(results->summaryBrowser()->toPlainText().contains(QStringLiteral("tracepot-fixture.sh")));
        QVERIFY(results->summaryBrowser()->toPlainText().contains(QStringLiteral("does not mean the input is safe")));

        bool sawBashrc = false;
        for (int row = 0; row < results->fileModel()->rowCount(); ++row) {
            sawBashrc |= results->fileModel()->index(row, 0).data().toString() == QStringLiteral("/home/tracepot/.bashrc");
        }
        QVERIFY(sawBashrc);
        // Evidence labels distinguish observations from inferences.
        QCOMPARE(results->fileModel()->index(0, 8).data().toString(), QStringLiteral("Observed"));
        QCOMPARE(results->persistenceModel()->index(0, 6).data().toString(), QStringLiteral("Inferred"));
        bool sawInferredNetwork = false;
        for (int row = 0; row < results->networkModel()->rowCount(); ++row) {
            sawInferredNetwork |= results->networkModel()->index(row, 6).data().toString() == QStringLiteral("Inferred");
        }
        QVERIFY(sawInferredNetwork);

        // Selecting a row shows its evidence in the details panel.
        auto* table = window.findChild<QTableView*>(QStringLiteral("fileTable"));
        QVERIFY(table != nullptr);
        table->selectRow(0);
        auto* details = table->parentWidget()->findChild<QTextBrowser*>();
        QVERIFY(details != nullptr);
        QVERIFY(!details->toPlainText().isEmpty());
        QVERIFY(details->toPlainText().contains(QStringLiteral("Observed")));
    }

    void displaysWarningsAndFilters()
    {
        MainWindow window(nullptr, false);
        QVERIFY(window.loadReportFile(QString::fromStdString((test::fixturesDir() / "sample-report.json").string())));
        auto* results = window.resultsView();
        bool sawWarning = false;
        for (int row = 0; row < results->diagnosticsModel()->rowCount(); ++row) {
            sawWarning |= results->diagnosticsModel()->index(row, 0).data().toString() == QStringLiteral("warning");
        }
        QVERIFY(sawWarning);

        auto* proxy = results->fileProxy();
        results->fileFilter()->setText(QStringLiteral("bashrc"));
        QCOMPARE(proxy->rowCount(), 1);
        results->fileFilter()->clear();
        QCOMPARE(proxy->rowCount(), 4);
        auto* kind = window.findChild<QComboBox*>(QStringLiteral("changeKindFilter"));
        kind->setCurrentText(QStringLiteral("deleted"));
        QCOMPARE(proxy->rowCount(), 1);
        kind->setCurrentIndex(0);
        window.findChild<QCheckBox*>(QStringLiteral("hideTemporaryCheck"))->setChecked(true);
        QCOMPARE(proxy->rowCount(), 3);

        // Sorting by size uses numeric keys ("20.0 KiB" > "79 B" although "7" > "2" as text).
        window.findChild<QCheckBox*>(QStringLiteral("hideTemporaryCheck"))->setChecked(false);
        auto* table = window.findChild<QTableView*>(QStringLiteral("fileTable"));
        table->sortByColumn(6, Qt::DescendingOrder);
        QCOMPARE(proxy->index(0, 6).data().toString(), QStringLiteral("20.0 KiB"));
        table->sortByColumn(6, Qt::AscendingOrder);
        QCOMPARE(proxy->index(0, 6).data().toString(), QStringLiteral("12 B"));
    }

    void presentsErrors()
    {
        MainWindow window(nullptr, false);
        window.show();
        const QString bogus = tmp_.path() + QStringLiteral("/bogus.json");
        test::writeFile(bogus.toStdString(), "{\"schema\":\"tracepot-report\",\"schemaVersion\":\"9.0\"}");
        QVERIFY(!window.loadReportFile(bogus));
        auto* error = child<QLabel>(window, "errorLabel");
        QVERIFY(error->isVisible());
        QVERIFY(error->text().contains(QStringLiteral("Cannot open report")));
        QVERIFY(error->text().contains(QStringLiteral("unsupported report schema version")));

        // Starting without readiness explains why instead of running anything.
        window.setInputPath(QString::fromStdString(test::fixtureScript("create_file.sh").string()));
        window.startAnalysis();
        QVERIFY(!window.isAnalysisRunning());
        QVERIFY(error->text().contains(QStringLiteral("Cannot start")));
    }

    void reportsAnalysisFailure()
    {
        if (!sandboxReady()) {
            QSKIP("sandbox/tracer not available on this host");
        }
        MainWindow window(nullptr, false);
        window.show();
        window.setReadiness(*realReadiness_);
        const std::filesystem::path archive = tmp_.path().toStdString() + "/no-entry.tar.gz";
        QVERIFY(test::ArchiveBuilder().file("README", "no installer here").write(archive));
        window.setInputPath(QString::fromStdString(archive.string()));
        QSignalSpy finished(&window, &MainWindow::analysisFinished);
        QTest::mouseClick(child<QPushButton>(window, "startButton"), Qt::LeftButton);
        QVERIFY(finished.wait(60000));
        QCOMPARE(finished.front().front().toBool(), false);
        auto* error = child<QLabel>(window, "errorLabel");
        QVERIFY(error->isVisible());
        QVERIFY(error->text().contains(QStringLiteral("no installer script")));
        QVERIFY(child<QLabel>(window, "statusLabel")->text().contains(QStringLiteral("did not run")));
    }

    void startAndCancel()
    {
        if (!sandboxReady()) {
            QSKIP("sandbox/tracer not available on this host");
        }
        MainWindow window(nullptr, false);
        window.show();
        window.setReadiness(*realReadiness_);
        window.setInputPath(QString::fromStdString(test::fixtureScript("sleep_long.sh").string()));
        auto* start = child<QPushButton>(window, "startButton");
        auto* cancel = child<QPushButton>(window, "cancelButton");
        QVERIFY(start->isEnabled());
        QSignalSpy finished(&window, &MainWindow::analysisFinished);
        QTest::mouseClick(start, Qt::LeftButton);
        QVERIFY(window.isAnalysisRunning());
        QVERIFY(!start->isEnabled());
        QVERIFY(cancel->isEnabled());
        QTRY_COMPARE_WITH_TIMEOUT(child<QLabel>(window, "stageLabel")->text(), QStringLiteral("Running in sandbox"), 30000);
        QTRY_VERIFY_WITH_TIMEOUT(child<QLabel>(window, "countsLabel")->text().contains(QStringLiteral("processes")), 10000);
        QVERIFY(child<QLabel>(window, "elapsedLabel")->text().endsWith(QStringLiteral(" s")));

        QTest::mouseClick(cancel, Qt::LeftButton);
        QVERIFY(finished.wait(30000));
        QCOMPARE(finished.front().front().toBool(), true);
        QVERIFY(!window.isAnalysisRunning());
        QVERIFY(start->isEnabled());
        QVERIFY(!cancel->isEnabled());
        QVERIFY(child<QLabel>(window, "statusLabel")->text().contains(QStringLiteral("cancelled")));
        const auto report = window.resultsView()->report();
        QVERIFY(report != nullptr);
        QCOMPARE(report->execution.reason, TerminationReason::Cancelled);
        QVERIFY(window.resultsView()->processModel()->rowCount() >= 1);
        // The partial report was saved automatically.
        const QDir saved(tmp_.path() + QStringLiteral("/data/tracepot/reports"));
        QVERIFY(saved.entryList({QStringLiteral("*.json")}, QDir::Files).contains(
            QString::fromStdString(report->analysisId) + QStringLiteral(".json")));
    }
};

QTEST_MAIN(TestGuiMainWindow)
#include "tst_gui_mainwindow.moc"
