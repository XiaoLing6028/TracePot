#include "gui/MainWindow.hpp"

#include "Version.hpp"
#include "core/analysis/Analyzer.hpp"
#include "core/models/Limits.hpp"
#include "core/observers/NetworkObserver.hpp"
#include "core/reporting/ReportJson.hpp"
#include "core/reporting/ReportRender.hpp"
#include "core/sandbox/BwrapCommand.hpp"
#include "core/util/PathUtil.hpp"
#include "gui/widgets/ResultsView.hpp"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardPaths>
#include <QStatusBar>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

namespace tracepot::gui {

namespace {

QString settingsPath()
{
    return QString::fromStdString((tracepotConfigDir() / "tracepot-gui.conf").string());
}

QSpinBox* makeSpin(QWidget* parent, int minimum, int maximum, int value, const QString& objectName,
                   const QString& suffix = {})
{
    auto* spin = new QSpinBox(parent);
    spin->setRange(minimum, maximum);
    spin->setValue(value);
    spin->setObjectName(objectName);
    if (!suffix.isEmpty()) {
        spin->setSuffix(suffix);
    }
    return spin;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent, bool checkReadinessOnStart) : QMainWindow(parent)
{
    setObjectName(QStringLiteral("mainWindow"));
    setWindowTitle(QStringLiteral("TracePot"));
    buildUi();
    buildMenus();
    loadSettings();
    updateControls();
    if (checkReadinessOnStart) {
        QTimer::singleShot(0, this, &MainWindow::checkReadinessAsync);
    }
}

MainWindow::~MainWindow()
{
    if (cancel_) {
        cancel_->cancel();
    }
    if (thread_ != nullptr) {
        thread_->wait();
    }
    if (readinessThread_ != nullptr) {
        readinessThread_->wait();
    }
}

void MainWindow::buildUi()
{
    auto* central = new QWidget(this);
    auto* layout = new QVBoxLayout(central);

    auto* banner = new QLabel(central);
    banner->setObjectName(QStringLiteral("riskBanner"));
    banner->setWordWrap(true);
    banner->setFrameShape(QFrame::StyledPanel);
    banner->setTextFormat(Qt::RichText);
    banner->setText(tr("<b>Warning: residual risk.</b> TracePot executes the selected input inside a Linux "
                       "namespace sandbox (bubblewrap with seccomp, no network, read-only system directories). The "
                       "sandbox shares the host kernel and is not a complete security boundary. Analyze "
                       "high-risk samples in a disposable virtual machine. Results describe one observed run "
                       "and never prove that an input is safe."));
    banner->setAccessibleName(tr("Residual risk warning"));
    layout->addWidget(banner);

    auto* splitter = new QSplitter(Qt::Horizontal, central);
    auto* scroll = new QScrollArea(splitter);
    scroll->setWidgetResizable(true);
    auto* left = new QWidget(scroll);
    auto* leftLayout = new QVBoxLayout(left);

    // ---- Input
    auto* inputGroup = new QGroupBox(tr("Input"), left);
    auto* inputForm = new QFormLayout(inputGroup);
    auto* inputRow = new QHBoxLayout();
    inputEdit_ = new QLineEdit(inputGroup);
    inputEdit_->setObjectName(QStringLiteral("inputPathEdit"));
    inputEdit_->setPlaceholderText(tr("Shell script or tar archive"));
    inputEdit_->setAccessibleName(tr("Installer path"));
    auto* browse = new QPushButton(tr("&Browse..."), inputGroup);
    browse->setObjectName(QStringLiteral("browseButton"));
    inputRow->addWidget(inputEdit_, 1);
    inputRow->addWidget(browse);
    auto* inputLabel = new QLabel(tr("&Installer:"), inputGroup);
    inputLabel->setBuddy(inputEdit_);
    inputForm->addRow(inputLabel, inputRow);
    inputTypeLabel_ = new QLabel(tr("No input selected"), inputGroup);
    inputTypeLabel_->setObjectName(QStringLiteral("inputTypeLabel"));
    inputTypeLabel_->setWordWrap(true);
    inputTypeLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    inputForm->addRow(tr("Detected type:"), inputTypeLabel_);
    entryEdit_ = new QLineEdit(inputGroup);
    entryEdit_->setObjectName(QStringLiteral("entryPointEdit"));
    entryEdit_->setPlaceholderText(tr("auto-detect (install.sh, setup.sh, ...)"));
    entryEdit_->setAccessibleName(tr("Archive entry point"));
    auto* entryLabel = new QLabel(tr("Archive &entry point:"), inputGroup);
    entryLabel->setBuddy(entryEdit_);
    inputForm->addRow(entryLabel, entryEdit_);
    argumentsEdit_ = new QPlainTextEdit(inputGroup);
    argumentsEdit_->setObjectName(QStringLiteral("argumentsEdit"));
    argumentsEdit_->setPlaceholderText(tr("One argument per line (passed verbatim, no shell parsing)"));
    argumentsEdit_->setAccessibleName(tr("Script arguments"));
    argumentsEdit_->setTabChangesFocus(true);
    argumentsEdit_->setMaximumHeight(70);
    auto* argumentsLabel = new QLabel(tr("&Arguments:"), inputGroup);
    argumentsLabel->setBuddy(argumentsEdit_);
    inputForm->addRow(argumentsLabel, argumentsEdit_);
    environmentEdit_ = new QPlainTextEdit(inputGroup);
    environmentEdit_->setObjectName(QStringLiteral("environmentEdit"));
    environmentEdit_->setPlaceholderText(tr("NAME=VALUE per line (only names are written to reports)"));
    environmentEdit_->setAccessibleName(tr("Environment variables"));
    environmentEdit_->setTabChangesFocus(true);
    environmentEdit_->setMaximumHeight(70);
    auto* environmentLabel = new QLabel(tr("En&vironment:"), inputGroup);
    environmentLabel->setBuddy(environmentEdit_);
    inputForm->addRow(environmentLabel, environmentEdit_);
    leftLayout->addWidget(inputGroup);

    // ---- Sandbox
    auto* sandboxGroup = new QGroupBox(tr("Sandbox"), left);
    auto* sandboxForm = new QFormLayout(sandboxGroup);
    timeoutSpin_ = makeSpin(sandboxGroup, 1, 3600, 120, QStringLiteral("timeoutSpin"), tr(" s"));
    memorySpin_ = makeSpin(sandboxGroup, 0, 65536, 2048, QStringLiteral("memorySpin"), tr(" MiB"));
    memorySpin_->setSpecialValueText(tr("no limit"));
    processSpin_ = makeSpin(sandboxGroup, 0, 10000, 256, QStringLiteral("processSpin"));
    processSpin_->setSpecialValueText(tr("no limit"));
    fileSizeSpin_ = makeSpin(sandboxGroup, 0, 65536, 512, QStringLiteral("fileSizeSpin"), tr(" MiB"));
    fileSizeSpin_->setSpecialValueText(tr("no limit"));
    diskSpin_ = makeSpin(sandboxGroup, 0, 1048576, 1024, QStringLiteral("diskSpin"), tr(" MiB"));
    diskSpin_->setSpecialValueText(tr("no limit"));
    for (const auto& [label, widget] : std::initializer_list<std::pair<QString, QSpinBox*>>{
             {tr("&Timeout:"), timeoutSpin_},
             {tr("&Memory per process:"), memorySpin_},
             {tr("Additional &processes:"), processSpin_},
             {tr("Maximum file si&ze:"), fileSizeSpin_},
             {tr("&Disk growth:"), diskSpin_}}) {
        auto* l = new QLabel(label, sandboxGroup);
        l->setBuddy(widget);
        widget->setAccessibleName(QString(label).remove(QLatin1Char('&')).remove(QLatin1Char(':')));
        sandboxForm->addRow(l, widget);
    }
    simulateRootCheck_ = new QCheckBox(tr("Simulate &root user inside the sandbox (no host privileges)"), sandboxGroup);
    simulateRootCheck_->setObjectName(QStringLiteral("simulateRootCheck"));
    simulateRootCheck_->setToolTip(tr("Makes system directories writable inside the sandbox so system-level "
                                      "installer behavior can be observed. Nothing is written to the host."));
    sandboxForm->addRow(simulateRootCheck_);
    const auto policy = IsolatedNetwork().describe();
    networkPolicyLabel_ = new QLabel(tr("<b>%1</b>: %2")
                                         .arg(QString::fromStdString(policy.mode).toHtmlEscaped(),
                                              QString::fromStdString(policy.description).toHtmlEscaped()),
                                     sandboxGroup);
    networkPolicyLabel_->setObjectName(QStringLiteral("networkPolicyLabel"));
    networkPolicyLabel_->setWordWrap(true);
    sandboxForm->addRow(tr("Network policy:"), networkPolicyLabel_);
    leftLayout->addWidget(sandboxGroup);

    // ---- Readiness
    auto* readinessGroup = new QGroupBox(tr("Dependency readiness"), left);
    auto* readinessLayout = new QVBoxLayout(readinessGroup);
    readinessLabel_ = new QLabel(tr("Not checked yet."), readinessGroup);
    readinessLabel_->setObjectName(QStringLiteral("readinessLabel"));
    readinessLabel_->setWordWrap(true);
    readinessLabel_->setTextFormat(Qt::RichText);
    readinessLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    recheckButton_ = new QPushButton(tr("Re-&check"), readinessGroup);
    recheckButton_->setObjectName(QStringLiteral("recheckButton"));
    readinessLayout->addWidget(readinessLabel_);
    readinessLayout->addWidget(recheckButton_, 0, Qt::AlignLeft);
    leftLayout->addWidget(readinessGroup);

    // ---- Actions and progress
    auto* buttons = new QHBoxLayout();
    startButton_ = new QPushButton(tr("&Start Analysis"), left);
    startButton_->setObjectName(QStringLiteral("startButton"));
    startButton_->setDefault(true);
    cancelButton_ = new QPushButton(tr("&Cancel"), left);
    cancelButton_->setObjectName(QStringLiteral("cancelButton"));
    buttons->addWidget(startButton_);
    buttons->addWidget(cancelButton_);
    leftLayout->addLayout(buttons);

    auto* progressGroup = new QGroupBox(tr("Progress"), left);
    auto* progressForm = new QFormLayout(progressGroup);
    stageLabel_ = new QLabel(tr("Idle"), progressGroup);
    stageLabel_->setObjectName(QStringLiteral("stageLabel"));
    elapsedLabel_ = new QLabel(QStringLiteral("—"), progressGroup);
    elapsedLabel_->setObjectName(QStringLiteral("elapsedLabel"));
    countsLabel_ = new QLabel(QStringLiteral("—"), progressGroup);
    countsLabel_->setObjectName(QStringLiteral("countsLabel"));
    statusLabel_ = new QLabel(QStringLiteral("—"), progressGroup);
    statusLabel_->setObjectName(QStringLiteral("statusLabel"));
    statusLabel_->setWordWrap(true);
    progressBar_ = new QProgressBar(progressGroup);
    progressBar_->setObjectName(QStringLiteral("progressBar"));
    progressBar_->setRange(0, 1);
    progressBar_->setValue(0);
    progressBar_->setTextVisible(false);
    progressBar_->setAccessibleName(tr("Analysis activity"));
    progressForm->addRow(tr("Stage:"), stageLabel_);
    progressForm->addRow(tr("Elapsed:"), elapsedLabel_);
    progressForm->addRow(tr("Live events:"), countsLabel_);
    progressForm->addRow(tr("Result:"), statusLabel_);
    progressForm->addRow(progressBar_);
    errorLabel_ = new QLabel(progressGroup);
    errorLabel_->setObjectName(QStringLiteral("errorLabel"));
    errorLabel_->setWordWrap(true);
    errorLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    errorLabel_->setStyleSheet(QStringLiteral("QLabel { color: palette(highlighted-text); background: #a01818; padding: 4px; }"));
    errorLabel_->setVisible(false);
    progressForm->addRow(errorLabel_);
    leftLayout->addWidget(progressGroup);
    leftLayout->addStretch(1);
    scroll->setWidget(left);

    results_ = new ResultsView(splitter);
    splitter->addWidget(scroll);
    splitter->addWidget(results_);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 5);
    layout->addWidget(splitter, 1);
    setCentralWidget(central);
    resize(1280, 800);

    inputDebounce_ = new QTimer(this);
    inputDebounce_->setSingleShot(true);
    inputDebounce_->setInterval(300);
    elapsedTimer_ = new QTimer(this);
    elapsedTimer_->setInterval(200);

    connect(inputEdit_, &QLineEdit::textChanged, inputDebounce_, qOverload<>(&QTimer::start));
    connect(inputDebounce_, &QTimer::timeout, this, &MainWindow::refreshInputInfo);
    connect(browse, &QPushButton::clicked, this, &MainWindow::browseInput);
    connect(startButton_, &QPushButton::clicked, this, &MainWindow::startAnalysis);
    connect(cancelButton_, &QPushButton::clicked, this, &MainWindow::cancelAnalysis);
    connect(recheckButton_, &QPushButton::clicked, this, &MainWindow::checkReadinessAsync);
    connect(elapsedTimer_, &QTimer::timeout, this, [this]() {
        elapsedLabel_->setText(tr("%1 s").arg(static_cast<double>(clock_.elapsed()) / 1000.0, 0, 'f', 1));
    });
}

void MainWindow::buildMenus()
{
    auto* file = menuBar()->addMenu(tr("&File"));
    auto* openInput = file->addAction(tr("Open &Installer..."), this, &MainWindow::browseInput);
    openInput->setShortcut(QKeySequence::Open);
    auto* openReport = file->addAction(tr("Open &Report..."), this, &MainWindow::openReportDialog);
    openReport->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_O));
    file->addSeparator();
    exportJsonAction_ = file->addAction(tr("Export &JSON..."), this, &MainWindow::exportJson);
    exportJsonAction_->setShortcut(QKeySequence::Save);
    exportHtmlAction_ = file->addAction(tr("Export &HTML..."), this, &MainWindow::exportHtml);
    exportHtmlAction_->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_E));
    file->addSeparator();
    auto* quit = file->addAction(tr("&Quit"), this, &QWidget::close);
    quit->setShortcut(QKeySequence::Quit);

    auto* analysis = menuBar()->addMenu(tr("&Analysis"));
    startAction_ = analysis->addAction(tr("&Start"), this, &MainWindow::startAnalysis);
    startAction_->setShortcuts({QKeySequence(Qt::Key_F5), QKeySequence(Qt::CTRL | Qt::Key_R)});
    cancelAction_ = analysis->addAction(tr("&Cancel"), this, &MainWindow::cancelAnalysis);
    cancelAction_->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F5));
    analysis->addSeparator();
    auto* readiness = analysis->addAction(tr("Check &Readiness"), this, &MainWindow::checkReadinessAsync);
    readiness->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_R));

    auto* help = menuBar()->addMenu(tr("&Help"));
    help->addAction(tr("&About TracePot"), this, &MainWindow::showAbout);
    help->addAction(tr("About &Qt"), qApp, &QApplication::aboutQt);
}

void MainWindow::setInputPath(const QString& path)
{
    inputEdit_->setText(path);
    refreshInputInfo();
}

void MainWindow::refreshInputInfo()
{
    inputDebounce_->stop();
    const QString path = inputEdit_->text().trimmed();
    inputInfo_.reset();
    if (path.isEmpty()) {
        inputTypeLabel_->setText(tr("No input selected"));
    } else {
        auto info = inspectInput(path.toStdString());
        if (!info) {
            inputTypeLabel_->setText(tr("Error: %1").arg(QString::fromStdString(info.error().message)));
        } else {
            inputInfo_ = info.value();
            switch (inputInfo_->kind) {
            case InputKind::ShellScript:
                inputTypeLabel_->setText(tr("Shell script (runs with %1)").arg(QString::fromStdString(inputInfo_->interpreter)));
                break;
            case InputKind::TarArchive:
                inputTypeLabel_->setText(tr("Tar archive (%1); extracted with path, link and size checks")
                                             .arg(QString::fromStdString(inputInfo_->format)));
                break;
            case InputKind::Unsupported:
                inputTypeLabel_->setText(tr("Unsupported (will not be executed): %1")
                                             .arg(QString::fromStdString(inputInfo_->reason)));
                break;
            }
        }
    }
    setWindowTitle(path.isEmpty() ? QStringLiteral("TracePot")
                                   : QStringLiteral("TracePot — %1").arg(QFileInfo(path).fileName()));
    updateControls();
}

void MainWindow::setReadiness(const Readiness& readiness)
{
    readiness_ = readiness;
    readinessPending_ = false;
    QString html = QStringLiteral("<ul style=\"margin-left:-20px\">");
    for (const auto& check : readiness.checks) {
        const QString status = check.ok ? tr("OK") : (check.required ? tr("FAILED") : tr("WARNING"));
        html += QStringLiteral("<li><b>%1</b> — %2: %3%4</li>")
                    .arg(status, QString::fromStdString(check.name).toHtmlEscaped(),
                         QString::fromStdString(check.detail).toHtmlEscaped(),
                         check.ok || check.hint.empty()
                             ? QString()
                             : QStringLiteral("<br><i>%1</i>").arg(QString::fromStdString(check.hint).toHtmlEscaped()));
    }
    html += QStringLiteral("</ul>");
    const bool ready = readiness.sandboxReady() && readiness.tracingReady();
    html += ready ? tr("<p><b>Ready.</b></p>")
                  : tr("<p><b>Not ready:</b> analyses are disabled until the failed checks are resolved. TracePot "
                       "never runs inputs without its sandbox.</p>");
    readinessLabel_->setText(html);
    updateControls();
    emit readinessChecked();
}

void MainWindow::checkReadinessAsync()
{
    if (readinessThread_ != nullptr) {
        return;
    }
    readinessPending_ = true;
    readinessLabel_->setText(tr("Checking sandbox and tracer..."));
    updateControls();
    auto result = std::make_shared<Readiness>();
    readinessThread_ = QThread::create([result]() { *result = checkReadiness(); });
    connect(readinessThread_, &QThread::finished, this, [this, result]() {
        readinessThread_->deleteLater();
        readinessThread_ = nullptr;
        setReadiness(*result);
    });
    readinessThread_->start();
}

bool MainWindow::canStartAnalysis() const
{
    return thread_ == nullptr && !readinessPending_ && readiness_ && readiness_->sandboxReady() &&
           readiness_->tracingReady() && inputInfo_ && inputInfo_->kind != InputKind::Unsupported;
}

void MainWindow::updateControls()
{
    const bool running = thread_ != nullptr;
    const bool canStart = canStartAnalysis();
    startButton_->setEnabled(canStart);
    startAction_->setEnabled(canStart);
    cancelButton_->setEnabled(running);
    cancelAction_->setEnabled(running);
    recheckButton_->setEnabled(!running && readinessThread_ == nullptr);
    const bool hasReport = results_->report() != nullptr;
    exportJsonAction_->setEnabled(hasReport && !running);
    exportHtmlAction_->setEnabled(hasReport && !running);
    entryEdit_->setEnabled(inputInfo_ && inputInfo_->kind == InputKind::TarArchive);
    for (QWidget* widget : std::initializer_list<QWidget*>{inputEdit_, argumentsEdit_, environmentEdit_, timeoutSpin_,
                                                           memorySpin_, processSpin_, fileSizeSpin_, diskSpin_,
                                                           simulateRootCheck_}) {
        widget->setEnabled(!running);
    }
}

AnalysisConfig MainWindow::currentConfig() const
{
    AnalysisConfig config;
    config.inputPath = inputEdit_->text().trimmed().toStdString();
    config.entryPoint = entryEdit_->isEnabled() ? entryEdit_->text().trimmed().toStdString() : std::string();
    for (const QString& line : argumentsEdit_->toPlainText().split(QLatin1Char('\n'))) {
        if (!line.isEmpty()) {
            config.arguments.push_back(line.toStdString());
        }
    }
    for (const QString& line : environmentEdit_->toPlainText().split(QLatin1Char('\n'))) {
        const QString trimmed = line.trimmed();
        const auto eq = trimmed.indexOf(QLatin1Char('='));
        if (!trimmed.isEmpty() && eq > 0) {
            config.environment.emplace_back(trimmed.left(eq).toStdString(), trimmed.mid(eq + 1).toStdString());
        }
    }
    config.user = simulateRootCheck_->isChecked() ? SandboxUser::SimulatedRoot : SandboxUser::Unprivileged;
    config.limits.timeoutSeconds = timeoutSpin_->value();
    config.limits.memoryBytes = static_cast<std::uint64_t>(memorySpin_->value()) * MiB;
    config.limits.maxProcesses = static_cast<std::uint32_t>(processSpin_->value());
    config.limits.maxFileSizeBytes = static_cast<std::uint64_t>(fileSizeSpin_->value()) * MiB;
    config.limits.maxDiskBytes = static_cast<std::uint64_t>(diskSpin_->value()) * MiB;
    return config;
}

void MainWindow::startAnalysis()
{
    clearError();
    if (!canStartAnalysis()) {
        showError(tr("Cannot start the analysis."),
                  !readiness_ ? tr("The sandbox readiness check has not completed.")
                  : !(readiness_->sandboxReady() && readiness_->tracingReady())
                      ? tr("The sandbox or tracer is not available; see Dependency readiness.")
                      : tr("Select a supported shell script or tar archive."));
        return;
    }
    for (const QString& line : environmentEdit_->toPlainText().split(QLatin1Char('\n'))) {
        const QString trimmed = line.trimmed();
        if (trimmed.isEmpty()) {
            continue;
        }
        const auto eq = trimmed.indexOf(QLatin1Char('='));
        if (eq <= 0 || !isValidEnvironmentName(trimmed.left(eq).toStdString())) {
            showError(tr("Invalid environment line: %1").arg(trimmed), tr("Use NAME=VALUE with a valid variable name."));
            return;
        }
    }
    saveSettings();
    results_->clear();
    cancel_ = std::make_shared<CancellationToken>();
    thread_ = new QThread(this);
    auto* worker = new AnalysisWorker(currentConfig(), readiness_, cancel_);
    worker->moveToThread(thread_);
    connect(thread_, &QThread::started, worker, &AnalysisWorker::run);
    connect(worker, &AnalysisWorker::progress, this, &MainWindow::onProgress);
    connect(worker, &AnalysisWorker::succeeded, this, &MainWindow::onSucceeded);
    connect(worker, &AnalysisWorker::failed, this, &MainWindow::onFailed);
    connect(worker, &AnalysisWorker::finished, thread_, &QThread::quit);
    connect(thread_, &QThread::finished, worker, &QObject::deleteLater);
    connect(thread_, &QThread::finished, this, &MainWindow::onThreadFinished);

    stageLabel_->setText(tr("Starting"));
    statusLabel_->setText(tr("Running..."));
    countsLabel_->setText(QStringLiteral("—"));
    elapsedLabel_->setText(tr("0.0 s"));
    progressBar_->setRange(0, 0);  // busy indicator
    clock_.start();
    elapsedTimer_->start();
    thread_->start();
    updateControls();
}

void MainWindow::cancelAnalysis()
{
    if (cancel_ && thread_ != nullptr) {
        cancel_->cancel();
        statusLabel_->setText(tr("Cancelling: terminating the sandbox..."));
    }
}

void MainWindow::onProgress(int stage, double /*elapsed*/, qulonglong processes, qulonglong fileEvents,
                            qulonglong networkEvents, const QString& message)
{
    stageLabel_->setText(QString::fromUtf8(stageLabel(static_cast<AnalysisStage>(stage)).data()));
    if (static_cast<AnalysisStage>(stage) >= AnalysisStage::Running) {
        countsLabel_->setText(tr("%1 processes, %2 file events, %3 network events")
                                  .arg(processes)
                                  .arg(fileEvents)
                                  .arg(networkEvents));
    }
    statusBar()->showMessage(message);
}

void MainWindow::onSucceeded(ReportPtr report)
{
    results_->setReport(report);
    const auto& execution = report->execution;
    statusLabel_->setText(tr("Finished: %1").arg(QString::fromStdString(describeTermination(execution))));
    if (execution.reason == TerminationReason::LaunchFailed) {
        showError(tr("The sandbox could not start the entry script."), QString::fromStdString(execution.detail));
    }
    autoSaveReport(*report);
    results_->tabs()->setCurrentIndex(0);
}

void MainWindow::onFailed(const QString& message, const QString& hint)
{
    statusLabel_->setText(tr("Analysis did not run."));
    showError(message, hint);
}

void MainWindow::onThreadFinished()
{
    thread_->deleteLater();
    thread_ = nullptr;
    elapsedTimer_->stop();
    progressBar_->setRange(0, 1);
    progressBar_->setValue(1);
    stageLabel_->setText(tr("Idle"));
    updateControls();
    emit analysisFinished(results_->report() != nullptr);
}

void MainWindow::showError(const QString& message, const QString& hint)
{
    QString text = tr("Error: %1").arg(message);
    if (!hint.trimmed().isEmpty()) {
        text += QStringLiteral("\n") + hint.trimmed();
    }
    errorLabel_->setText(text);
    errorLabel_->setVisible(true);
    statusBar()->showMessage(tr("TracePot: %1").arg(message));
}

void MainWindow::clearError()
{
    errorLabel_->clear();
    errorLabel_->setVisible(false);
}

bool MainWindow::loadReportFile(const QString& path)
{
    clearError();
    auto report = tracepot::loadReportFile(path.toStdString());
    if (!report) {
        showError(tr("Cannot open report %1").arg(QFileInfo(path).fileName()),
                  QString::fromStdString(report.error().message));
        return false;
    }
    results_->setReport(std::make_shared<const AnalysisReport>(std::move(report).value()));
    statusLabel_->setText(tr("Loaded report %1").arg(QFileInfo(path).fileName()));
    setWindowTitle(QStringLiteral("TracePot — %1").arg(QFileInfo(path).fileName()));
    updateControls();
    return true;
}

void MainWindow::autoSaveReport(const AnalysisReport& report)
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) +
                        QStringLiteral("/tracepot/reports");
    if (!QDir().mkpath(dir)) {
        return;
    }
    const QString path = dir + QLatin1Char('/') + QString::fromStdString(report.analysisId) + QStringLiteral(".json");
    if (writeTextFileAtomic(path.toStdString(), serializeReport(report))) {
        statusBar()->showMessage(tr("Report saved to %1").arg(path));
    }
}

void MainWindow::browseInput()
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Select installer"), settings.value(QStringLiteral("lastDirectory"), QDir::homePath()).toString(),
        tr("Installers (*.sh *.tar *.tar.gz *.tgz *.tar.bz2 *.tar.xz *.tar.zst *.run);;All files (*)"));
    if (!path.isEmpty()) {
        settings.setValue(QStringLiteral("lastDirectory"), QFileInfo(path).absolutePath());
        setInputPath(path);
    }
}

void MainWindow::openReportDialog()
{
    const QString start = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) +
                          QStringLiteral("/tracepot/reports");
    const QString path = QFileDialog::getOpenFileName(this, tr("Open TracePot report"), start,
                                                      tr("TracePot reports (*.json);;All files (*)"));
    if (!path.isEmpty()) {
        loadReportFile(path);
    }
}

void MainWindow::exportJson()
{
    const auto report = results_->report();
    if (!report) {
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, tr("Export JSON report"),
                                                      QString::fromStdString(report->analysisId) + QStringLiteral(".json"),
                                                      tr("JSON (*.json)"));
    if (path.isEmpty()) {
        return;
    }
    if (auto written = writeTextFileAtomic(path.toStdString(), serializeReport(*report)); !written) {
        showError(tr("Export failed"), QString::fromStdString(written.error().message));
    }
}

void MainWindow::exportHtml()
{
    const auto report = results_->report();
    if (!report) {
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, tr("Export HTML report"),
                                                      QString::fromStdString(report->analysisId) + QStringLiteral(".html"),
                                                      tr("HTML (*.html)"));
    if (path.isEmpty()) {
        return;
    }
    if (auto written = writeTextFileAtomic(path.toStdString(), renderHtmlReport(*report)); !written) {
        showError(tr("Export failed"), QString::fromStdString(written.error().message));
    }
}

void MainWindow::showAbout()
{
    QMessageBox::about(
        this, tr("About TracePot"),
        tr("<h3>TracePot %1</h3><p>What did this installer actually do?</p>"
           "<p>TracePot runs shell scripts and tar archives inside a bubblewrap sandbox (user, PID, mount, IPC, UTS "
           "and network namespaces, seccomp, resource limits), records process, file and network activity with "
           "strace, and compares the filesystem before and after the run.</p>"
           "<p>The sandbox shares the host kernel. For high-risk samples use a disposable virtual machine. "
           "Reports describe observed behavior only and never certify an input as safe.</p>"
           "<p>Licensed under the Apache License, Version 2.0.</p>")
            .arg(QString::fromUtf8(kApplicationVersion.data(), static_cast<int>(kApplicationVersion.size()))));
}

void MainWindow::loadSettings()
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    timeoutSpin_->setValue(settings.value(QStringLiteral("timeoutSeconds"), timeoutSpin_->value()).toInt());
    memorySpin_->setValue(settings.value(QStringLiteral("memoryMiB"), memorySpin_->value()).toInt());
    processSpin_->setValue(settings.value(QStringLiteral("maxProcesses"), processSpin_->value()).toInt());
    fileSizeSpin_->setValue(settings.value(QStringLiteral("maxFileSizeMiB"), fileSizeSpin_->value()).toInt());
    diskSpin_->setValue(settings.value(QStringLiteral("maxDiskMiB"), diskSpin_->value()).toInt());
    simulateRootCheck_->setChecked(settings.value(QStringLiteral("simulateRoot"), false).toBool());
}

void MainWindow::saveSettings() const
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    settings.setValue(QStringLiteral("timeoutSeconds"), timeoutSpin_->value());
    settings.setValue(QStringLiteral("memoryMiB"), memorySpin_->value());
    settings.setValue(QStringLiteral("maxProcesses"), processSpin_->value());
    settings.setValue(QStringLiteral("maxFileSizeMiB"), fileSizeSpin_->value());
    settings.setValue(QStringLiteral("maxDiskMiB"), diskSpin_->value());
    settings.setValue(QStringLiteral("simulateRoot"), simulateRootCheck_->isChecked());
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (thread_ != nullptr) {
        // Cancelling kills the sandbox; the worker then finishes promptly.
        statusLabel_->setText(tr("Cancelling before exit..."));
        cancel_->cancel();
        thread_->wait();
    }
    saveSettings();
    event->accept();
}

}  // namespace tracepot::gui
