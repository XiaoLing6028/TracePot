#pragma once

#include "core/analysis/Cancellation.hpp"
#include "core/archive/InputInspector.hpp"
#include "core/sandbox/Readiness.hpp"
#include "gui/AnalysisWorker.hpp"

#include <QElapsedTimer>
#include <QMainWindow>

#include <memory>
#include <optional>

class QAction;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QThread;
class QTimer;

namespace tracepot::gui {

class ResultsView;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    // When checkReadinessOnStart is false the sandbox probe is not run automatically
    // (used by tests that inject a readiness result).
    explicit MainWindow(QWidget* parent = nullptr, bool checkReadinessOnStart = true);
    ~MainWindow() override;

    void setInputPath(const QString& path);
    void setReadiness(const Readiness& readiness);
    [[nodiscard]] bool isAnalysisRunning() const { return thread_ != nullptr; }
    [[nodiscard]] bool canStartAnalysis() const;
    [[nodiscard]] ResultsView* resultsView() const { return results_; }
    [[nodiscard]] AnalysisConfig currentConfig() const;

    // Loads a saved report into the results view. Returns false and shows the error on failure.
    bool loadReportFile(const QString& path);

public slots:
    void startAnalysis();
    void cancelAnalysis();
    void refreshInputInfo();
    void checkReadinessAsync();

signals:
    void analysisFinished(bool producedReport);
    void readinessChecked();

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildUi();
    void buildMenus();
    void updateControls();
    void showError(const QString& message, const QString& hint = {});
    void clearError();
    void loadSettings();
    void saveSettings() const;
    void autoSaveReport(const AnalysisReport& report);

    void onProgress(int stage, double elapsed, qulonglong processes, qulonglong fileEvents, qulonglong networkEvents,
                    const QString& message);
    void onSucceeded(const ReportPtr& report);
    void onFailed(const QString& message, const QString& hint);
    void onThreadFinished();

    void browseInput();
    void openReportDialog();
    void exportJson();
    void exportHtml();
    void showAbout();

    // Setup
    QLineEdit* inputEdit_ = nullptr;
    QLabel* inputTypeLabel_ = nullptr;
    QLineEdit* entryEdit_ = nullptr;
    QPlainTextEdit* argumentsEdit_ = nullptr;
    QPlainTextEdit* environmentEdit_ = nullptr;
    QSpinBox* timeoutSpin_ = nullptr;
    QSpinBox* memorySpin_ = nullptr;
    QSpinBox* processSpin_ = nullptr;
    QSpinBox* fileSizeSpin_ = nullptr;
    QSpinBox* diskSpin_ = nullptr;
    QCheckBox* simulateRootCheck_ = nullptr;
    QLabel* networkPolicyLabel_ = nullptr;
    QLabel* readinessLabel_ = nullptr;
    QPushButton* recheckButton_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;

    // Progress
    QLabel* stageLabel_ = nullptr;
    QLabel* elapsedLabel_ = nullptr;
    QLabel* countsLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QLabel* errorLabel_ = nullptr;
    QProgressBar* progressBar_ = nullptr;

    ResultsView* results_ = nullptr;
    QAction* exportJsonAction_ = nullptr;
    QAction* exportHtmlAction_ = nullptr;
    QAction* startAction_ = nullptr;
    QAction* cancelAction_ = nullptr;

    QTimer* inputDebounce_ = nullptr;
    QTimer* elapsedTimer_ = nullptr;
    QElapsedTimer clock_;
    std::optional<InputInfo> inputInfo_;
    std::optional<Readiness> readiness_;
    bool readinessPending_ = false;
    QThread* thread_ = nullptr;
    QThread* readinessThread_ = nullptr;
    std::shared_ptr<CancellationToken> cancel_;
};

}  // namespace tracepot::gui
