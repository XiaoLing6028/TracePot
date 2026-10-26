#pragma once

#include "gui/AnalysisWorker.hpp"
#include "gui/models/RecordTableModel.hpp"

#include <QWidget>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QTabWidget;
class QTableView;
class QTextBrowser;

namespace tracepot::gui {

// Tabbed presentation of an analysis report: summary, filesystem changes, process timeline,
// syscall events, network events, persistence findings, and warnings/limitations. Every table is
// sortable and filterable, and the selected record's evidence is shown in a details panel.
class ResultsView : public QWidget {
    Q_OBJECT

public:
    explicit ResultsView(QWidget* parent = nullptr);

    void setReport(ReportPtr report);
    void clear();
    [[nodiscard]] ReportPtr report() const { return report_; }

    // Accessors used by tests.
    [[nodiscard]] QTabWidget* tabs() const { return tabs_; }
    [[nodiscard]] RecordTableModel* fileModel() const { return files_.model; }
    [[nodiscard]] RecordFilterProxy* fileProxy() const { return files_.proxy; }
    [[nodiscard]] RecordTableModel* processModel() const { return processes_.model; }
    [[nodiscard]] RecordTableModel* networkModel() const { return network_.model; }
    [[nodiscard]] RecordTableModel* persistenceModel() const { return persistence_.model; }
    [[nodiscard]] RecordTableModel* diagnosticsModel() const { return diagnostics_.model; }
    [[nodiscard]] QTextBrowser* summaryBrowser() const { return summary_; }
    [[nodiscard]] QLineEdit* fileFilter() const { return files_.filter; }

private:
    struct TablePage {
        QWidget* page = nullptr;
        QLineEdit* filter = nullptr;
        QTableView* view = nullptr;
        QTextBrowser* details = nullptr;
        RecordTableModel* model = nullptr;
        RecordFilterProxy* proxy = nullptr;
    };

    TablePage makePage(const QString& name, const QStringList& headers, QWidget* extraControls = nullptr);
    void populate();

    QTabWidget* tabs_ = nullptr;
    QTextBrowser* summary_ = nullptr;
    TablePage files_;
    TablePage processes_;
    TablePage events_;
    TablePage network_;
    TablePage persistence_;
    TablePage diagnostics_;
    QComboBox* changeKind_ = nullptr;
    QCheckBox* hideTemporary_ = nullptr;
    ReportPtr report_;
};

}  // namespace tracepot::gui
