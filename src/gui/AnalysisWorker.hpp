#pragma once

#include "core/analysis/Analyzer.hpp"
#include "core/models/AnalysisConfig.hpp"
#include "core/models/Report.hpp"
#include "core/sandbox/Readiness.hpp"

#include <QMetaType>
#include <QObject>
#include <QString>

#include <memory>
#include <optional>

namespace tracepot::gui {

using ReportPtr = std::shared_ptr<const AnalysisReport>;

// Runs one analysis on a worker thread. Communication with the UI happens only through queued
// signals; cancellation goes through the shared, thread-safe CancellationToken.
class AnalysisWorker : public QObject {
    Q_OBJECT

public:
    AnalysisWorker(AnalysisConfig config, std::optional<Readiness> readiness,
                   std::shared_ptr<CancellationToken> cancel);

public slots:
    void run();

signals:
    void progress(int stage, double elapsedSeconds, qulonglong processes, qulonglong fileEvents,
                  qulonglong networkEvents, const QString& message);
    void succeeded(tracepot::gui::ReportPtr report);
    void failed(const QString& message, const QString& hint);
    void finished();

private:
    AnalysisConfig config_;
    std::optional<Readiness> readiness_;
    std::shared_ptr<CancellationToken> cancel_;
};

}  // namespace tracepot::gui

Q_DECLARE_METATYPE(tracepot::gui::ReportPtr)
