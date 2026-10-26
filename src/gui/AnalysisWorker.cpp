#include "gui/AnalysisWorker.hpp"

#include <exception>

namespace tracepot::gui {

AnalysisWorker::AnalysisWorker(AnalysisConfig config, std::optional<Readiness> readiness,
                               std::shared_ptr<CancellationToken> cancel)
    : config_(std::move(config)), readiness_(std::move(readiness)), cancel_(std::move(cancel))
{
}

void AnalysisWorker::run()
{
    try {
        Analyzer analyzer(config_);
        if (readiness_) {
            analyzer.setReadiness(*readiness_);
        }
        auto result = analyzer.run(*cancel_, [this](const ProgressUpdate& update) {
            emit progress(static_cast<int>(update.stage), update.elapsedSeconds, update.counts.processes,
                          update.counts.fileEvents, update.counts.networkEvents,
                          QString::fromStdString(update.message));
        });
        if (result) {
            emit succeeded(std::make_shared<const AnalysisReport>(std::move(result).value()));
        } else {
            emit failed(QString::fromStdString(result.error().message), QString::fromStdString(result.error().hint));
        }
    } catch (const std::exception& ex) {
        emit failed(QStringLiteral("Internal error: %1").arg(QString::fromUtf8(ex.what())), QString());
    }
    emit finished();
}

}  // namespace tracepot::gui
