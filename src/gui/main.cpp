#include "Version.hpp"
#include "gui/AnalysisWorker.hpp"
#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QCommandLineParser>

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("TracePot"));
    QApplication::setApplicationDisplayName(QStringLiteral("TracePot"));
    QApplication::setApplicationVersion(QString::fromUtf8(tracepot::kApplicationVersion.data(),
                                                          static_cast<int>(tracepot::kApplicationVersion.size())));
    QApplication::setDesktopFileName(QStringLiteral("tracepot"));
    qRegisterMetaType<tracepot::gui::ReportPtr>();

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("TracePot — Linux installer behavior analysis"));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption reportOption(QStringLiteral("report"), QStringLiteral("Open a saved TracePot report."),
                                    QStringLiteral("file"));
    parser.addOption(reportOption);
    parser.addPositionalArgument(QStringLiteral("input"), QStringLiteral("Installer to preselect (optional)."));
    parser.process(app);

    tracepot::gui::MainWindow window;
    if (parser.isSet(reportOption)) {
        window.loadReportFile(parser.value(reportOption));
    }
    if (!parser.positionalArguments().isEmpty()) {
        window.setInputPath(parser.positionalArguments().constFirst());
    }
    window.show();
    return QApplication::exec();
}
