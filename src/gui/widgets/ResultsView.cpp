#include "gui/widgets/ResultsView.hpp"

#include "core/reporting/ReportRender.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QSplitter>
#include <QTabWidget>
#include <QTableView>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace tracepot::gui {

namespace {

QString qs(const std::string& text)
{
    return QString::fromStdString(text);
}

QString esc(const std::string& text)
{
    return QString::fromStdString(text).toHtmlEscaped();
}

QString modeText(std::uint32_t mode)
{
    return QStringLiteral("%1").arg(mode & 07777, 4, 8, QLatin1Char('0'));
}

QString joinArgs(const std::vector<std::string>& argv)
{
    QStringList parts;
    for (const auto& arg : argv) {
        parts << qs(arg);
    }
    return parts.join(QLatin1Char(' '));
}

QString pidList(const std::vector<int>& pids)
{
    QStringList parts;
    for (const int pid : pids) {
        parts << QString::number(pid);
    }
    return parts.join(QStringLiteral(", "));
}

QString evidenceLabel(EvidenceKind kind)
{
    switch (kind) {
    case EvidenceKind::Observed: return QStringLiteral("Observed");
    case EvidenceKind::Inferred: return QStringLiteral("Inferred");
    case EvidenceKind::Missing: return QStringLiteral("Missing");
    case EvidenceKind::Error: return QStringLiteral("Error");
    }
    return {};
}

QString kv(const QString& key, const QString& value)
{
    return QStringLiteral("<tr><th align=\"left\">%1</th><td>%2</td></tr>").arg(key.toHtmlEscaped(), value);
}

QString metadataTable(const FileMetadata& m)
{
    QString html = QStringLiteral("<table cellspacing=\"2\">");
    html += kv(QStringLiteral("Type"), esc(std::string(enumName(m.type))));
    html += kv(QStringLiteral("Mode"), modeText(m.mode));
    html += kv(QStringLiteral("Owner"), QStringLiteral("%1:%2 (as seen inside the sandbox)").arg(m.uid).arg(m.gid));
    html += kv(QStringLiteral("Size"), esc(formatBytes(m.size)));
    if (m.type == FileType::Symlink) {
        html += kv(QStringLiteral("Link target"), QStringLiteral("<code>%1</code>").arg(esc(m.linkTarget)));
    }
    if (m.sha256) {
        html += kv(QStringLiteral("SHA-256"), QStringLiteral("<code>%1</code>").arg(esc(*m.sha256)));
    } else if (!m.hashNote.empty()) {
        html += kv(QStringLiteral("SHA-256"), esc(m.hashNote));
    }
    return html + QStringLiteral("</table>");
}

double originOf(const AnalysisReport& report)
{
    double origin = 0;
    for (const auto& p : report.processes) {
        if (p.startTime && (origin == 0 || *p.startTime < origin)) {
            origin = *p.startTime;
        }
    }
    return origin;
}

QVariant relative(std::optional<double> timestamp, double origin)
{
    if (!timestamp || origin == 0) {
        return {};
    }
    return QStringLiteral("+%1 s").arg(*timestamp - origin, 0, 'f', 3);
}

}  // namespace

ResultsView::ResultsView(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    tabs_ = new QTabWidget(this);
    tabs_->setObjectName(QStringLiteral("resultsTabs"));
    tabs_->setAccessibleName(tr("Analysis results"));
    layout->addWidget(tabs_);

    summary_ = new QTextBrowser(this);
    summary_->setObjectName(QStringLiteral("summaryBrowser"));
    summary_->setAccessibleName(tr("Summary"));
    summary_->setOpenExternalLinks(false);
    tabs_->addTab(summary_, tr("Summary"));

    auto* fileControls = new QWidget(this);
    auto* fileControlsLayout = new QHBoxLayout(fileControls);
    fileControlsLayout->setContentsMargins(0, 0, 0, 0);
    changeKind_ = new QComboBox(fileControls);
    changeKind_->setObjectName(QStringLiteral("changeKindFilter"));
    changeKind_->setAccessibleName(tr("Change kind filter"));
    changeKind_->addItems({tr("All changes"), QStringLiteral("created"), QStringLiteral("modified"),
                           QStringLiteral("deleted")});
    hideTemporary_ = new QCheckBox(tr("Hide temporary paths"), fileControls);
    hideTemporary_->setObjectName(QStringLiteral("hideTemporaryCheck"));
    fileControlsLayout->addWidget(changeKind_);
    fileControlsLayout->addWidget(hideTemporary_);
    files_ = makePage(tr("Filesystem"),
                      {tr("Path"), tr("Change"), tr("Aspects"), tr("Area"), tr("Type"), tr("Mode"), tr("Size"),
                       tr("PIDs"), tr("Evidence")},
                      fileControls);
    connect(changeKind_, &QComboBox::currentIndexChanged, this, [this](int index) {
        files_.proxy->setColumnValue(1, index == 0 ? QString() : changeKind_->currentText());
    });
    connect(hideTemporary_, &QCheckBox::toggled, this, [this](bool hide) {
        files_.proxy->setExcludedValue(3, hide ? QStringLiteral("temporary") : QString());
    });

    processes_ = makePage(tr("Processes"), {tr("Start"), tr("PID"), tr("Parent"), tr("Executable"), tr("Arguments"),
                                            tr("Result"), tr("Evidence")});
    events_ = makePage(tr("Events"), {tr("Time"), tr("PID"), tr("Type"), tr("Path / endpoint"), tr("Target"),
                                      tr("Detail"), tr("Outcome"), tr("Evidence")});
    network_ = makePage(tr("Network"), {tr("Time"), tr("PID"), tr("Kind"), tr("Protocol"), tr("Destination"),
                                        tr("Outcome"), tr("Evidence"), tr("Detail")});
    persistence_ = makePage(tr("Persistence"), {tr("Category"), tr("Scope"), tr("Path"), tr("Action"),
                                                tr("Outcome"), tr("PIDs"), tr("Evidence")});
    diagnostics_ = makePage(tr("Warnings && Limitations"), {tr("Severity"), tr("Kind"), tr("Code"), tr("Message")});

    files_.view->setObjectName(QStringLiteral("fileTable"));
    processes_.view->setObjectName(QStringLiteral("processTable"));
    events_.view->setObjectName(QStringLiteral("eventTable"));
    network_.view->setObjectName(QStringLiteral("networkTable"));
    persistence_.view->setObjectName(QStringLiteral("persistenceTable"));
    diagnostics_.view->setObjectName(QStringLiteral("warningsTable"));
    files_.filter->setObjectName(QStringLiteral("fileFilterEdit"));
    clear();
}

ResultsView::TablePage ResultsView::makePage(const QString& name, const QStringList& headers, QWidget* extraControls)
{
    TablePage page;
    page.page = new QWidget(this);
    auto* layout = new QVBoxLayout(page.page);
    auto* controls = new QHBoxLayout();
    auto* label = new QLabel(tr("&Filter:"), page.page);
    page.filter = new QLineEdit(page.page);
    page.filter->setClearButtonEnabled(true);
    page.filter->setPlaceholderText(tr("Filter %1").arg(QString(name).remove(QLatin1Char('&')).toLower()));
    page.filter->setAccessibleName(tr("%1 filter").arg(QString(name).remove(QLatin1Char('&'))));
    label->setBuddy(page.filter);
    controls->addWidget(label);
    controls->addWidget(page.filter, 1);
    if (extraControls != nullptr) {
        controls->addWidget(extraControls);
    }
    layout->addLayout(controls);

    page.model = new RecordTableModel(headers, page.page);
    page.proxy = new RecordFilterProxy(page.page);
    page.proxy->setSourceModel(page.model);
    page.view = new QTableView(page.page);
    page.view->setModel(page.proxy);
    page.view->setSortingEnabled(true);
    page.view->setSelectionBehavior(QAbstractItemView::SelectRows);
    page.view->setSelectionMode(QAbstractItemView::SingleSelection);
    page.view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    page.view->setAlternatingRowColors(true);
    page.view->setWordWrap(false);
    page.view->horizontalHeader()->setStretchLastSection(true);
    page.view->verticalHeader()->setVisible(false);
    page.view->setAccessibleName(tr("%1 table").arg(QString(name).remove(QLatin1Char('&'))));
    page.details = new QTextBrowser(page.page);
    page.details->setAccessibleName(tr("%1 evidence details").arg(QString(name).remove(QLatin1Char('&'))));
    page.details->setPlaceholderText(tr("Select a row to see its evidence."));

    auto* splitter = new QSplitter(Qt::Vertical, page.page);
    splitter->addWidget(page.view);
    splitter->addWidget(page.details);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    layout->addWidget(splitter, 1);

    connect(page.filter, &QLineEdit::textChanged, page.proxy, &RecordFilterProxy::setText);
    auto* view = page.view;
    auto* details = page.details;
    connect(view->selectionModel(), &QItemSelectionModel::currentRowChanged, details,
            [view, details](const QModelIndex& current) {
                details->setHtml(current.isValid()
                                     ? view->model()->index(current.row(), 0).data(RecordTableModel::DetailsRole).toString()
                                     : QString());
            });
    tabs_->addTab(page.page, name);
    return page;
}

void ResultsView::clear()
{
    report_.reset();
    summary_->setHtml(tr("<p>No report loaded. Start an analysis or open a saved TracePot report.</p>"));
    for (auto* page : {&files_, &processes_, &events_, &network_, &persistence_, &diagnostics_}) {
        page->model->setRows({});
        page->details->clear();
    }
}

void ResultsView::setReport(ReportPtr report)
{
    report_ = std::move(report);
    populate();
}

void ResultsView::populate()
{
    if (!report_) {
        clear();
        return;
    }
    const AnalysisReport& r = *report_;
    const double origin = originOf(r);
    const bool traced = r.sandbox.tracingEnabled;

    // ---- Summary
    QString html;
    html += QStringLiteral("<h2>%1</h2>").arg(esc(r.input.fileName));
    html += QStringLiteral("<p><b>Note:</b> %1</p>").arg(esc(r.disclaimer));
    html += QStringLiteral("<table cellspacing=\"4\">");
    html += kv(tr("Outcome"), esc(describeTermination(r.execution)));
    html += kv(tr("Input"), esc(std::string(enumName(r.input.kind)) + ", " + formatBytes(r.input.sizeBytes)));
    html += kv(tr("SHA-256"), QStringLiteral("<code>%1</code>").arg(esc(r.input.sha256)));
    html += kv(tr("Entry point"), QStringLiteral("<code>%1</code>").arg(esc(r.input.entryPoint)));
    html += kv(tr("Execution time"), QStringLiteral("%1 s").arg(r.execution.executionSeconds, 0, 'f', 2));
    html += kv(tr("Sandbox"), esc(r.sandbox.backend + " " + r.sandbox.backendVersion + "; user: " +
                                  std::string(enumName(r.sandbox.user))));
    html += kv(tr("Network policy"), esc(r.networkPolicy.mode + " — " + r.networkPolicy.description));
    html += kv(tr("Syscall tracing"), traced ? esc(r.sandbox.tracer + " " + r.sandbox.tracerVersion)
                                             : tr("<b>Missing</b>: tracing was unavailable"));
    html += kv(tr("Observed (facts)"),
               tr("%1 processes, %2 filesystem changes, %3 syscall events, %4 network events")
                   .arg(r.processes.size())
                   .arg(r.filesystemChanges.size())
                   .arg(r.events.size())
                   .arg(r.networkEvents.size()));
    html += kv(tr("Inferred"), tr("%1 persistence-related findings").arg(r.persistence.size()));
    html += kv(tr("Host integrity"), esc(r.hostIntegrity.note));
    std::size_t warnings = 0;
    std::size_t errors = 0;
    for (const auto& d : r.diagnostics) {
        warnings += d.severity == Severity::Warning ? 1 : 0;
        errors += d.severity == Severity::Error ? 1 : 0;
    }
    html += kv(tr("Diagnostics"), tr("%1 errors, %2 warnings (see Warnings && Limitations)").arg(errors).arg(warnings));
    html += QStringLiteral("</table>");
    if (!r.execution.stdoutExcerpt.empty()) {
        html += tr("<h3>Captured stdout (untrusted)</h3><pre>%1</pre>").arg(esc(r.execution.stdoutExcerpt));
    }
    if (!r.execution.stderrExcerpt.empty()) {
        html += tr("<h3>Captured stderr (untrusted; includes launcher diagnostics)</h3><pre>%1</pre>")
                    .arg(esc(r.execution.stderrExcerpt));
    }
    summary_->setHtml(html);

    // ---- Filesystem
    QVector<RecordTableModel::Row> rows;
    for (const auto& c : r.filesystemChanges) {
        const FileMetadata* meta = c.after ? &*c.after : (c.before ? &*c.before : nullptr);
        QString mode = meta != nullptr ? modeText(meta->mode) : QString();
        if (c.before && c.after && c.before->mode != c.after->mode) {
            mode = modeText(c.before->mode) + QStringLiteral(" → ") + modeText(c.after->mode);
        }
        QStringList aspects;
        for (const auto& a : c.aspects) {
            aspects << qs(a);
        }
        RecordTableModel::Row row;
        row.values = {qs(c.path),
                      qs(std::string(enumName(c.kind))),
                      aspects.join(QStringLiteral(", ")),
                      qs(c.area),
                      meta != nullptr ? qs(std::string(enumName(meta->type))) : QString(),
                      mode,
                      meta != nullptr ? qs(formatBytes(meta->size)) : QString(),
                      pidList(c.attributedPids),
                      evidenceLabel(EvidenceKind::Observed)};
        row.sortKeys.resize(row.values.size());
        row.sortKeys[6] = meta != nullptr ? QVariant::fromValue<qulonglong>(meta->size) : QVariant();
        QString details = QStringLiteral("<h3><code>%1</code></h3>").arg(esc(c.path));
        details += tr("<p><b>Observed</b> by comparing filesystem snapshots taken before and after execution.</p>");
        details += QStringLiteral("<p>%1 %2</p>").arg(esc(std::string(enumName(c.kind))), aspects.join(QStringLiteral(", ")));
        if (c.before) {
            details += tr("<h4>Before</h4>") + metadataTable(*c.before);
        }
        if (c.after) {
            details += tr("<h4>After</h4>") + metadataTable(*c.after);
        }
        if (!c.attributedPids.empty()) {
            details += tr("<p>Modified by process(es) %1 according to the syscall trace.</p>").arg(pidList(c.attributedPids));
        }
        for (const auto& note : c.notes) {
            details += QStringLiteral("<p><i>%1</i></p>").arg(esc(note));
        }
        if (c.textDiff) {
            details += tr("<h4>Content diff%1</h4><pre>%2</pre>")
                           .arg(c.textDiffTruncated ? tr(" (truncated)") : QString(), esc(*c.textDiff));
        }
        row.details = details;
        rows.push_back(std::move(row));
    }
    files_.model->setRows(std::move(rows));

    // ---- Processes
    rows.clear();
    for (const auto& p : r.processes) {
        QString result;
        if (p.exitCode) {
            result = tr("exit %1").arg(*p.exitCode);
        } else if (!p.signal.empty()) {
            result = qs(p.signal);
        } else {
            result = tr("not observed");
        }
        if (p.terminatedAtTeardown) {
            result += tr(" (sandbox teardown)");
        }
        RecordTableModel::Row row;
        const QString exe = p.executable().empty() ? tr("(forked, no exec)") : qs(p.executable());
        row.values = {relative(p.startTime, origin), p.pid, p.ppid ? QVariant(*p.ppid) : QVariant(), exe,
                      joinArgs(p.argv()), result, evidenceLabel(EvidenceKind::Observed)};
        row.sortKeys = {p.startTime ? QVariant(*p.startTime) : QVariant(), p.pid, p.ppid ? QVariant(*p.ppid) : QVariant()};
        row.sortKeys.resize(row.values.size());
        QString details = tr("<h3>Process %1</h3><p><b>Observed</b> in the syscall trace (PID as seen by the "
                             "tracer).</p><table>")
                              .arg(p.pid);
        details += kv(tr("Parent"), p.ppid ? QString::number(*p.ppid) : tr("unknown / sandbox init"));
        details += kv(tr("Result"), result.toHtmlEscaped());
        details += kv(tr("Threads"), QString::number(p.threadCount));
        details += QStringLiteral("</table><h4>%1</h4><ul>").arg(tr("Program executions"));
        for (const auto& exec : p.execs) {
            details += QStringLiteral("<li><code>%1</code> %2 — %3%4</li>")
                           .arg(esc(exec.path), joinArgs(exec.argv).toHtmlEscaped(),
                                esc(std::string(enumName(exec.outcome))),
                                exec.error.empty() ? QString() : QStringLiteral(" (%1)").arg(esc(exec.error)));
        }
        details += QStringLiteral("</ul>");
        int shown = 0;
        QString events;
        for (const auto& e : r.events) {
            if (e.pid == p.pid && e.type != EventType::ProcessExec && shown++ < 200) {
                events += QStringLiteral("<li>%1 <code>%2</code> %3</li>")
                              .arg(esc(std::string(enumName(e.type))), esc(e.path), esc(std::string(enumName(e.outcome))));
            }
        }
        if (!events.isEmpty()) {
            details += tr("<h4>Events</h4><ul>%1</ul>").arg(events);
        }
        row.details = details;
        rows.push_back(std::move(row));
    }
    processes_.model->setRows(std::move(rows));

    // ---- Events
    rows.clear();
    for (const auto& e : r.events) {
        RecordTableModel::Row row;
        row.values = {relative(e.timestamp, origin),
                      e.pid,
                      qs(std::string(enumName(e.type))),
                      qs(e.path),
                      qs(e.targetPath),
                      qs(e.detail),
                      qs(std::string(enumName(e.outcome)) + (e.error.empty() ? "" : " (" + e.error + ")")),
                      evidenceLabel(EvidenceKind::Observed)};
        row.sortKeys = {e.timestamp, e.pid};
        row.sortKeys.resize(row.values.size());
        row.details = tr("<h3>%1</h3><p><b>Observed</b>: system call <code>%2</code> by process %3.</p><table>%4%5%6%7</table>")
                          .arg(esc(std::string(enumName(e.type))), esc(e.syscall))
                          .arg(e.pid)
                          .arg(kv(tr("Path"), QStringLiteral("<code>%1</code>").arg(esc(e.path))),
                               kv(tr("Target"), QStringLiteral("<code>%1</code>").arg(esc(e.targetPath))),
                               kv(tr("Detail"), esc(e.detail)),
                               kv(tr("Outcome"), esc(std::string(enumName(e.outcome)) +
                                                     (e.error.empty() ? "" : " (" + e.error + ")"))));
        rows.push_back(std::move(row));
    }
    events_.model->setRows(std::move(rows));

    // ---- Network
    rows.clear();
    for (const auto& n : r.networkEvents) {
        QString destination = qs(n.hostname.empty() ? n.address : n.hostname);
        if (!n.hostname.empty() && !n.address.empty()) {
            destination += tr(" via %1").arg(qs(n.address));
        }
        if (n.port) {
            destination += QStringLiteral(":%1").arg(*n.port);
        }
        RecordTableModel::Row row;
        row.values = {relative(n.timestamp, origin),
                      n.pid ? QVariant(*n.pid) : QVariant(),
                      qs(std::string(enumName(n.kind))),
                      qs(n.protocol),
                      destination,
                      qs(std::string(enumName(n.outcome)) + (n.error.empty() ? "" : " (" + n.error + ")")),
                      evidenceLabel(n.evidence),
                      qs(n.detail)};
        row.sortKeys = {n.timestamp ? QVariant(*n.timestamp) : QVariant()};
        row.sortKeys.resize(row.values.size());
        row.details = tr("<h3>%1</h3><p><b>%2</b> (source: %3).</p><p>%4</p><p><i>%5</i></p>")
                          .arg(esc(std::string(enumName(n.kind))), evidenceLabel(n.evidence),
                               esc(std::string(enumName(n.source))), destination.toHtmlEscaped(), esc(n.detail));
        rows.push_back(std::move(row));
    }
    network_.model->setRows(std::move(rows));

    // ---- Persistence
    rows.clear();
    for (const auto& f : r.persistence) {
        QStringList basis;
        for (const auto b : f.basis) {
            basis << qs(std::string(enumName(b)));
        }
        RecordTableModel::Row row;
        row.values = {qs(std::string(enumName(f.category))), qs(f.scope), qs(f.path), qs(f.action), qs(f.outcome),
                      pidList(f.pids), evidenceLabel(EvidenceKind::Inferred)};
        row.details = tr("<h3><code>%1</code></h3><p><b>Inferred</b> classification (rule <code>%2</code>): %3.</p>"
                         "<p>Based on: %4.</p><p>A persistence-related location is not automatically malicious; "
                         "installers legitimately configure services and shells.</p>")
                          .arg(esc(f.path), esc(f.ruleId), esc(f.description), basis.join(QStringLiteral(", ")));
        rows.push_back(std::move(row));
    }
    persistence_.model->setRows(std::move(rows));

    // ---- Diagnostics
    rows.clear();
    for (const auto& d : r.diagnostics) {
        RecordTableModel::Row row;
        row.values = {qs(std::string(enumName(d.severity))), qs(std::string(enumName(d.kind))), qs(d.code),
                      qs(d.message)};
        row.sortKeys = {static_cast<int>(d.severity) * -1};
        row.sortKeys.resize(row.values.size());
        row.details = QStringLiteral("<h3>%1: %2</h3><p>%3</p>")
                          .arg(esc(std::string(enumName(d.severity))), esc(std::string(enumName(d.kind))),
                               esc(d.message));
        rows.push_back(std::move(row));
    }
    if (!traced) {
        RecordTableModel::Row row;
        row.values = {QStringLiteral("warning"), QStringLiteral("limitation"), QStringLiteral("missing-trace"),
                      tr("Process, event and network tables are empty because no syscall trace was collected "
                         "(missing observation, not absence of activity).")};
        rows.push_back(std::move(row));
    }
    diagnostics_.model->setRows(std::move(rows));

    for (auto* page : {&files_, &processes_, &events_, &network_, &persistence_, &diagnostics_}) {
        page->view->resizeColumnsToContents();
        page->details->clear();
    }
}

}  // namespace tracepot::gui
