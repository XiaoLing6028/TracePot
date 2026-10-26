#include "common/TestSupport.hpp"
#include "core/reporting/ReportJson.hpp"
#include "core/reporting/ReportRender.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <nlohmann/json.hpp>

using namespace tracepot;

namespace {

AnalysisReport sampleReport()
{
    AnalysisReport r;
    r.schemaVersion = reportSchemaVersionString();
    r.applicationName = "TracePot";
    r.applicationVersion = "0.1.0";
    r.analysisId = "tracepot-test-0001";
    r.disclaimer = reportDisclaimer();
    r.startedAt = "2026-01-01T00:00:00.000Z";
    r.finishedAt = "2026-01-01T00:00:05.000Z";
    r.durationSeconds = 5;
    r.input.fileName = "tracepot-fixture.sh";
    r.input.sha256 = std::string(64, 'a');
    r.input.sizeBytes = 42;
    r.input.kind = InputKind::ShellScript;
    r.input.interpreter = "sh";
    r.input.entryPoint = "/work/tracepot-fixture.sh";
    r.input.arguments = {"--prefix", "/opt/x"};
    r.input.environmentKeys = {"TOKEN"};
    r.sandbox.backend = "bubblewrap";
    r.sandbox.user = SandboxUser::SimulatedRoot;
    r.sandbox.seccompEnabled = true;
    r.sandbox.seccompBlocked = {"bpf"};
    r.sandbox.tracingEnabled = true;
    r.sandbox.limits.timeoutSeconds = 30;
    r.networkPolicy.mode = "isolated";
    r.execution.reason = TerminationReason::Signaled;
    r.execution.signal = "SIGSEGV";
    r.execution.stdoutExcerpt = "out <b>bold</b>";

    ProcessRecord p;
    p.pid = 100;
    p.startTime = 10.5;
    p.execs.push_back({10.5, "/usr/bin/sh", {"/usr/bin/sh", "/work/tracepot-fixture.sh"}, Outcome::Success, ""});
    p.signal = "SIGSEGV";
    r.processes.push_back(p);
    ProcessRecord child;
    child.pid = 101;
    child.ppid = 100;
    child.exitCode = 0;
    r.processes.push_back(child);

    TraceEvent e;
    e.seq = 1;
    e.timestamp = 10.6;
    e.pid = 100;
    e.type = EventType::FileWrite;
    e.syscall = "openat";
    e.path = "/home/tracepot/.bashrc";
    e.outcome = Outcome::Success;
    r.events.push_back(e);

    FileChange c;
    c.path = "/home/tracepot/.bashrc";
    c.kind = ChangeKind::Modified;
    c.aspects = {"content", "permissions"};
    c.area = "home";
    FileMetadata before;
    before.type = FileType::Regular;
    before.mode = 0644;
    before.size = 10;
    before.sha256 = std::string(64, 'b');
    FileMetadata after = before;
    after.mode = 04755;
    after.sha256.reset();
    after.hashNote = "not hashed";
    c.before = before;
    c.after = after;
    c.textDiff = "--- a\n+++ b\n+<script>alert(1)</script>\n";
    c.attributedPids = {100};
    r.filesystemChanges.push_back(c);

    NetworkEvent n;
    n.timestamp = 10.7;
    n.pid = 100;
    n.kind = NetworkEventKind::DnsQuery;
    n.hostname = "example.com";
    n.port = 53;
    n.outcome = Outcome::Success;
    r.networkEvents.push_back(n);
    NetworkEvent inferred;
    inferred.kind = NetworkEventKind::InferredDestination;
    inferred.evidence = EvidenceKind::Inferred;
    inferred.source = ObservationSource::CommandLine;
    inferred.hostname = "example.org";
    r.networkEvents.push_back(inferred);

    PersistenceFinding f;
    f.category = PersistenceCategory::ShellStartup;
    f.scope = "user";
    f.path = c.path;
    f.action = "modified";
    f.outcome = "applied-in-sandbox";
    f.ruleId = "shell-startup-user";
    f.basis = {ObservationSource::FilesystemDiff, ObservationSource::SyscallTrace};
    f.pids = {100};
    r.persistence.push_back(f);
    r.resourceLimitEvents.push_back({std::nullopt, "disk", "too big"});
    r.hostIntegrity.performed = true;
    r.hostIntegrity.pathsChecked = {"/home/alice/.bashrc"};
    r.diagnostics.push_back({Severity::Warning, DiagnosticKind::Limitation, "no-trace", "missing"});
    return r;
}

}  // namespace

class TestReportJson : public QObject {
    Q_OBJECT

private slots:
    void roundTrip()
    {
        const AnalysisReport original = sampleReport();
        const std::string json = serializeReport(original);
        auto parsed = parseReport(json);
        QVERIFY2(parsed.ok(), parsed.ok() ? "" : parsed.error().message.c_str());
        const AnalysisReport& r = parsed.value();
        QCOMPARE(QString::fromStdString(r.analysisId), QStringLiteral("tracepot-test-0001"));
        QCOMPARE(QString::fromStdString(r.applicationName), QStringLiteral("TracePot"));
        QCOMPARE(r.input.kind, InputKind::ShellScript);
        QCOMPARE(r.input.arguments, original.input.arguments);
        QCOMPARE(r.sandbox.user, SandboxUser::SimulatedRoot);
        QCOMPARE(r.execution.reason, TerminationReason::Signaled);
        QVERIFY(!r.execution.exitCode.has_value());
        QCOMPARE(r.processes.size(), std::size_t{2});
        QCOMPARE(*r.processes[1].ppid, 100);
        QVERIFY(!r.processes[0].ppid.has_value());
        QCOMPARE(r.processes[0].execs.front().argv, original.processes[0].execs.front().argv);
        QCOMPARE(r.events.front().type, EventType::FileWrite);
        const auto& change = r.filesystemChanges.front();
        QCOMPARE(change.before->mode, 0644u);
        QCOMPARE(change.after->mode, 04755u);
        QVERIFY(change.before->sha256.has_value());
        QVERIFY(!change.after->sha256.has_value());
        QCOMPARE(change.aspects, original.filesystemChanges.front().aspects);
        QCOMPARE(r.networkEvents[1].evidence, EvidenceKind::Inferred);
        QVERIFY(!r.networkEvents[1].timestamp.has_value());
        QCOMPARE(r.persistence.front().basis.size(), std::size_t{2});
        QVERIFY(!r.resourceLimitEvents.front().timestamp.has_value());
        QCOMPARE(r.diagnostics.front().severity, Severity::Warning);
        // Serializing the parsed report reproduces the same document.
        QCOMPARE(serializeReport(r), json);
    }

    void missingValuesAreExplicitNulls()
    {
        const auto doc = nlohmann::json::parse(serializeReport(sampleReport()));
        QVERIFY(doc["execution"]["exitCode"].is_null());
        QVERIFY(doc["processes"][0]["ppid"].is_null());
        QVERIFY(doc["input"]["archive"].is_null());
        QVERIFY(doc["filesystemChanges"][0]["after"]["sha256"].is_null());
        QCOMPARE(QString::fromStdString(doc["filesystemChanges"][0]["after"]["mode"].get<std::string>()),
                 QStringLiteral("4755"));
        QCOMPARE(QString::fromStdString(doc["persistence"][0]["evidence"].get<std::string>()), QStringLiteral("inferred"));
        QVERIFY(!doc.contains("verdict"));  // TracePot never declares a sample safe
        QVERIFY(doc["input"].contains("environmentKeys"));
        QVERIFY(serializeReport(sampleReport()).find("TOKEN=") == std::string::npos);
    }

    void schemaVersioning()
    {
        auto doc = nlohmann::json::parse(serializeReport(sampleReport()));
        QCOMPARE(QString::fromStdString(doc["schema"].get<std::string>()), QStringLiteral("tracepot-report"));
        QCOMPARE(QString::fromStdString(doc["schemaVersion"].get<std::string>()), QStringLiteral("1.0"));

        doc["schemaVersion"] = "1.7";  // newer minor: accepted, unknown fields ignored
        doc["futureField"] = {{"x", 1}};
        QVERIFY(parseReport(doc.dump()).ok());

        doc["schemaVersion"] = "2.0";
        auto major = parseReport(doc.dump());
        QVERIFY(!major.ok());
        QCOMPARE(major.error().code, ErrorCode::ReportInvalid);

        doc["schemaVersion"] = "garbage";
        QVERIFY(!parseReport(doc.dump()).ok());
        doc["schemaVersion"] = "1.0";
        doc["schema"] = "something-else";
        QVERIFY(!parseReport(doc.dump()).ok());
        QVERIFY(!parseReport("{not json").ok());
        QVERIFY(!parseReport("[]").ok());

        auto wrongType = nlohmann::json::parse(serializeReport(sampleReport()));
        wrongType["processes"] = "not an array";
        QVERIFY(!parseReport(wrongType.dump()).ok());
    }

    void schemaFileMatchesSerializer()
    {
        const auto schema = nlohmann::json::parse(test::readFile(TRACEPOT_SCHEMA_FILE));
        const auto doc = nlohmann::json::parse(serializeReport(sampleReport()));
        for (const auto& key : schema["required"]) {
            QVERIFY2(doc.contains(key.get<std::string>()), key.get<std::string>().c_str());
        }
        for (const auto& [key, value] : doc.items()) {
            QVERIFY2(schema["properties"].contains(key), key.c_str());
        }
        QCOMPARE(QString::fromStdString(schema["properties"]["schemaVersion"]["pattern"].get<std::string>()),
                 QStringLiteral("^1\\.[0-9]+$"));
    }

    void fileRoundTrip()
    {
        QTemporaryDir dir;
        const auto path = std::filesystem::path(dir.path().toStdString()) / "report.json";
        QVERIFY(writeTextFileAtomic(path, serializeReport(sampleReport())).ok());
        auto loaded = loadReportFile(path);
        QVERIFY(loaded.ok());
        QCOMPARE(QString::fromStdString(loaded->analysisId), QStringLiteral("tracepot-test-0001"));
        QVERIFY(!loadReportFile(path.parent_path() / "missing.json").ok());
    }

    void sampleFixtureLoads()
    {
        auto loaded = loadReportFile(test::fixturesDir() / "sample-report.json");
        QVERIFY2(loaded.ok(), loaded.ok() ? "" : loaded.error().message.c_str());
        QVERIFY(!loaded->filesystemChanges.empty());
        QVERIFY(!loaded->diagnostics.empty());
    }

    void htmlEscapesUntrustedContent()
    {
        const std::string html = renderHtmlReport(sampleReport());
        QVERIFY(html.find("<script>") == std::string::npos);
        QVERIFY(html.find("&lt;script&gt;alert(1)&lt;/script&gt;") != std::string::npos);
        QVERIFY(html.find("out &lt;b&gt;bold&lt;/b&gt;") != std::string::npos);
        QVERIFY(html.find("TracePot report") != std::string::npos);
        QVERIFY(html.find("does not mean the input is safe") != std::string::npos);
    }

    void textSummary()
    {
        const std::string text = renderTextSummary(sampleReport(), true);
        QVERIFY(text.find("terminated by SIGSEGV") != std::string::npos);
        QVERIFY(text.find("shell-startup") != std::string::npos);
        QVERIFY(text.find("Filesystem changes: 1") != std::string::npos);
    }
};

QTEST_GUILESS_MAIN(TestReportJson)
#include "tst_report_json.moc"
