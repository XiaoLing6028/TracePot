#include "common/TestSupport.hpp"
#include "core/analysis/Analyzer.hpp"
#include "core/observers/TraceCollector.hpp"

#include <QtTest>

#include <algorithm>

using namespace tracepot;

namespace {


// tests/fixtures/traces/bwrap-session.strace is modeled on real
// `strace -f -ttt -q -y --pidns-translation` output of bubblewrap running a script.
const std::string& sampleTrace()
{
    static const std::string trace = test::readFile(test::fixturesDir() / "traces" / "bwrap-session.strace");
    return trace;
}

TraceCollectorOptions options()
{
    TraceCollectorOptions o;
    o.entryExecutable = "/usr/bin/sh";
    o.entryArgv = {"/usr/bin/sh", "/work/install.sh"};
    o.sensitiveReadPatterns = defaultSensitiveReadPatterns();
    return o;
}

const TraceEvent* findEvent(const TraceCollector& c, EventType type, const std::string& path)
{
    const auto& events = c.events();
    const auto it = std::find_if(events.begin(), events.end(),
                                 [&](const TraceEvent& e) { return e.type == type && e.path == path; });
    return it == events.end() ? nullptr : &*it;
}

const ProcessRecord* findProcess(const std::vector<ProcessRecord>& processes, int pid)
{
    const auto it = std::find_if(processes.begin(), processes.end(), [pid](const ProcessRecord& p) { return p.pid == pid; });
    return it == processes.end() ? nullptr : &*it;
}

}  // namespace

class TestTraceCollector : public QObject {
    Q_OBJECT

private:
    static void verifyCollected(const TraceCollector& c)
    {
        QVERIFY(c.entryObserved());
        QCOMPARE(*c.entryPid(), 1301);
        QCOMPARE(c.linesMalformed(), std::uint64_t{0});

        const auto processes = c.processes();
        QCOMPARE(processes.size(), std::size_t{4});
        QVERIFY(findProcess(processes, 1299) == nullptr);  // bubblewrap, not part of the sample
        QVERIFY(findProcess(processes, 1300) == nullptr);
        QVERIFY(findProcess(processes, 1304) == nullptr);  // a thread, not a process

        const auto* entry = findProcess(processes, 1301);
        QVERIFY(entry != nullptr);
        QVERIFY(!entry->ppid.has_value());
        QCOMPARE(*entry->exitCode, 3);
        QCOMPARE(QString::fromStdString(entry->executable()), QStringLiteral("/usr/bin/sh"));

        const auto* mkdir = findProcess(processes, 1302);
        QVERIFY(mkdir != nullptr);
        QCOMPARE(*mkdir->ppid, 1301);
        QCOMPARE(mkdir->argv(), (std::vector<std::string>{"mkdir", "-p", "d/e"}));
        QCOMPARE(*mkdir->exitCode, 0);

        const auto* curl = findProcess(processes, 1303);
        QCOMPARE(*curl->exitCode, 6);
        QCOMPARE(curl->threadCount, 1);

        const auto* sleep = findProcess(processes, 1305);
        QCOMPARE(QString::fromStdString(sleep->signal), QStringLiteral("SIGKILL"));
        QVERIFY(sleep->terminatedAtTeardown);
        QVERIFY(!entry->terminatedAtTeardown);

        // File events, attributed and resolved to absolute sandbox paths.
        QVERIFY(findEvent(c, EventType::FileWrite, "/work/out.txt") != nullptr);
        QCOMPARE(findEvent(c, EventType::DirectoryCreate, "/work/d")->pid, 1302);
        QVERIFY(findEvent(c, EventType::DirectoryCreate, "/work/d/e") != nullptr);  // resolved through fchdir
        QVERIFY(findEvent(c, EventType::DirectoryCreate, "/work") == nullptr);      // EEXIST noise dropped
        QVERIFY(findEvent(c, EventType::DirectoryCreate, "/newroot/work") == nullptr);  // bwrap setup ignored
        const auto* link = findEvent(c, EventType::SymlinkCreate, "/work/link");
        QCOMPARE(QString::fromStdString(link->targetPath), QStringLiteral("out.txt"));
        QCOMPARE(QString::fromStdString(findEvent(c, EventType::PermissionChange, "/work/out.txt")->detail),
                 QStringLiteral("0755"));
        QCOMPARE(QString::fromStdString(findEvent(c, EventType::FileRename, "/work/out.txt")->targetPath),
                 QStringLiteral("/work/renamed.txt"));
        QVERIFY(findEvent(c, EventType::DirectoryDelete, "/work/d/e") != nullptr);
        const auto* secret = findEvent(c, EventType::SensitiveRead, "/home/tracepot/.ssh/id_rsa");
        QVERIFY(secret != nullptr);
        QCOMPARE(secret->outcome, Outcome::Failed);
        const auto* cron = findEvent(c, EventType::FileWrite, "/etc/cron.d/job");
        QCOMPARE(QString::fromStdString(cron->error), QStringLiteral("EROFS"));
        QVERIFY(findEvent(c, EventType::FileWrite, "/dev/null") == nullptr);
        QCOMPARE(findEvent(c, EventType::FileWrite, "/work/thread-file")->pid, 1303);  // thread -> process
        QCOMPARE(c.readOnlyOpens(), std::uint64_t{2});

        // Network observations.
        const auto& net = c.networkEvents();
        auto findNet = [&](NetworkEventKind kind, const std::string& key) -> const NetworkEvent* {
            for (const auto& n : net) {
                if (n.kind == kind && (n.hostname == key || n.address == key)) {
                    return &n;
                }
            }
            return nullptr;
        };
        const auto* dns = findNet(NetworkEventKind::DnsQuery, "example.com");
        QVERIFY(dns != nullptr);
        QVERIFY(dns->detail.find("AAAA") != std::string::npos);
        QCOMPARE(QString::fromStdString(dns->address), QStringLiteral("127.0.0.1"));
        QVERIFY(findNet(NetworkEventKind::DnsQuery, "test.invalid") != nullptr);  // via sendmmsg on a connected socket
        const auto* blocked = findNet(NetworkEventKind::Connect, "198.51.100.7");
        QVERIFY(blocked != nullptr);
        QCOMPARE(blocked->outcome, Outcome::Failed);
        QCOMPARE(QString::fromStdString(blocked->protocol), QStringLiteral("tcp"));
        QCOMPARE(*blocked->port, 443);
        QCOMPARE(blocked->evidence, EvidenceKind::Observed);
        const auto* inferred = findNet(NetworkEventKind::InferredDestination, "downloads.example.com");
        QVERIFY(inferred != nullptr);
        QCOMPARE(inferred->evidence, EvidenceKind::Inferred);
        QCOMPARE(*inferred->port, 8443);
        QVERIFY(inferred->detail.find("pw") == std::string::npos);  // credentials never reported
        QVERIFY(inferred->detail.find("[credentials]") != std::string::npos);

        QCOMPARE(c.limitEvents().size(), std::size_t{1});
        QCOMPARE(QString::fromStdString(c.limitEvents().front().limit), QStringLiteral("process-count"));
    }

private slots:
    void collectsWholeTrace()
    {
        TraceCollector collector(options());
        collector.feed(sampleTrace());
        collector.finish();
        verifyCollected(collector);
    }

    void handlesArbitraryChunkBoundaries()
    {
        const std::string& trace = sampleTrace();
        for (const std::size_t chunk : {std::size_t{1}, std::size_t{7}, std::size_t{64}, std::size_t{4093}}) {
            TraceCollector collector(options());
            for (std::size_t i = 0; i < trace.size(); i += chunk) {
                collector.feed(std::string_view(trace).substr(i, chunk));
            }
            collector.finish();
            verifyCollected(collector);
        }
    }

    void ignoresEverythingWithoutEntry()
    {
        auto o = options();
        o.entryArgv = {"/usr/bin/sh", "/work/other.sh"};
        TraceCollector collector(o);
        collector.feed(sampleTrace());
        collector.finish();
        QVERIFY(!collector.entryObserved());
        QVERIFY(collector.events().empty());
        QVERIFY(collector.processes().empty());
        QVERIFY(!collector.warnings().empty());
    }

    void enforcesEventLimit()
    {
        auto o = options();
        o.maxEvents = 3;
        TraceCollector collector(o);
        collector.feed(sampleTrace());
        collector.finish();
        QCOMPARE(collector.events().size(), std::size_t{3});
        QVERIFY(collector.eventsDropped() > 0);
    }

    void dropsOversizedLines()
    {
        auto o = options();
        o.maxLineBytes = 200;
        TraceCollector collector(o);
        collector.feed(sampleTrace());
        collector.feed("1301  100.5 openat(AT_FDCWD</work>, \"" + std::string(1000, 'a') + "\", O_WRONLY) = 3\n");
        collector.finish();
        QVERIFY(collector.linesMalformed() >= 1);
        QVERIFY(collector.entryObserved());
    }

    void countsForProgress()
    {
        TraceCollector collector(options());
        collector.feed(sampleTrace());
        const auto counts = collector.counts();
        QCOMPARE(counts.processes, std::uint64_t{4});
        QVERIFY(counts.fileEvents >= 9);
        QVERIFY(counts.networkEvents >= 4);
    }
};

QTEST_GUILESS_MAIN(TestTraceCollector)
#include "tst_trace_collector.moc"
