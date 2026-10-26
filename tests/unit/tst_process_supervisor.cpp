// Timeout and cancellation state handling of the process supervisor that launches the sandbox.

#include "core/analysis/Cancellation.hpp"
#include "core/sandbox/ProcessSupervisor.hpp"

#include <QElapsedTimer>
#include <QFile>
#include <QtTest>

#include <csignal>

#include <sys/wait.h>
#include <unistd.h>

using namespace tracepot;
using namespace std::chrono_literals;

class TestProcessSupervisor : public QObject {
    Q_OBJECT

private:
    // True if the process exists and is not a zombie (zombies are dead but not yet reaped).
    static bool alive(pid_t pid)
    {
        QFile stat(QStringLiteral("/proc/%1/stat").arg(pid));
        if (!stat.open(QIODevice::ReadOnly)) {
            return false;
        }
        const QByteArray content = stat.readAll();
        const int close = content.lastIndexOf(')');
        return close > 0 && close + 2 < content.size() && content.at(close + 2) != 'Z';
    }

    static SpawnSpec shell(const std::string& script)
    {
        SpawnSpec spec;
        spec.executable = "/bin/sh";
        spec.argv = {"sh", "-c", script};
        return spec;
    }

private slots:
    void reportsExitCode()
    {
        ProcessSupervisor process;
        QVERIFY(process.start(shell("exit 7")).ok());
        const auto status = process.waitFor(10s);
        QVERIFY(status.has_value());
        QVERIFY(status->exited);
        QCOMPARE(status->code, 7);
        QVERIFY(!process.running());
    }

    void reportsSignals()
    {
        ProcessSupervisor process;
        QVERIFY(process.start(shell("kill -SEGV $$")).ok());
        const auto status = process.waitFor(10s);
        QVERIFY(status.has_value());
        QVERIFY(!status->exited);
        QCOMPARE(status->signal, SIGSEGV);
        QCOMPARE(QString::fromStdString(signalName(SIGSEGV)), QStringLiteral("SIGSEGV"));
    }

    void timeoutLeavesProcessRunningUntilKilled()
    {
        ProcessSupervisor process;
        QVERIFY(process.start(shell("sleep 30")).ok());
        QElapsedTimer timer;
        timer.start();
        QVERIFY(!process.waitFor(300ms).has_value());  // timed out: still running
        QVERIFY(process.running());
        QVERIFY(timer.elapsed() >= 250);
        process.signalGroup(SIGKILL);
        const auto status = process.waitFor(10s);
        QVERIFY(status.has_value());
        QCOMPARE(status->signal, SIGKILL);
        QVERIFY(timer.elapsed() < 5000);
    }

    void groupKillReachesGrandchildren()
    {
        // The supervised process starts a background grandchild; killing the group must reach it.
        ProcessSupervisor process;
        QVERIFY(process.start(shell("sleep 30 & echo $! > /dev/null; wait")).ok());
        QVERIFY(!process.waitFor(200ms).has_value());
        const auto children = childProcesses(process.pid());
        QVERIFY(!children.empty());
        QVERIFY(alive(children.front()));
        process.signalGroup(SIGKILL);
        QVERIFY(process.waitFor(10s).has_value());
        QTRY_VERIFY_WITH_TIMEOUT(!alive(children.front()), 5000);
    }

    void destructorKillsRunningChild()
    {
        pid_t pid = -1;
        {
            ProcessSupervisor process;
            QVERIFY(process.start(shell("sleep 30")).ok());
            pid = process.pid();
            QVERIFY(::kill(pid, 0) == 0);
        }
        QVERIFY(!alive(pid));  // killed and reaped
    }

    void launchFailureIsReported()
    {
        ProcessSupervisor process;
        SpawnSpec spec;
        spec.executable = "/nonexistent/tracepot-binary";
        spec.argv = {"x"};
        const auto status = process.start(spec);
        QVERIFY(!status.ok());
        QCOMPARE(status.error().code, ErrorCode::LaunchFailed);
        SpawnSpec relative;
        relative.executable = "sh";
        QVERIFY(!ProcessSupervisor().start(relative).ok());
    }

    void environmentIsNotInherited()
    {
        qputenv("TRACEPOT_SECRET_TEST", "leak");
        auto run = runAndCapture("/bin/sh", {"sh", "-c", "echo \"[$TRACEPOT_SECRET_TEST]\"; echo err >&2"}, 10s);
        QVERIFY(run.ok());
        QCOMPARE(QString::fromStdString(run->out), QStringLiteral("[]\n"));
        QCOMPARE(QString::fromStdString(run->err), QStringLiteral("err\n"));
        QVERIFY(!run->timedOut);
    }

    void captureTimesOut()
    {
        auto run = runAndCapture("/bin/sh", {"sh", "-c", "sleep 30"}, 300ms);
        QVERIFY(run.ok());
        QVERIFY(run->timedOut);
        QCOMPARE(run->status.signal, SIGKILL);
    }

    void cancellationToken()
    {
        CancellationToken token;
        QVERIFY(!token.cancelled());
        token.cancel();
        QVERIFY(token.cancelled());
        token.cancel();  // idempotent
        QVERIFY(token.cancelled());
    }
};

QTEST_GUILESS_MAIN(TestProcessSupervisor)
#include "tst_process_supervisor.moc"
