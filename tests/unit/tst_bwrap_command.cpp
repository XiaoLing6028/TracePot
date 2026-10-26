#include "core/sandbox/BwrapCommand.hpp"
#include "core/util/PathUtil.hpp"

#include <QtTest>

#include <algorithm>

using namespace tracepot;

namespace {

SandboxRequest request(SandboxUser user)
{
    SandboxRequest r;
    r.bwrapPath = "/usr/bin/bwrap";
    r.features.clearenv = true;
    r.features.disableUserns = true;
    r.features.tmpfsSize = true;
    r.features.unshareCgroupTry = true;
    r.rootDir = "/ws/root";
    r.user = user;
    r.interpreterPath = "/usr/bin/sh";
    r.scriptPath = "/work/install.sh";
    r.arguments = {"--prefix=/opt/x", "a b; rm -rf / $(id)"};
    r.environment = {{"FOO", "bar baz"}};
    r.seccompFd = 10;
    return r;
}

bool hasSequence(const std::vector<std::string>& argv, const std::vector<std::string>& sequence)
{
    return std::search(argv.begin(), argv.end(), sequence.begin(), sequence.end()) != argv.end();
}

}  // namespace

class TestBwrapCommand : public QObject {
    Q_OBJECT

private slots:
    void namespacesAndHardening()
    {
        auto plan = buildSandboxPlan(request(SandboxUser::Unprivileged));
        QVERIFY(plan.ok());
        const auto& argv = plan->argv;
        for (const char* flag : {"--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-net",
                                 "--die-with-parent", "--new-session", "--clearenv", "--disable-userns"}) {
            QVERIFY2(std::find(argv.begin(), argv.end(), flag) != argv.end(), flag);
        }
        QVERIFY(hasSequence(argv, {"--cap-drop", "ALL"}));
        QVERIFY(hasSequence(argv, {"--seccomp", "10"}));
        QVERIFY(hasSequence(argv, {"--uid", "1000", "--gid", "1000"}));
        QVERIFY(hasSequence(argv, {"--hostname", "tracepot-sandbox"}));
        QVERIFY(hasSequence(argv, {"--chdir", "/work"}));
        QVERIFY(plan->nestedUserNamespacesDisabled);
        // Nothing from the invoking user's environment is passed through.
        QVERIFY(hasSequence(argv, {"--setenv", "HOME", "/home/tracepot"}));
        QVERIFY(hasSequence(argv, {"--setenv", "FOO", "bar baz"}));
    }

    void minimalFilesystemView()
    {
        auto plan = buildSandboxPlan(request(SandboxUser::Unprivileged));
        const auto& argv = plan->argv;
        QVERIFY(hasSequence(argv, {"--ro-bind", "/usr", "/usr"}));
        QVERIFY(hasSequence(argv, {"--ro-bind", "/ws/root/etc", "/etc"}));
        QVERIFY(hasSequence(argv, {"--bind", "/ws/root/home/tracepot", "/home/tracepot"}));
        QVERIFY(hasSequence(argv, {"--bind", "/ws/root/work", "/work"}));
        QVERIFY(hasSequence(argv, {"--bind", "/ws/root/tmp", "/tmp"}));
        // Only workspace paths are writable from the host's point of view.
        for (const auto& path : plan->hostWritablePaths) {
            QVERIFY2(path.rfind("/ws/root/", 0) == 0, path.c_str());
        }
        // The host's home directory, runtime directory and sockets are never bound.
        const std::string home = hostHomeDirectory().string();
        for (std::size_t i = 0; i + 1 < argv.size(); ++i) {
            if (argv[i] == "--bind" || argv[i] == "--ro-bind") {
                const std::string& source = argv[i + 1];
                QVERIFY2(source == "/usr" || source.rfind("/ws/root/", 0) == 0 || source.rfind("/lib", 0) == 0 ||
                             source == "/bin" || source == "/sbin",
                         source.c_str());
                QVERIFY(home.empty() || source != home);
            }
        }
        QVERIFY(std::find(argv.begin(), argv.end(), "/run/user/0") == argv.end());
    }

    void simulatedRootMakesSystemDirectoriesWritable()
    {
        auto plan = buildSandboxPlan(request(SandboxUser::SimulatedRoot));
        QVERIFY(plan.ok());
        QVERIFY(hasSequence(plan->argv, {"--bind", "/ws/root/etc", "/etc"}));
        QVERIFY(hasSequence(plan->argv, {"--uid", "0", "--gid", "0"}));
        QVERIFY(hasSequence(plan->argv, {"--setenv", "HOME", "/root"}));
        QVERIFY(std::find(plan->writablePaths.begin(), plan->writablePaths.end(), "/etc") != plan->writablePaths.end());
    }

    void argumentsAreNotShellParsed()
    {
        auto plan = buildSandboxPlan(request(SandboxUser::Unprivileged));
        const std::vector<std::string> expected = {"/usr/bin/sh", "/work/install.sh", "--prefix=/opt/x",
                                                   "a b; rm -rf / $(id)"};
        QCOMPARE(plan->entryArgv, expected);
        QVERIFY(hasSequence(plan->argv, {"--", "/usr/bin/sh", "/work/install.sh", "--prefix=/opt/x", "a b; rm -rf / $(id)"}));
        QCOMPARE(plan->argv.back(), std::string("a b; rm -rf / $(id)"));
    }

    void rejectsInvalidEnvironment()
    {
        auto bad = request(SandboxUser::Unprivileged);
        bad.environment = {{"BAD-NAME", "x"}};
        QVERIFY(!buildSandboxPlan(bad).ok());
        QVERIFY(isValidEnvironmentName("GOOD_NAME1"));
        QVERIFY(!isValidEnvironmentName("1BAD"));
        QVERIFY(!isValidEnvironmentName(""));
        QVERIFY(!isValidEnvironmentName("A=B"));
    }

    void fallsBackWithoutClearenv()
    {
        auto r = request(SandboxUser::Unprivileged);
        r.features.clearenv = false;
        auto plan = buildSandboxPlan(r);
        QVERIFY(std::find(plan->argv.begin(), plan->argv.end(), "--clearenv") == plan->argv.end());
        QVERIFY(hasSequence(plan->argv, {"--unsetenv", "LANG"}));
    }

    void parsesFeatures()
    {
        const auto features = parseBwrapFeatures("usage: bwrap [OPTIONS...]\n  --clearenv  Unset all\n  --size BYTES\n",
                                                 "bubblewrap 0.9.0\n");
        QVERIFY(features.clearenv);
        QVERIFY(features.tmpfsSize);
        QVERIFY(!features.disableUserns);
        QCOMPARE(QString::fromStdString(features.version), QStringLiteral("bubblewrap 0.9.0"));
    }
};

QTEST_GUILESS_MAIN(TestBwrapCommand)
#include "tst_bwrap_command.moc"
