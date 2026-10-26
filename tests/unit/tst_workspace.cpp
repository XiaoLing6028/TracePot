#include "common/TestSupport.hpp"
#include "core/sandbox/Workspace.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <sys/stat.h>

using namespace tracepot;
namespace fs = std::filesystem;

class TestWorkspace : public QObject {
    Q_OBJECT

private slots:
    void createsPrivateDirectories()
    {
        QTemporaryDir base;
        auto workspace = Workspace::create(base.path().toStdString(), "tracepot-test-1");
        QVERIFY(workspace.ok());
        const auto& paths = workspace->paths();
        struct stat st {};
        QCOMPARE(::stat(paths.runDir.c_str(), &st), 0);
        QCOMPARE(st.st_mode & 0777, 0700u);
        for (const auto& dir : {paths.rootDir, paths.inputDir, paths.traceLog.parent_path(), paths.stdoutLog.parent_path()}) {
            QVERIFY(fs::is_directory(dir));
        }
        // The trace and the input copy live outside the tree that is mounted into the sandbox.
        QVERIFY(paths.traceLog.string().rfind(paths.rootDir.string(), 0) != 0);
        QVERIFY(paths.inputDir.string().rfind(paths.rootDir.string(), 0) != 0);
    }

    void rejectsUnsafeIdentifiersAndExistingDirectories()
    {
        QTemporaryDir base;
        QVERIFY(!Workspace::create(base.path().toStdString(), "../escape").ok());
        QVERIFY(!Workspace::create(base.path().toStdString(), "").ok());
        QVERIFY(!Workspace::create(base.path().toStdString(), ".hidden").ok());
        fs::create_directory(fs::path(base.path().toStdString()) / "taken");
        QVERIFY(!Workspace::create(base.path().toStdString(), "taken").ok());
        fs::create_symlink("/tmp", fs::path(base.path().toStdString()) / "planted");
        QVERIFY(!Workspace::create(base.path().toStdString(), "planted").ok());
    }

    void populatesSandboxRootWithoutSecrets()
    {
        QTemporaryDir base;
        auto workspace = Workspace::create(base.path().toStdString(), "tracepot-test-2");
        QVERIFY(workspace.ok());
        QVERIFY(workspace->populateSandboxRoot(SandboxUser::Unprivileged).ok());
        const fs::path root = workspace->paths().rootDir;
        QVERIFY(fs::is_directory(root / "home/tracepot/.config"));
        QVERIFY(fs::exists(root / "home/tracepot/.bashrc"));
        QVERIFY(fs::exists(root / "root/.profile"));
        QVERIFY(fs::is_directory(root / "etc/systemd/system"));
        QVERIFY(fs::is_directory(root / "work"));
        const std::string passwd = test::readFile(root / "etc/passwd");
        QVERIFY(passwd.find("tracepot:x:1000:1000") != std::string::npos);
        QCOMPARE(test::readFile(root / "etc/hostname"), std::string("tracepot-sandbox\n"));
        // Never copied, even when readable (e.g. when running as root).
        for (const char* secret : {"etc/shadow", "etc/gshadow", "etc/sudoers", "etc/ssh", "etc/environment", "etc/apt/auth.conf.d"}) {
            QVERIFY2(!fs::exists(root / secret), secret);
        }
        // The machine-id is synthesized so the host's identifier is not exposed.
        const std::string machineId = test::readFile(root / "etc/machine-id");
        QCOMPARE(machineId.size(), std::size_t{33});
        if (fs::exists("/etc/machine-id")) {
            QVERIFY(machineId != test::readFile("/etc/machine-id"));
        }
        struct stat st {};
        QCOMPARE(::stat((root / "tmp").c_str(), &st), 0);
        QCOMPARE(st.st_mode & 07777, 01777u);
    }

    void removalHandlesHostileTrees()
    {
        QTemporaryDir base;
        fs::path runDir;
        {
            auto workspace = Workspace::create(base.path().toStdString(), "tracepot-test-3");
            QVERIFY(workspace.ok());
            runDir = workspace->paths().runDir;
            const fs::path root = workspace->paths().rootDir;
            // What analyzed code might leave behind: unreadable directories and symlinks to the host.
            test::writeFile(root / "locked/inner/file", "x");
            ::chmod((root / "locked/inner").c_str(), 0);
            ::chmod((root / "locked").c_str(), 0);
            QTemporaryDir outside;
            test::writeFile(fs::path(outside.path().toStdString()) / "keep.txt", "keep");
            fs::create_directory_symlink(outside.path().toStdString(), root / "link-to-host");
            QVERIFY(workspace->remove().ok());
            QVERIFY(!fs::exists(runDir));
            QVERIFY(fs::exists(fs::path(outside.path().toStdString()) / "keep.txt"));  // symlink not followed
        }
    }

    void destructorRemovesUnlessKept()
    {
        QTemporaryDir base;
        fs::path removed;
        fs::path kept;
        {
            auto first = Workspace::create(base.path().toStdString(), "tracepot-test-4");
            removed = first->paths().runDir;
            auto second = Workspace::create(base.path().toStdString(), "tracepot-test-5");
            kept = second->paths().runDir;
            second->setKeep(true);
        }
        QVERIFY(!fs::exists(removed));
        QVERIFY(fs::exists(kept));
    }
};

QTEST_GUILESS_MAIN(TestWorkspace)
#include "tst_workspace.moc"
