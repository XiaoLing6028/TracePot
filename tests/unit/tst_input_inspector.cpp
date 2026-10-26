#include "common/TestSupport.hpp"
#include "core/archive/InputInspector.hpp"

#include <QTemporaryDir>
#include <QtTest>

using namespace tracepot;
namespace fs = std::filesystem;

class TestInputInspector : public QObject {
    Q_OBJECT

private slots:
    void shebangDetection_data()
    {
        QTest::addColumn<QString>("header");
        QTest::addColumn<QString>("fileName");
        QTest::addColumn<QString>("expectedShell");
        QTest::newRow("sh") << "#!/bin/sh\necho" << "x" << "sh";
        QTest::newRow("bash usr") << "#!/usr/bin/bash -e\n" << "x" << "bash";
        QTest::newRow("env bash") << "#!/usr/bin/env bash\n" << "x" << "bash";
        QTest::newRow("env -S") << "#!/usr/bin/env -S bash -eu\n" << "x" << "bash";
        QTest::newRow("spaces") << "#! /bin/dash\n" << "x" << "dash";
        QTest::newRow("crlf") << "#!/bin/sh\r\n" << "x" << "sh";
        QTest::newRow("no shebang .sh") << "echo hi\n" << "install.sh" << "sh";
        QTest::newRow("python") << "#!/usr/bin/python3\n" << "x.sh" << "";
        QTest::newRow("no shebang no ext") << "echo hi\n" << "install" << "";
    }

    void shebangDetection()
    {
        QFETCH(QString, header);
        QFETCH(QString, fileName);
        QFETCH(QString, expectedShell);
        std::string rejected;
        QCOMPARE(QString::fromStdString(shellInterpreterFor(header.toStdString(), fileName.toStdString(), &rejected)),
                 expectedShell);
    }

    void classification()
    {
        QCOMPARE(classifyHeader("#!/bin/bash\n", "a").kind, InputKind::ShellScript);
        const auto elf = classifyHeader(std::string("\x7f" "ELF\x02\x01\x01\0\0\0\0\0", 16), "installer.bin");
        QCOMPARE(elf.kind, InputKind::Unsupported);
        QVERIFY(elf.reason.find("not execute binary installers") != std::string::npos);
        QCOMPARE(classifyHeader("PK\x03\x04rest", "a.zip").kind, InputKind::Unsupported);
        QCOMPARE(classifyHeader("\x1f\x8b\x08\x00", "a.tgz").format, std::string("tar+gzip"));
        QCOMPARE(classifyHeader(std::string("\xfd" "7zXZ\0", 6), "a.txz").format, std::string("tar+xz"));
        QCOMPARE(classifyHeader("BZh91AY", "a.tbz").format, std::string("tar+bzip2"));
        std::string ustar(512, '\0');
        ustar.replace(257, 5, "ustar");
        QCOMPARE(classifyHeader(ustar, "a.tar").kind, InputKind::TarArchive);
        QCOMPARE(classifyHeader("#!/usr/bin/perl\n", "a.pl").kind, InputKind::Unsupported);
        QCOMPARE(classifyHeader("random text", "notes.txt").kind, InputKind::Unsupported);
        QCOMPARE(classifyHeader("!<arch>\ndebian-binary", "a.deb").format, std::string("deb"));
    }

    void inspectsFiles()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "install.sh", "#!/bin/sh\necho hi\n");
        auto script = inspectInput(root / "install.sh");
        QVERIFY(script.ok());
        QCOMPARE(script->kind, InputKind::ShellScript);
        QCOMPARE(script->sizeBytes, std::uint64_t{18});

        QVERIFY(test::ArchiveBuilder().file("install.sh", "#!/bin/sh\n").write(root / "pkg.tar.gz"));
        auto archive = inspectInput(root / "pkg.tar.gz");
        QVERIFY(archive.ok());
        QCOMPARE(archive->kind, InputKind::TarArchive);

        // gzip that is not a tar archive is rejected rather than executed or extracted
        QVERIFY(test::ArchiveBuilder().write(root / "empty.tar.gz"));
        test::writeFile(root / "fake.gz", std::string("\x1f\x8b\x08\x00garbage", 12));
        auto fake = inspectInput(root / "fake.gz");
        QVERIFY(fake.ok());
        QCOMPARE(fake->kind, InputKind::Unsupported);

        test::writeFile(root / "empty.sh", "");
        QCOMPARE(inspectInput(root / "empty.sh")->kind, InputKind::Unsupported);

        auto missing = inspectInput(root / "missing.sh");
        QVERIFY(!missing.ok());
        QCOMPARE(missing.error().code, ErrorCode::InputNotFound);
        QVERIFY(!inspectInput(root).ok());  // a directory is not an input
    }

    void realElfBinaryRejected()
    {
        auto info = inspectInput("/usr/bin/true");
        if (!info.ok()) {
            QSKIP("/usr/bin/true not available");
        }
        QCOMPARE(info->kind, InputKind::Unsupported);
        QCOMPARE(QString::fromStdString(info->format), QStringLiteral("ELF executable"));
    }
};

QTEST_GUILESS_MAIN(TestInputInspector)
#include "tst_input_inspector.moc"
