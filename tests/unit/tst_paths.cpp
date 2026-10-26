#include "core/util/PathUtil.hpp"

#include <QtTest>

using namespace tracepot;

class TestPaths : public QObject {
    Q_OBJECT

private slots:
    void archivePathNormalization_data()
    {
        QTest::addColumn<QString>("input");
        QTest::addColumn<QString>("expected");
        QTest::newRow("plain") << "a/b/c" << "a/b/c";
        QTest::newRow("dot prefix") << "./a/b" << "a/b";
        QTest::newRow("double slashes") << "a//b///c/" << "a/b/c";
        QTest::newRow("inner dots") << "a/./b/./c" << "a/b/c";
        QTest::newRow("unicode") << QString::fromUtf8("dír/ünï cödé.txt") << QString::fromUtf8("dír/ünï cödé.txt");
    }

    void archivePathNormalization()
    {
        QFETCH(QString, input);
        QFETCH(QString, expected);
        auto result = normalizeArchivePath(input.toStdString());
        QVERIFY(result.ok());
        QCOMPARE(QString::fromStdString(result.value()), expected);
    }

    void archivePathRejection_data()
    {
        QTest::addColumn<QString>("input");
        QTest::newRow("parent") << "../etc/passwd";
        QTest::newRow("inner parent") << "a/../../b";
        QTest::newRow("hidden parent") << "a/b/../c";
        QTest::newRow("absolute") << "/etc/passwd";
        QTest::newRow("root only") << "./";
        QTest::newRow("empty") << "";
    }

    void archivePathRejection()
    {
        QFETCH(QString, input);
        QVERIFY(!normalizeArchivePath(input.toStdString()).ok());
    }

    void nulByteRejected()
    {
        const std::string withNul("a\0b", 3);
        QVERIFY(!normalizeArchivePath(withNul).ok());
    }

    void absoluteNormalization()
    {
        QCOMPARE(QString::fromStdString(normalizeAbsolute("/a/./b/../c")), QStringLiteral("/a/c"));
        QCOMPARE(QString::fromStdString(normalizeAbsolute("/../../etc")), QStringLiteral("/etc"));
        QCOMPARE(QString::fromStdString(normalizeAbsolute("//a//b/")), QStringLiteral("/a/b"));
        QCOMPARE(QString::fromStdString(normalizeAbsolute("/")), QStringLiteral("/"));
        QCOMPARE(QString::fromStdString(resolveAgainst("/work", "sub/../x")), QStringLiteral("/work/x"));
        QCOMPARE(QString::fromStdString(resolveAgainst("/work", "/etc/x")), QStringLiteral("/etc/x"));
        QCOMPARE(QString::fromStdString(resolveAgainst("/work", "../../..")), QStringLiteral("/"));
    }

    void symlinkEscapes()
    {
        QVERIFY(symlinkTargetEscapes("", "../x"));
        QVERIFY(symlinkTargetEscapes("a", "../../x"));
        QVERIFY(symlinkTargetEscapes("a/b", "/etc/passwd"));
        QVERIFY(symlinkTargetEscapes("a", ""));
        QVERIFY(!symlinkTargetEscapes("a/b", "../c"));
        QVERIFY(!symlinkTargetEscapes("a", "./b/../c"));
        QVERIFY(!symlinkTargetEscapes("", "a/b"));
        QVERIFY(symlinkTargetEscapes("a", "b/../../.."));
    }

    void utf8Validation()
    {
        QVERIFY(isValidUtf8("plain ascii"));
        QVERIFY(isValidUtf8("\xc3\xbc\xe2\x82\xac\xf0\x9f\x98\x80"));  // ü € 😀
        QVERIFY(!isValidUtf8("\xff"));
        QVERIFY(!isValidUtf8("\xc3"));          // truncated
        QVERIFY(!isValidUtf8("\xc0\xaf"));      // overlong '/'
        QVERIFY(!isValidUtf8("\xed\xa0\x80"));  // surrogate
    }

    void displaySafety()
    {
        QCOMPARE(QString::fromStdString(displaySafe("a\nb\tc\x1b[31m")), QStringLiteral("a\\nb\\tc\\x1b[31m"));
        QCOMPARE(QString::fromStdString(displaySafe("bad\xff")), QStringLiteral("bad\\xff"));
        QCOMPARE(QString::fromStdString(displaySafe("\xc3\xbc")), QString::fromUtf8("ü"));
        QCOMPARE(QString::fromStdString(displaySafeMultiline("line1\nline2\tx\x07")), QStringLiteral("line1\nline2\tx\\x07"));
        // A literal backslash-t must not be turned into a tab.
        QCOMPARE(QString::fromStdString(displaySafeMultiline("a\\tb")), QStringLiteral("a\\tb"));
    }

    void areas()
    {
        QCOMPARE(QString::fromStdString(sandboxArea("/home/tracepot/.bashrc")), QStringLiteral("home"));
        QCOMPARE(QString::fromStdString(sandboxArea("/root/.profile")), QStringLiteral("home"));
        QCOMPARE(QString::fromStdString(sandboxArea("/etc/cron.d/x")), QStringLiteral("system-config"));
        QCOMPARE(QString::fromStdString(sandboxArea("/tmp/x")), QStringLiteral("temporary"));
        QCOMPARE(QString::fromStdString(sandboxArea("/var/tmp/x")), QStringLiteral("temporary"));
        QCOMPARE(QString::fromStdString(sandboxArea("/work/a")), QStringLiteral("work"));
        QCOMPARE(QString::fromStdString(sandboxArea("/opt/app")), QStringLiteral("system-data"));
        QCOMPARE(QString::fromStdString(sandboxArea("/homework")), QStringLiteral("other"));
    }

    void xdgDirectories()
    {
        qputenv("XDG_CACHE_HOME", "/custom/cache");
        QCOMPARE(QString::fromStdString(tracepotCacheDir().string()), QStringLiteral("/custom/cache/tracepot"));
        qputenv("XDG_CACHE_HOME", "relative/ignored");  // the XDG spec requires absolute paths
        qputenv("HOME", "/home/someone");
        QCOMPARE(QString::fromStdString(tracepotCacheDir().string()), QStringLiteral("/home/someone/.cache/tracepot"));
        qputenv("XDG_CONFIG_HOME", "/custom/config");
        QCOMPARE(QString::fromStdString(tracepotConfigDir().string()), QStringLiteral("/custom/config/tracepot"));
    }
};

QTEST_GUILESS_MAIN(TestPaths)
#include "tst_paths.moc"
