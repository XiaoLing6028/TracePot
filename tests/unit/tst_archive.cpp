#include "common/TestSupport.hpp"
#include "core/archive/EntryPoint.hpp"
#include "core/archive/SafeExtractor.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <sys/stat.h>

using namespace tracepot;
using test::ArchiveBuilder;
namespace fs = std::filesystem;

class TestArchive : public QObject {
    Q_OBJECT

private:
    QTemporaryDir tmp_;

    fs::path base() const { return tmp_.path().toStdString(); }

    // Builds `builder` into a fresh archive and extracts it into a fresh directory.
    Result<ExtractionResult> extract(const ArchiveBuilder& builder, const std::string& name, ArchiveLimits limits = {},
                                     fs::path* destOut = nullptr)
    {
        const fs::path archive = base() / (name + ".tar.gz");
        const fs::path dest = base() / (name + "-out");
        fs::create_directories(dest);
        if (!builder.write(archive)) {
            return makeError(ErrorCode::Internal, "test archive could not be written");
        }
        if (destOut != nullptr) {
            *destOut = dest;
        }
        return extractTarSafely(archive, dest, limits);
    }

    static bool dirIsEmpty(const fs::path& dir)
    {
        return fs::is_empty(dir);
    }

private slots:
    void extractsValidArchive()
    {
        fs::path dest;
        auto result = extract(ArchiveBuilder()
                                  .directory("pkg")
                                  .file("pkg/install.sh", "#!/bin/sh\necho ok\n", 0755)
                                  .file("pkg/data/config.txt", "value=1\n")
                                  .symlink("pkg/link", "data/config.txt")
                                  .hardlink("pkg/hard", "pkg/install.sh")
                                  .file("pkg/setuid", "x", 04755),
                              "valid", {}, &dest);
        QVERIFY2(result.ok(), result.ok() ? "" : result.error().message.c_str());
        QCOMPARE(test::readFile(dest / "pkg/data/config.txt"), std::string("value=1\n"));
        QVERIFY(fs::is_symlink(dest / "pkg/link"));
        QCOMPARE(fs::read_symlink(dest / "pkg/link").string(), std::string("data/config.txt"));
        QCOMPARE(fs::hard_link_count(dest / "pkg/install.sh"), std::uintmax_t{2});
        struct stat st {};
        QCOMPARE(::stat((dest / "pkg/install.sh").c_str(), &st), 0);
        QCOMPARE(st.st_mode & 07777, 0755u);
        QCOMPARE(::stat((dest / "pkg/setuid").c_str(), &st), 0);
        QCOMPARE(st.st_mode & 07000, 0u);  // setuid stripped
        QCOMPARE(result->entries.size(), std::size_t{6});
    }

    void rejectsParentTraversal()
    {
        fs::path dest;
        auto result = extract(ArchiveBuilder().file("ok.txt", "x").file("../escape.txt", "evil"), "traversal", {}, &dest);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
        QVERIFY(!fs::exists(base() / "escape.txt"));
        result = extract(ArchiveBuilder().file("a/../../escape2.txt", "evil"), "traversal2");
        QVERIFY(!result.ok());
        QVERIFY(!fs::exists(base() / "escape2.txt"));
    }

    void rejectsAbsolutePaths()
    {
        const std::string target = (base() / "absolute-target.txt").string();
        auto result = extract(ArchiveBuilder().file(target, "evil"), "absolute");
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
        QVERIFY(!fs::exists(target));
    }

    void rejectsEscapingSymlinks()
    {
        auto result = extract(ArchiveBuilder().symlink("etc", "/etc"), "abs-link");
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
        result = extract(ArchiveBuilder().directory("a").symlink("a/up", "../../outside"), "rel-link");
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
    }

    void rejectsWritesThroughSymlinks()
    {
        // Classic attack: an in-root symlink to a directory, then a member written "through" it.
        QTemporaryDir outside;
        fs::path dest;
        auto result = extract(ArchiveBuilder().directory("real").symlink("link", "real").file("link/payload", "evil"),
                              "through", {}, &dest);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
        QVERIFY(!fs::exists(dest / "real" / "payload"));
    }

    void rejectsReplacingSymlinkWithFile()
    {
        fs::path dest;
        auto result = extract(ArchiveBuilder().file("target", "t").symlink("name", "target").file("name", "overwrite"),
                              "replace", {}, &dest);
        QVERIFY(!result.ok());
        QCOMPARE(test::readFile(dest / "target"), std::string("t"));  // never written through the link
    }

    void rejectsSpecialFiles()
    {
        auto result = extract(ArchiveBuilder().charDevice("null"), "device");
        QVERIFY(!result.ok());
        QVERIFY(result.error().message.find("device") != std::string::npos);
        result = extract(ArchiveBuilder().fifo("pipe"), "fifo");
        QVERIFY(!result.ok());
        QVERIFY(result.error().message.find("FIFO") != std::string::npos);
    }

    void rejectsUnsafeHardlinks()
    {
        auto result = extract(ArchiveBuilder().hardlink("h", "../outside"), "hard-escape");
        QVERIFY(!result.ok());
        result = extract(ArchiveBuilder().hardlink("h", "does-not-exist"), "hard-missing");
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
    }

    void rejectsDuplicates()
    {
        auto result = extract(ArchiveBuilder().file("a", "1").file("a", "2"), "dup");
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveUnsafe);
    }

    void enforcesLimits()
    {
        ArchiveLimits limits;
        limits.maxEntries = 3;
        ArchiveBuilder many;
        for (int i = 0; i < 5; ++i) {
            many.file("f" + std::to_string(i), "x");
        }
        auto result = extract(many, "many", limits);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveLimitExceeded);

        ArchiveLimits sizeLimits;
        sizeLimits.maxFileBytes = 1000;
        result = extract(ArchiveBuilder().file("big", std::string(5000, 'x')), "big", sizeLimits);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveLimitExceeded);

        ArchiveLimits totalLimits;
        totalLimits.maxTotalBytes = 6000;
        result = extract(ArchiveBuilder().file("a", std::string(4000, 'x')).file("b", std::string(4000, 'y')), "total",
                         totalLimits);
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveLimitExceeded);

        ArchiveLimits depthLimits;
        depthLimits.maxDepth = 3;
        result = extract(ArchiveBuilder().file("a/b/c/d/e", "x"), "deep", depthLimits);
        QVERIFY(!result.ok());
    }

    void rejectsCorruptArchives()
    {
        const fs::path good = base() / "good.tar.gz";
        QVERIFY(ArchiveBuilder().file("a", std::string(100000, 'x')).write(good));
        const std::string bytes = test::readFile(good);
        const fs::path truncated = base() / "truncated.tar.gz";
        test::writeFile(truncated, bytes.substr(0, bytes.size() / 2));
        const fs::path dest = base() / "corrupt-out";
        fs::create_directories(dest);
        auto result = extractTarSafely(truncated, dest, {});
        QVERIFY(!result.ok());
        QCOMPARE(result.error().code, ErrorCode::ArchiveMalformed);
    }

    void resolvesEntryPoints()
    {
        fs::path dest;
        auto single = extract(ArchiveBuilder().file("tool-1.0/install.sh", "#!/bin/bash\n").file("tool-1.0/README", "r"),
                              "entry-single", {}, &dest);
        QVERIFY(single.ok());
        auto entry = resolveEntryPoint(single.value(), dest, "");
        QVERIFY(entry.ok());
        QCOMPARE(QString::fromStdString(entry->relativePath), QStringLiteral("tool-1.0/install.sh"));
        QCOMPARE(QString::fromStdString(entry->interpreter), QStringLiteral("bash"));

        auto ambiguous = extract(ArchiveBuilder().file("install.sh", "#!/bin/sh\n").file("setup.sh", "#!/bin/sh\n"),
                                 "entry-ambiguous", {}, &dest);
        QVERIFY(ambiguous.ok());
        auto failed = resolveEntryPoint(ambiguous.value(), dest, "");
        QVERIFY(!failed.ok());
        QCOMPARE(failed.error().code, ErrorCode::EntryPointNotFound);
        auto chosen = resolveEntryPoint(ambiguous.value(), dest, "./setup.sh");
        QVERIFY(chosen.ok());
        QCOMPARE(QString::fromStdString(chosen->relativePath), QStringLiteral("setup.sh"));

        auto none = extract(ArchiveBuilder().file("README", "r"), "entry-none", {}, &dest);
        QVERIFY(!resolveEntryPoint(none.value(), dest, "").ok());
        QVERIFY(!resolveEntryPoint(none.value(), dest, "../etc/passwd").ok());

        auto python = extract(ArchiveBuilder().file("install.sh", "#!/usr/bin/python3\n"), "entry-python", {}, &dest);
        auto unsupported = resolveEntryPoint(python.value(), dest, "");
        QVERIFY(!unsupported.ok());
        QCOMPARE(unsupported.error().code, ErrorCode::UnsupportedInput);
    }
};

QTEST_GUILESS_MAIN(TestArchive)
#include "tst_archive.moc"
