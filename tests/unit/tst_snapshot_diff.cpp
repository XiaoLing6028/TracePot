#include "common/TestSupport.hpp"
#include "core/diff/FsDiff.hpp"
#include "core/diff/Snapshot.hpp"
#include "core/util/Sha256.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <algorithm>

#include <sys/stat.h>
#include <unistd.h>

using namespace tracepot;
namespace fs = std::filesystem;

namespace {

const FileChange* findChange(const std::vector<FileChange>& changes, const std::string& path)
{
    const auto it = std::find_if(changes.begin(), changes.end(), [&](const FileChange& c) { return c.path == path; });
    return it == changes.end() ? nullptr : &*it;
}

bool hasAspect(const FileChange& change, const std::string& aspect)
{
    return std::find(change.aspects.begin(), change.aspects.end(), aspect) != change.aspects.end();
}

}  // namespace

class TestSnapshotDiff : public QObject {
    Q_OBJECT

private:
    Snapshot snap(const fs::path& root, SnapshotOptions options = {})
    {
        return takeSnapshot({{root, "/"}}, options);
    }

private slots:
    void detectsCreatedModifiedDeleted()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "keep.txt", "same\n");
        test::writeFile(root / "modify.txt", "line1\nline2\n");
        test::writeFile(root / "delete.txt", "bye\n");
        const Snapshot before = snap(root);

        test::writeFile(root / "modify.txt", "line1\nline2\nline3\n");
        fs::remove(root / "delete.txt");
        test::writeFile(root / "sub" / "new.txt", "new\n");
        const Snapshot after = snap(root);

        const auto changes = diffSnapshots(before, after, {});
        QVERIFY(findChange(changes, "/keep.txt") == nullptr);

        const auto* modified = findChange(changes, "/modify.txt");
        QVERIFY(modified != nullptr);
        QCOMPARE(modified->kind, ChangeKind::Modified);
        QVERIFY(hasAspect(*modified, "content"));
        QVERIFY(hasAspect(*modified, "size"));
        QVERIFY(modified->textDiff.has_value());
        QVERIFY(modified->textDiff->find("+line3") != std::string::npos);
        QCOMPARE(QString::fromStdString(*modified->after->sha256),
                 QString::fromStdString(sha256Hex("line1\nline2\nline3\n")));

        const auto* deleted = findChange(changes, "/delete.txt");
        QVERIFY(deleted != nullptr);
        QCOMPARE(deleted->kind, ChangeKind::Deleted);
        QVERIFY(deleted->before.has_value());
        QVERIFY(!deleted->after.has_value());

        const auto* createdDir = findChange(changes, "/sub");
        QVERIFY(createdDir != nullptr);
        QCOMPARE(createdDir->kind, ChangeKind::Created);
        QCOMPARE(createdDir->after->type, FileType::Directory);
        const auto* created = findChange(changes, "/sub/new.txt");
        QVERIFY(created != nullptr);
        QCOMPARE(created->kind, ChangeKind::Created);
        QCOMPARE(created->after->size, std::uint64_t{4});
        QVERIFY(created->textDiff && created->textDiff->find("+new") != std::string::npos);
    }

    void detectsPermissionChanges()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "tool", "#!/bin/sh\n", 0644);
        const Snapshot before = snap(root);
        ::chmod((root / "tool").c_str(), 04755);
        const Snapshot after = snap(root);
        const auto changes = diffSnapshots(before, after, {});
        QCOMPARE(changes.size(), std::size_t{1});
        QVERIFY(hasAspect(changes.front(), "permissions"));
        QVERIFY(!hasAspect(changes.front(), "content"));
        QCOMPARE(changes.front().before->mode, 0644u);
        QCOMPARE(changes.front().after->mode, 04755u);
    }

    void symlinksAreRecordedNotFollowed()
    {
        QTemporaryDir dir;
        QTemporaryDir outside;
        const fs::path root = dir.path().toStdString();
        const fs::path secretDir = outside.path().toStdString();
        test::writeFile(secretDir / "secret.txt", "do not read\n");
        const Snapshot before = snap(root);

        fs::create_symlink(secretDir / "secret.txt", root / "file-link");
        fs::create_directory_symlink(secretDir, root / "dir-link");
        const Snapshot after = snap(root);

        const auto& link = after.entries.at("/file-link");
        QCOMPARE(link.meta.type, FileType::Symlink);
        QCOMPARE(QString::fromStdString(link.meta.linkTarget), QString::fromStdString((secretDir / "secret.txt").string()));
        QVERIFY(!link.meta.sha256.has_value());  // the target was not read
        QVERIFY(!link.text.has_value());
        QVERIFY(after.entries.count("/dir-link/secret.txt") == 0);  // directory symlink not traversed

        const auto changes = diffSnapshots(before, after, {});
        QCOMPARE(changes.size(), std::size_t{2});
    }

    void detectsSymlinkRetargetAndTypeChange()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        fs::create_symlink("a", root / "link");
        test::writeFile(root / "becomes-dir", "x");
        const Snapshot before = snap(root);
        fs::remove(root / "link");
        fs::create_symlink("b", root / "link");
        fs::remove(root / "becomes-dir");
        fs::create_directory(root / "becomes-dir");
        const Snapshot after = snap(root);
        const auto changes = diffSnapshots(before, after, {});
        const auto* link = findChange(changes, "/link");
        QVERIFY(link != nullptr && hasAspect(*link, "link-target"));
        const auto* typeChange = findChange(changes, "/becomes-dir");
        QVERIFY(typeChange != nullptr && hasAspect(*typeChange, "type"));
    }

    void respectsHashAndTextLimits()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "big.bin", std::string(4096, 'x'));
        test::writeFile(root / "binary", std::string("a\0b", 3));
        SnapshotOptions options;
        options.limits.maxHashFileBytes = 1024;
        options.limits.maxTextBytes = 16;
        const Snapshot s = snap(root, options);
        const auto& big = s.entries.at("/big.bin");
        QVERIFY(!big.meta.sha256.has_value());
        QVERIFY(!big.meta.hashNote.empty());
        const auto& binary = s.entries.at("/binary");
        QVERIFY(binary.meta.sha256.has_value());
        QVERIFY(!binary.text.has_value());  // NUL bytes: not treated as text
    }

    void hashlessContentComparisonFallsBackToMetadata()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "big.bin", std::string(4096, 'x'));
        SnapshotOptions options;
        options.limits.maxHashFileBytes = 1024;
        const Snapshot before = snap(root, options);
        test::writeFile(root / "big.bin", std::string(5000, 'y'));
        const Snapshot after = snap(root, options);
        const auto changes = diffSnapshots(before, after, {});
        QCOMPARE(changes.size(), std::size_t{1});
        QVERIFY(hasAspect(changes.front(), "content"));
        QVERIFY(!changes.front().notes.empty());
    }

    void entryLimitTruncatesAndSuppressesDeletions()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        for (int i = 0; i < 20; ++i) {
            test::writeFile(root / ("f" + std::to_string(i)), "x");
        }
        SnapshotOptions full;
        const Snapshot before = snap(root, full);
        SnapshotOptions limited;
        limited.limits.maxEntries = 5;
        const Snapshot after = snap(root, limited);
        QVERIFY(after.truncated);
        QVERIFY(!after.warnings.empty());
        // A truncated "after" snapshot must not produce false "deleted" reports.
        const auto changes = diffSnapshots(before, after, {});
        QVERIFY(std::none_of(changes.begin(), changes.end(),
                             [](const FileChange& c) { return c.kind == ChangeKind::Deleted; }));
    }

    void uidMappingTranslatesOwnership()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "f", "x");
        SnapshotOptions options;
        options.uidMapping = std::make_pair(static_cast<std::uint32_t>(::getuid()), 1000u);
        const Snapshot s = snap(root, options);
        QCOMPARE(s.entries.at("/f").meta.uid, 1000u);
    }

    void directoryTimestampsIgnored()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        fs::create_directory(root / "d");
        const Snapshot before = snap(root);
        test::writeFile(root / "d" / "x", "1");
        const Snapshot after = snap(root);
        const auto changes = diffSnapshots(before, after, {});
        QVERIFY(findChange(changes, "/d") == nullptr);
        QVERIFY(findChange(changes, "/d/x") != nullptr);
    }

    void measuresTree()
    {
        QTemporaryDir dir;
        const fs::path root = dir.path().toStdString();
        test::writeFile(root / "a", std::string(10000, 'x'));
        test::writeFile(root / "d" / "b", "y");
        const auto usage = measureTree(root, 100);
        QCOMPARE(usage.entries, std::uint64_t{3});
        QVERIFY(usage.bytes >= 10000);
        QVERIFY(!usage.truncated);
        QVERIFY(measureTree(root, 2).truncated);
    }
};

QTEST_GUILESS_MAIN(TestSnapshotDiff)
#include "tst_snapshot_diff.moc"
