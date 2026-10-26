#include "common/TestSupport.hpp"
#include "core/util/Sha256.hpp"

#include <QTemporaryDir>
#include <QtTest>

#include <unistd.h>

using namespace tracepot;

class TestSha256 : public QObject {
    Q_OBJECT

private slots:
    void knownVectors()
    {
        QCOMPARE(QString::fromStdString(sha256Hex("")),
                 QStringLiteral("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        QCOMPARE(QString::fromStdString(sha256Hex("abc")),
                 QStringLiteral("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        QCOMPARE(QString::fromStdString(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
                 QStringLiteral("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
    }

    void incrementalMatchesOneShot()
    {
        const std::string data(100000, 'a');
        Sha256 hasher;
        for (std::size_t i = 0; i < data.size(); i += 777) {
            hasher.update(std::string_view(data).substr(i, 777));
        }
        QCOMPARE(hasher.finalHex(), sha256Hex(data));
    }

    void hashesFiles()
    {
        QTemporaryDir dir;
        const auto path = std::filesystem::path(dir.path().toStdString()) / "hello.txt";
        test::writeFile(path, "hello\n");
        auto hash = sha256File(path);
        QVERIFY(hash.ok());
        QCOMPARE(QString::fromStdString(hash.value()),
                 QStringLiteral("5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"));
    }

    void doesNotFollowSymlinks()
    {
        QTemporaryDir dir;
        const auto base = std::filesystem::path(dir.path().toStdString());
        test::writeFile(base / "target", "secret");
        std::filesystem::create_symlink(base / "target", base / "link");
        QVERIFY(!sha256File(base / "link").ok());
        QVERIFY(!sha256File(base / "missing").ok());
    }
};

QTEST_GUILESS_MAIN(TestSha256)
#include "tst_sha256.moc"
