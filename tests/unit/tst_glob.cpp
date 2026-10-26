#include "core/util/Glob.hpp"

#include <QtTest>

using namespace tracepot;

class TestGlob : public QObject {
    Q_OBJECT

private slots:
    void matching_data()
    {
        QTest::addColumn<QString>("pattern");
        QTest::addColumn<QString>("text");
        QTest::addColumn<bool>("expected");
        QTest::newRow("literal") << "/etc/crontab" << "/etc/crontab" << true;
        QTest::newRow("literal mismatch") << "/etc/crontab" << "/etc/crontab2" << false;
        QTest::newRow("star segment") << "/home/*/.bashrc" << "/home/tracepot/.bashrc" << true;
        QTest::newRow("star stops at slash") << "/home/*/.bashrc" << "/home/a/b/.bashrc" << false;
        QTest::newRow("double star") << "/etc/systemd/system/**" << "/etc/systemd/system/x.service" << true;
        QTest::newRow("double star deep") << "/etc/systemd/system/**" << "/etc/systemd/system/a.wants/b.service" << true;
        QTest::newRow("double star needs prefix") << "/etc/systemd/system/**" << "/etc/systemd/systemx" << false;
        QTest::newRow("question") << "/etc/rc?.d/**" << "/etc/rc3.d/S01x" << true;
        QTest::newRow("question no slash") << "/a?b" << "/a/b" << false;
        QTest::newRow("star empty") << "/a/*" << "/a/" << true;
        QTest::newRow("case sensitive") << "/ETC/x" << "/etc/x" << false;
        QTest::newRow("glob key") << "/etc/ssh/ssh_host_*_key" << "/etc/ssh/ssh_host_rsa_key" << true;
        QTest::newRow("glob key pub") << "/etc/ssh/ssh_host_*_key" << "/etc/ssh/ssh_host_rsa_key.pub" << false;
    }

    void matching()
    {
        QFETCH(QString, pattern);
        QFETCH(QString, text);
        QFETCH(bool, expected);
        QCOMPARE(globMatch(pattern.toStdString(), text.toStdString()), expected);
    }

    void pathologicalPatternIsFast()
    {
        // Backtracking matchers explode on this; the DP matcher stays linear in pattern*text.
        const std::string pattern = "/" + std::string(30, '*') + "x" + std::string(30, '*') + "y";
        const std::string text = "/" + std::string(2000, 'a');
        QElapsedTimer timer;
        timer.start();
        QVERIFY(!globMatch(pattern, text));
        QVERIFY(timer.elapsed() < 2000);
    }
};

QTEST_GUILESS_MAIN(TestGlob)
#include "tst_glob.moc"
