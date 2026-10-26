#include "core/diff/TextDiff.hpp"

#include <QtTest>

using namespace tracepot;

class TestTextDiff : public QObject {
    Q_OBJECT

private slots:
    void identicalTextsProduceNoDiff()
    {
        QVERIFY(unifiedDiff("a\nb\n", "a\nb\n", "a", "b").diff.empty());
    }

    void appendedLine()
    {
        const auto result = unifiedDiff("one\ntwo\n", "one\ntwo\nthree\n", "a/f", "b/f");
        const std::string expected = "--- a/f\n+++ b/f\n@@ -1,2 +1,3 @@\n one\n two\n+three\n";
        QCOMPARE(QString::fromStdString(result.diff), QString::fromStdString(expected));
    }

    void changedLineWithContext()
    {
        std::string before;
        std::string after;
        for (int i = 1; i <= 10; ++i) {
            before += "line" + std::to_string(i) + "\n";
            after += (i == 5 ? std::string("changed") : "line" + std::to_string(i)) + "\n";
        }
        const auto result = unifiedDiff(before, after, "a", "b");
        QVERIFY(result.diff.find("@@ -2,7 +2,7 @@") != std::string::npos);
        QVERIFY(result.diff.find("-line5\n+changed\n") != std::string::npos);
        QVERIFY(result.diff.find(" line1\n") == std::string::npos);  // outside the 3-line context
    }

    void separateHunks()
    {
        std::string before;
        std::string after;
        for (int i = 1; i <= 30; ++i) {
            before += std::to_string(i) + "\n";
            after += (i == 3 || i == 27 ? "x" : std::to_string(i)) + "\n";
        }
        const auto result = unifiedDiff(before, after, "a", "b");
        std::size_t hunks = 0;
        for (std::size_t pos = 0; (pos = result.diff.find("@@ -", pos)) != std::string::npos; ++pos) {
            ++hunks;
        }
        QCOMPARE(hunks, std::size_t{2});
    }

    void fromEmptyFile()
    {
        const auto result = unifiedDiff("", "new\n", "/dev/null", "b/x");
        QVERIFY(result.diff.find("@@ -0,0 +1,1 @@\n+new\n") != std::string::npos);
    }

    void missingFinalNewline()
    {
        const auto result = unifiedDiff("a\n", "a\nb", "a", "b");
        QVERIFY(result.diff.find("+b\n\\ No newline at end of file\n") != std::string::npos);
    }

    void truncation()
    {
        std::string after;
        for (int i = 0; i < 1000; ++i) {
            after += "a fairly long line number " + std::to_string(i) + "\n";
        }
        const auto result = unifiedDiff("", after, "a", "b", 3, 512);
        QVERIFY(result.truncated);
        QVERIFY(result.diff.size() < 600);
    }
};

QTEST_GUILESS_MAIN(TestTextDiff)
#include "tst_text_diff.moc"
