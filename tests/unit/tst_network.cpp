#include "core/observers/NetworkObserver.hpp"

#include <QtTest>

using namespace tracepot;

namespace {

std::string dnsQuery(const std::vector<std::string>& labels, std::uint16_t type, bool response = false)
{
    std::string message = {'\x12', '\x34', response ? '\x81' : '\x01', '\x00', '\x00', '\x01', '\0', '\0', '\0', '\0',
                           '\0', '\0'};
    for (const auto& label : labels) {
        message += static_cast<char>(label.size());
        message += label;
    }
    message += '\0';
    message += static_cast<char>(type >> 8);
    message += static_cast<char>(type & 0xff);
    message += std::string("\0\x01", 2);
    return message;
}

}  // namespace

class TestNetwork : public QObject {
    Q_OBJECT

private slots:
    void decodesQueries()
    {
        const auto a = decodeDnsQuery(dnsQuery({"updates", "example", "org"}, 1));
        QCOMPARE(a.size(), std::size_t{1});
        QCOMPARE(QString::fromStdString(a.front().name), QStringLiteral("updates.example.org"));
        QCOMPARE(QString::fromStdString(a.front().type), QStringLiteral("A"));
        QCOMPARE(QString::fromStdString(decodeDnsQuery(dnsQuery({"x"}, 28)).front().type), QStringLiteral("AAAA"));
        QCOMPARE(QString::fromStdString(decodeDnsQuery(dnsQuery({"x"}, 99)).front().type), QStringLiteral("TYPE99"));
    }

    void rejectsMalformedMessages()
    {
        QVERIFY(decodeDnsQuery("").empty());
        QVERIFY(decodeDnsQuery("short").empty());
        QVERIFY(decodeDnsQuery(dnsQuery({"example", "com"}, 1, true)).empty());  // a response, not a query
        std::string truncated = dnsQuery({"example", "com"}, 1);
        truncated.resize(truncated.size() - 3);
        QVERIFY(decodeDnsQuery(truncated).empty());
        QVERIFY(decodeDnsQuery(dnsQuery({std::string("bad\x01label", 9)}, 1)).empty());
        std::string overlong = dnsQuery({"a"}, 1);
        overlong[12] = static_cast<char>(60);  // label length beyond the buffer
        QVERIFY(decodeDnsQuery(overlong).empty());
    }

    void extractsUrls()
    {
        const auto urls = extractUrls({"curl", "-fsSL", "https://get.example.com/install.sh", "-o", "/tmp/x",
                                       "sh -c 'wget http://mirror.example.net:8080/a.tar.gz && echo done'"});
        QCOMPARE(urls.size(), std::size_t{2});
        QCOMPARE(QString::fromStdString(urls[0]), QStringLiteral("https://get.example.com/install.sh"));
        QCOMPARE(QString::fromStdString(urls[1]), QStringLiteral("http://mirror.example.net:8080/a.tar.gz"));
        QVERIFY(extractUrls({"echo", "no urls here", "https://"}).empty());
    }

    void parsesUrls()
    {
        auto plain = parseUrl("https://example.com/path?q=1");
        QCOMPARE(QString::fromStdString(plain->scheme), QStringLiteral("https"));
        QCOMPARE(QString::fromStdString(plain->host), QStringLiteral("example.com"));
        QVERIFY(!plain->port.has_value());
        auto credentials = parseUrl("ftp://user:secret@files.example.com:2121/x");
        QCOMPARE(QString::fromStdString(credentials->host), QStringLiteral("files.example.com"));
        QCOMPARE(*credentials->port, 2121);
        auto v6 = parseUrl("http://[2001:db8::1]:8080/");
        QCOMPARE(QString::fromStdString(v6->host), QStringLiteral("2001:db8::1"));
        QCOMPARE(*v6->port, 8080);
        QVERIFY(!parseUrl("not a url").has_value());
        QVERIFY(!parseUrl("http://host:99999999/").has_value());
    }

    void isolatedPolicyDescription()
    {
        IsolatedNetwork network;
        const auto info = network.describe();
        QCOMPARE(QString::fromStdString(info.mode), QStringLiteral("isolated"));
        QVERIFY(!info.externalConnectivity);
        QVERIFY(!info.dnsResolution);
        QVERIFY(network.sandboxArguments().empty());
        QVERIFY(network.collectEvents().empty());
    }
};

QTEST_GUILESS_MAIN(TestNetwork)
#include "tst_network.moc"
