#include "core/observers/StraceParser.hpp"
#include "unit/strace_samples.hpp"

#include <QtTest>

using namespace tracepot;

class TestStraceParser : public QObject {
    Q_OBJECT

private slots:
    void lineKinds()
    {
        auto syscall = parseStraceLine(
            samples::kOpenatLine);
        QVERIFY(syscall.has_value());
        QCOMPARE(syscall->kind, StraceLine::Kind::Syscall);
        QCOMPARE(syscall->pid, 1301);
        QCOMPARE(syscall->timestamp, 1793006449.069854);
        QCOMPARE(QString::fromStdString(syscall->name), QStringLiteral("openat"));

        auto unfinished = parseStraceLine("1301  1793006449.070010 vfork( <unfinished ...>");
        QCOMPARE(unfinished->kind, StraceLine::Kind::Unfinished);
        QCOMPARE(QString::fromStdString(unfinished->text), QStringLiteral("vfork("));

        auto resumed = parseStraceLine("1301  1793006449.070903 <... vfork resumed>) = 3 /* 1302 in strace's PID NS */");
        QCOMPARE(resumed->kind, StraceLine::Kind::Resumed);
        QCOMPARE(QString::fromStdString(resumed->name), QStringLiteral("vfork"));

        auto exited = parseStraceLine("1349  1793006481.808475 +++ exited with 7 +++");
        QCOMPARE(exited->kind, StraceLine::Kind::Exited);
        QCOMPARE(exited->exitCode, 7);

        auto killed = parseStraceLine("1393  1793006496.290593 +++ killed by SIGSEGV (core dumped) +++");
        QCOMPARE(killed->kind, StraceLine::Kind::Killed);
        QCOMPARE(QString::fromStdString(killed->name), QStringLiteral("SIGSEGV"));
        QVERIFY(killed->coreDumped);

        auto signal = parseStraceLine("1301 1.5 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED} ---");
        QCOMPARE(signal->kind, StraceLine::Kind::Signal);
        QCOMPARE(QString::fromStdString(signal->name), QStringLiteral("SIGCHLD"));
    }

    void malformedLinesRejected()
    {
        QVERIFY(!parseStraceLine("").has_value());
        QVERIFY(!parseStraceLine("strace: Process 12 attached").has_value());
        QVERIFY(!parseStraceLine("12 1.0 ?\?\?( <unfinished ...>").has_value());
        QVERIFY(!parseStraceLine("abc 1.0 openat()").has_value());
        QVERIFY(!parseSyscallText("openat(AT_FDCWD, \"unterminated").has_value());
        QVERIFY(!parseSyscallText("openat(1, 2)").has_value());  // no return value
    }

    void syscallParsing()
    {
        auto record = parseSyscallText(
            samples::kConnectRefused);
        QVERIFY(record.has_value());
        QCOMPARE(record->args.size(), std::size_t{3});
        QVERIFY(!record->succeeded());
        QCOMPARE(record->returnValue, -1LL);
        QCOMPARE(QString::fromStdString(record->errnoName), QStringLiteral("ECONNREFUSED"));
        const auto fd = parseFdToken(record->args[0]);
        QCOMPARE(fd.fd, 3);
        QVERIFY(fd.socketInode.has_value());
        QCOMPARE(*fd.socketInode, std::uint64_t{5360});
        const auto addr = parseSockAddr(record->args[1]);
        QVERIFY(addr.has_value());
        QCOMPARE(QString::fromStdString(addr->family), QStringLiteral("AF_INET"));
        QCOMPARE(QString::fromStdString(addr->address), QStringLiteral("127.0.0.1"));
        QCOMPARE(*addr->port, 53);

        auto clone = parseSyscallText(
            "clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f) = 3 /* 1349 "
            "in strace's PID NS */");
        QVERIFY(clone.has_value());
        QCOMPARE(clone->returnValue, 3LL);
        QCOMPARE(*clone->translatedPid, 1349LL);

        auto exitGroup = parseSyscallText("exit_group(0)   = ?");
        QVERIFY(exitGroup.has_value());
        QVERIFY(!exitGroup->returnKnown);

        auto opened = parseSyscallText(samples::kOpenDeletedFile);
        QCOMPARE(QString::fromStdString(opened->returnDecoration), QStringLiteral("/work/x (deleted)"));
    }

    void hostileFileNames()
    {
        // A file literally named:  a,b>c "q" <x>.txt  — strace escapes quotes and angle brackets.
        auto record = parseSyscallText(
            samples::kHostileFileName);
        QVERIFY(record.has_value());
        QCOMPARE(record->args.size(), std::size_t{4});
        QCOMPARE(QString::fromStdString(*decodeQuotedString(record->args[1])), QStringLiteral("a,b>c \"q\" <x>.txt"));
        QCOMPARE(QString::fromStdString(record->returnDecoration), QStringLiteral("/work/a,b>c \"q\" <x>.txt"));

        // A name containing what looks like the end of the call and a fake return value.
        auto tricky = parseSyscallText(samples::kFakeReturnInName);
        QVERIFY(tricky.has_value());
        QCOMPARE(tricky->args.size(), std::size_t{1});
        QCOMPARE(QString::fromStdString(*decodeQuotedString(tricky->args[0])), QStringLiteral("x\") = 0 /* fake */, ("));
        QCOMPARE(QString::fromStdString(tricky->errnoName), QStringLiteral("ENOENT"));

        // Newline and escape sequences in names stay escaped in the trace and decode to bytes.
        auto control = parseSyscallText(samples::kControlCharacterName);
        QCOMPARE(*decodeQuotedString(control->args[0]), std::string("nl\nline\x1b[31m"));
    }

    void escapes()
    {
        QCOMPARE(decodeEscapes(samples::kOctalUtf8), std::string("\xc3\xbcn\xc3\xaf"));  // ünï
        QCOMPARE(decodeEscapes(samples::kOctalDnsPayload), std::string("h\0\1\x07" "example\x03" "com\0", 16));
        QCOMPARE(decodeEscapes(samples::kHexEscapes), std::string("AJ"));
        QCOMPARE(decodeEscapes(samples::kSimpleEscapes), std::string("\\ \" \t"));
        bool truncated = false;
        QCOMPARE(*decodeQuotedString(samples::kTruncatedString, &truncated), std::string("abc"));
        QVERIFY(truncated);
    }

    void arraysAndAddresses()
    {
        bool truncated = false;
        const auto argv = parseStringArray(samples::kArgvArray, &truncated);
        QCOMPARE(argv.size(), std::size_t{3});
        QCOMPARE(QString::fromStdString(argv[2]), QStringLiteral("echo \"a, b\"; ls [x]"));
        QVERIFY(!truncated);

        auto v6 = parseSockAddr(
            samples::kInet6Address);
        QCOMPARE(QString::fromStdString(v6->address), QStringLiteral("2001:db8::1"));
        QCOMPARE(*v6->port, 443);
        auto unixAddr = parseSockAddr(samples::kUnixAddress);
        QCOMPARE(QString::fromStdString(unixAddr->address), QStringLiteral("/run/dbus/system_bus_socket"));
        auto abstract = parseSockAddr(samples::kAbstractUnixAddress);
        QCOMPARE(QString::fromStdString(abstract->address), QStringLiteral("@/tmp/.X11-unix/X0"));
        QVERIFY(!parseSockAddr("NULL").has_value());
    }

    void splitRespectsStructure()
    {
        const auto args = splitArguments(samples::kStructuredArguments);
        QCOMPARE(args.size(), std::size_t{4});
        QCOMPARE(QString::fromStdString(args[0]), QStringLiteral("3</a,b>"));
        QCOMPARE(QString::fromStdString(args[1]), QStringLiteral("{x=1, y=[2, 3]}"));
    }

    void assemblerMergesUnfinishedCalls()
    {
        StraceAssembler assembler;
        auto first = parseStraceLine(
            samples::kUnfinishedExecve);
        QVERIFY(!assembler.push(*first).has_value());
        // Interleaved line from another process.
        auto other = parseStraceLine("1348  1.1 <... vfork resumed>) = 4 /* 1350 in strace's PID NS */");
        QVERIFY(!assembler.push(*other).has_value());  // no pending vfork for 1348 in this assembler
        auto resumed = parseStraceLine("1350  1.2 <... execve resumed>) = 0");
        auto record = assembler.push(*resumed);
        QVERIFY(record.has_value());
        QCOMPARE(QString::fromStdString(record->name), QStringLiteral("execve"));
        QCOMPARE(record->timestamp, 1.0);  // start time of the call
        QCOMPARE(record->pid, 1350);
        QVERIFY(record->succeeded());
        QCOMPARE(parseStringArray(record->args[1]).size(), std::size_t{2});
    }
};

QTEST_GUILESS_MAIN(TestStraceParser)
#include "tst_strace_parser.moc"
