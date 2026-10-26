#include "core/observers/StraceParser.hpp"

#include <cctype>
#include <cstdlib>

namespace tracepot {

namespace {

std::string_view trim(std::string_view text)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) {
        text.remove_suffix(1);
    }
    return text;
}

bool startsWith(std::string_view text, std::string_view prefix)
{
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

bool isIdentifier(std::string_view name)
{
    if (name.empty()) {
        return false;
    }
    for (const char c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            return false;
        }
    }
    return true;
}

// Tracks strace's lexical structure: quoted strings, /* comments */, fd decorations <...> and
// bracket nesting. Strace escapes '"' inside strings and '<', '>' inside decorations, so the
// analyzed program cannot forge structure through file names or argument contents.
class Scanner {
public:
    explicit Scanner(std::string_view text) : text_(text) {}

    // Returns the index of the first character at nesting depth 0 (outside strings, comments and
    // decorations) for which `stop` returns true, or npos.
    template <typename Pred>
    std::size_t findTopLevel(std::size_t start, Pred stop)
    {
        int depth = 0;
        for (std::size_t i = start; i < text_.size(); ++i) {
            const char c = text_[i];
            if (c == '"') {
                i = skipQuoted(i, '"');
                continue;
            }
            if (c == '/' && i + 1 < text_.size() && text_[i + 1] == '*') {
                const auto end = text_.find("*/", i + 2);
                if (end == std::string_view::npos) {
                    return std::string_view::npos;
                }
                i = end + 1;
                continue;
            }
            if (c == '<' && opensDecoration(i)) {
                i = skipQuoted(i, '>');
                continue;
            }
            if (depth == 0 && stop(c)) {
                return i;
            }
            if (c == '(' || c == '[' || c == '{') {
                ++depth;
            } else if (c == ')' || c == ']' || c == '}') {
                if (depth == 0) {
                    return std::string_view::npos;  // unbalanced; let the caller's predicate decide
                }
                --depth;
            }
        }
        return std::string_view::npos;
    }

private:
    // Skips from an opening delimiter at `open` to its closing `close`, honoring backslash escapes.
    std::size_t skipQuoted(std::size_t open, char close) const
    {
        for (std::size_t i = open + 1; i < text_.size(); ++i) {
            if (text_[i] == '\\') {
                ++i;
                continue;
            }
            if (text_[i] == close) {
                return i;
            }
        }
        return text_.size();
    }

    bool opensDecoration(std::size_t i) const
    {
        if (i == 0) {
            return false;
        }
        const char prev = text_[i - 1];
        if (std::isdigit(static_cast<unsigned char>(prev))) {
            return true;
        }
        return i >= 8 && text_.substr(i - 8, 8) == "AT_FDCWD";
    }

    std::string_view text_;
};

std::size_t findClosingParen(std::string_view text, std::size_t afterOpen)
{
    // The first ')' at nesting depth 0 closes the argument list.
    Scanner scanner(text);
    return scanner.findTopLevel(afterOpen, [](char c) { return c == ')'; });
}

bool parseInteger(std::string_view text, long long& value, std::size_t& consumed)
{
    std::size_t i = 0;
    bool negative = false;
    if (i < text.size() && text[i] == '-') {
        negative = true;
        ++i;
    }
    int base = 10;
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
        base = 16;
        i += 2;
    }
    const std::size_t digitsStart = i;
    unsigned long long accumulator = 0;
    while (i < text.size()) {
        const char c = text[i];
        int digit = -1;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (base == 16 && c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (base == 16 && c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        }
        if (digit < 0) {
            break;
        }
        accumulator = accumulator * static_cast<unsigned long long>(base) + static_cast<unsigned long long>(digit);
        ++i;
    }
    if (i == digitsStart) {
        return false;
    }
    value = negative ? -static_cast<long long>(accumulator) : static_cast<long long>(accumulator);
    consumed = i;
    return true;
}

void parseReturn(std::string_view text, SyscallRecord& record)
{
    text = trim(text);
    if (text.empty()) {
        return;
    }
    if (text.front() == '?') {
        record.returnKnown = false;
        auto rest = trim(text.substr(1));
        if (!rest.empty() && rest.front() == 'E') {
            record.errnoName = std::string(rest.substr(0, rest.find(' ')));
        }
        return;
    }
    long long value = 0;
    std::size_t consumed = 0;
    if (!parseInteger(text, value, consumed)) {
        return;
    }
    record.returnKnown = true;
    record.returnValue = value;
    text.remove_prefix(consumed);
    if (!text.empty() && text.front() == '<') {
        // Decoration directly follows the number; find its end honoring escapes.
        std::size_t end = 1;
        while (end < text.size() && text[end] != '>') {
            if (text[end] == '\\') {
                ++end;
            }
            ++end;
        }
        record.returnDecoration = decodeEscapes(text.substr(1, std::min(end, text.size()) - 1));
        text.remove_prefix(std::min(end + 1, text.size()));
    }
    text = trim(text);
    if (value < 0 && !text.empty() && text.front() == 'E') {
        record.errnoName = std::string(text.substr(0, text.find(' ')));
    }
    const auto comment = text.find("/* ");
    if (comment != std::string_view::npos) {
        auto inner = text.substr(comment + 3);
        long long translated = 0;
        std::size_t used = 0;
        if (parseInteger(inner, translated, used) && inner.substr(used).find("in strace's PID NS") != std::string_view::npos) {
            record.translatedPid = translated;
        }
    }
}

}  // namespace

std::optional<StraceLine> parseStraceLine(std::string_view line)
{
    line = trim(line);
    StraceLine result;
    long long pid = 0;
    std::size_t used = 0;
    if (!parseInteger(line, pid, used) || pid <= 0) {
        return std::nullopt;
    }
    result.pid = static_cast<int>(pid);
    line = trim(line.substr(used));
    // Timestamp "seconds.micros".
    std::size_t tsEnd = 0;
    while (tsEnd < line.size() && (std::isdigit(static_cast<unsigned char>(line[tsEnd])) || line[tsEnd] == '.')) {
        ++tsEnd;
    }
    if (tsEnd == 0) {
        return std::nullopt;
    }
    result.timestamp = std::strtod(std::string(line.substr(0, tsEnd)).c_str(), nullptr);
    std::string_view rest = trim(line.substr(tsEnd));

    if (startsWith(rest, "+++ exited with ")) {
        long long code = 0;
        std::size_t n = 0;
        if (!parseInteger(rest.substr(16), code, n)) {
            return std::nullopt;
        }
        result.kind = StraceLine::Kind::Exited;
        result.exitCode = static_cast<int>(code);
        return result;
    }
    if (startsWith(rest, "+++ killed by ")) {
        auto signal = rest.substr(14);
        result.kind = StraceLine::Kind::Killed;
        result.name = std::string(signal.substr(0, signal.find(' ')));
        result.coreDumped = signal.find("(core dumped)") != std::string_view::npos;
        return result;
    }
    if (startsWith(rest, "--- ")) {
        auto signal = rest.substr(4);
        result.kind = StraceLine::Kind::Signal;
        result.name = std::string(signal.substr(0, signal.find(' ')));
        return result;
    }
    if (startsWith(rest, "<... ")) {
        const auto marker = rest.find(" resumed>");
        if (marker == std::string_view::npos) {
            return std::nullopt;
        }
        result.kind = StraceLine::Kind::Resumed;
        result.name = std::string(rest.substr(5, marker - 5));
        result.text = std::string(rest.substr(marker + 9));
        return isIdentifier(result.name) ? std::optional<StraceLine>(result) : std::nullopt;
    }
    const auto paren = rest.find('(');
    if (paren == std::string_view::npos) {
        return std::nullopt;
    }
    result.name = std::string(rest.substr(0, paren));
    if (!isIdentifier(result.name)) {
        return std::nullopt;
    }
    constexpr std::string_view kUnfinished = "<unfinished ...>";
    if (rest.size() >= kUnfinished.size() && rest.substr(rest.size() - kUnfinished.size()) == kUnfinished) {
        result.kind = StraceLine::Kind::Unfinished;
        result.text = std::string(trim(rest.substr(0, rest.size() - kUnfinished.size())));
        return result;
    }
    result.kind = StraceLine::Kind::Syscall;
    result.text = std::string(rest);
    return result;
}

std::optional<SyscallRecord> parseSyscallText(std::string_view text)
{
    const auto open = text.find('(');
    if (open == std::string_view::npos || !isIdentifier(text.substr(0, open))) {
        return std::nullopt;
    }
    const auto close = findClosingParen(text, open + 1);
    if (close == std::string_view::npos) {
        return std::nullopt;
    }
    SyscallRecord record;
    record.name = std::string(text.substr(0, open));
    record.args = splitArguments(text.substr(open + 1, close - open - 1));
    auto rest = trim(text.substr(close + 1));
    if (rest.empty() || rest.front() != '=') {
        return std::nullopt;
    }
    parseReturn(rest.substr(1), record);
    return record;
}

std::vector<std::string> splitArguments(std::string_view args)
{
    std::vector<std::string> result;
    Scanner scanner(args);
    std::size_t start = 0;
    while (start <= args.size()) {
        const auto comma = scanner.findTopLevel(start, [](char c) { return c == ','; });
        const auto end = comma == std::string_view::npos ? args.size() : comma;
        auto token = trim(args.substr(start, end - start));
        if (!token.empty() || comma != std::string_view::npos) {
            result.emplace_back(token);
        }
        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }
    return result;
}

std::string decodeEscapes(std::string_view text)
{
    std::string out;
    out.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c != '\\' || i + 1 >= text.size()) {
            out += c;
            continue;
        }
        const char e = text[++i];
        switch (e) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case 'r': out += '\r'; break;
        case 'v': out += '\v'; break;
        case 'f': out += '\f'; break;
        case 'a': out += '\a'; break;
        case 'b': out += '\b'; break;
        case '\\': out += '\\'; break;
        case '"': out += '"'; break;
        case '\'': out += '\''; break;
        case 'x': {
            int value = 0;
            int digits = 0;
            while (digits < 2 && i + 1 < text.size() && std::isxdigit(static_cast<unsigned char>(text[i + 1]))) {
                const char h = text[++i];
                value = value * 16 + (std::isdigit(static_cast<unsigned char>(h)) ? h - '0' : (std::tolower(h) - 'a' + 10));
                ++digits;
            }
            out += static_cast<char>(value);
            break;
        }
        default:
            if (e >= '0' && e <= '7') {
                int value = e - '0';
                int digits = 1;
                while (digits < 3 && i + 1 < text.size() && text[i + 1] >= '0' && text[i + 1] <= '7') {
                    value = value * 8 + (text[++i] - '0');
                    ++digits;
                }
                out += static_cast<char>(value & 0xff);
            } else {
                out += e;
            }
        }
    }
    return out;
}

std::optional<std::string> decodeQuotedString(std::string_view token, bool* truncated)
{
    token = trim(token);
    if (token.empty() || token.front() != '"') {
        return std::nullopt;
    }
    std::size_t end = 1;
    while (end < token.size() && token[end] != '"') {
        if (token[end] == '\\') {
            ++end;
        }
        ++end;
    }
    if (end >= token.size()) {
        return std::nullopt;
    }
    if (truncated != nullptr) {
        *truncated = token.substr(end + 1).find("...") != std::string_view::npos;
    }
    return decodeEscapes(token.substr(1, end - 1));
}

FdRef parseFdToken(std::string_view token)
{
    token = trim(token);
    FdRef ref;
    std::size_t decorationStart = std::string_view::npos;
    if (startsWith(token, "AT_FDCWD")) {
        ref.atFdcwd = true;
        decorationStart = 8;
    } else {
        long long value = 0;
        std::size_t used = 0;
        if (parseInteger(token, value, used)) {
            ref.fd = static_cast<int>(value);
            decorationStart = used;
        }
    }
    if (decorationStart != std::string_view::npos && decorationStart < token.size() && token[decorationStart] == '<' &&
        token.back() == '>') {
        const std::string decoded = decodeEscapes(token.substr(decorationStart + 1, token.size() - decorationStart - 2));
        if (startsWith(decoded, "socket:[") && decoded.back() == ']') {
            ref.socketInode = std::strtoull(decoded.c_str() + 8, nullptr, 10);
        } else {
            ref.path = decoded;
        }
    }
    return ref;
}

std::vector<std::string> parseStringArray(std::string_view token, bool* truncated)
{
    std::vector<std::string> values;
    token = trim(token);
    if (token.size() < 2 || token.front() != '[') {
        return values;
    }
    const auto close = token.rfind(']');
    if (close == std::string_view::npos || close == 0) {
        return values;
    }
    for (const auto& element : splitArguments(token.substr(1, close - 1))) {
        bool elementTruncated = false;
        if (auto value = decodeQuotedString(element, &elementTruncated)) {
            values.push_back(std::move(*value));
            if (elementTruncated && truncated != nullptr) {
                *truncated = true;
            }
        } else if (element == "..." && truncated != nullptr) {
            *truncated = true;
        }
    }
    return values;
}

std::optional<SockAddr> parseSockAddr(std::string_view token)
{
    token = trim(token);
    if (token.size() < 2 || token.front() != '{') {
        return std::nullopt;
    }
    const auto close = token.rfind('}');
    if (close == std::string_view::npos) {
        return std::nullopt;
    }
    SockAddr addr;
    for (const auto& fieldText : splitArguments(token.substr(1, close - 1))) {
        std::string_view field = fieldText;
        if (startsWith(field, "sa_family=")) {
            addr.family = std::string(field.substr(10));
        } else if (startsWith(field, "sin_port=htons(") || startsWith(field, "sin6_port=htons(")) {
            const auto open = field.find('(');
            long long port = 0;
            std::size_t used = 0;
            if (parseInteger(field.substr(open + 1), port, used)) {
                addr.port = static_cast<int>(port);
            }
        } else if (startsWith(field, "sin_addr=inet_addr(")) {
            if (auto value = decodeQuotedString(field.substr(19))) {
                addr.address = *value;
            }
        } else if (startsWith(field, "inet_pton(")) {
            const auto inner = splitArguments(field.substr(10, field.size() - 11));
            if (inner.size() >= 2) {
                if (auto value = decodeQuotedString(inner[1])) {
                    addr.address = *value;
                }
            }
        } else if (startsWith(field, "sun_path=")) {
            auto value = field.substr(9);
            const bool abstract = startsWith(value, "@");
            if (auto decoded = decodeQuotedString(abstract ? value.substr(1) : value)) {
                addr.address = (abstract ? "@" : "") + *decoded;
            }
        }
    }
    if (addr.family.empty()) {
        return std::nullopt;
    }
    return addr;
}

std::optional<SyscallRecord> StraceAssembler::push(const StraceLine& line)
{
    switch (line.kind) {
    case StraceLine::Kind::Syscall: {
        auto record = parseSyscallText(line.text);
        if (record) {
            record->pid = line.pid;
            record->timestamp = line.timestamp;
        }
        return record;
    }
    case StraceLine::Kind::Unfinished:
        pending_[line.pid] = Pending{line.timestamp, line.text};
        return std::nullopt;
    case StraceLine::Kind::Resumed: {
        const auto it = pending_.find(line.pid);
        if (it == pending_.end()) {
            return std::nullopt;
        }
        const Pending pending = it->second;
        pending_.erase(it);
        std::string text = pending.text + line.text;
        auto record = parseSyscallText(text);
        if (record) {
            record->pid = line.pid;
            record->timestamp = pending.timestamp;
        }
        return record;
    }
    case StraceLine::Kind::Exited:
    case StraceLine::Kind::Killed:
        pending_.erase(line.pid);
        return std::nullopt;
    case StraceLine::Kind::Signal:
        return std::nullopt;
    }
    return std::nullopt;
}

}  // namespace tracepot
