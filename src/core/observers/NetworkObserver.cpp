#include "core/observers/NetworkObserver.hpp"

#include <array>
#include <cctype>
#include <cstdint>

namespace tracepot {

namespace {

std::string dnsTypeName(std::uint16_t type)
{
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return "TYPE" + std::to_string(type);
    }
}

std::uint16_t readU16(std::string_view data, std::size_t offset)
{
    return static_cast<std::uint16_t>((static_cast<unsigned char>(data[offset]) << 8) |
                                      static_cast<unsigned char>(data[offset + 1]));
}

}  // namespace

std::vector<DnsQuestion> decodeDnsQuery(std::string_view message)
{
    std::vector<DnsQuestion> questions;
    if (message.size() < 12) {
        return questions;
    }
    const std::uint16_t flags = readU16(message, 2);
    const bool isResponse = (flags & 0x8000) != 0;
    const unsigned opcode = (flags >> 11) & 0x0f;
    const std::uint16_t qdcount = readU16(message, 4);
    if (isResponse || opcode != 0 || qdcount == 0 || qdcount > 16) {
        return questions;
    }
    std::size_t offset = 12;
    for (std::uint16_t q = 0; q < qdcount; ++q) {
        std::string name;
        for (int labels = 0;; ++labels) {
            if (offset >= message.size() || labels > 127) {
                return {};
            }
            const auto length = static_cast<unsigned char>(message[offset]);
            ++offset;
            if (length == 0) {
                break;
            }
            if ((length & 0xc0) != 0 || offset + length > message.size()) {
                return {};  // compression pointers are not used in queries; treat as malformed
            }
            for (std::size_t i = 0; i < length; ++i) {
                const char c = message[offset + i];
                const bool printable = std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
                if (!printable) {
                    return {};
                }
            }
            if (!name.empty()) {
                name += '.';
            }
            name.append(message.substr(offset, length));
            offset += length;
            if (name.size() > 253) {
                return {};
            }
        }
        if (offset + 4 > message.size()) {
            return {};
        }
        questions.push_back({name.empty() ? std::string(".") : name, dnsTypeName(readU16(message, offset))});
        offset += 4;
    }
    return questions;
}

std::optional<UrlParts> parseUrl(std::string_view url)
{
    const auto schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos || schemeEnd == 0) {
        return std::nullopt;
    }
    UrlParts parts;
    parts.scheme = std::string(url.substr(0, schemeEnd));
    for (auto& c : parts.scheme) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    std::string_view rest = url.substr(schemeEnd + 3);
    rest = rest.substr(0, rest.find_first_of("/?#"));
    if (const auto at = rest.rfind('@'); at != std::string_view::npos) {
        rest = rest.substr(at + 1);  // drop credentials; they are never reported
    }
    if (!rest.empty() && rest.front() == '[') {
        const auto close = rest.find(']');
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        parts.host = std::string(rest.substr(1, close - 1));
        rest = rest.substr(close + 1);
        if (!rest.empty() && rest.front() == ':') {
            rest.remove_prefix(1);
        } else {
            rest = {};
        }
    } else {
        const auto colon = rest.rfind(':');
        parts.host = std::string(rest.substr(0, colon));
        rest = colon == std::string_view::npos ? std::string_view() : rest.substr(colon + 1);
    }
    if (!rest.empty()) {
        int port = 0;
        for (const char c : rest) {
            if (!std::isdigit(static_cast<unsigned char>(c)) || port > 65535) {
                return std::nullopt;
            }
            port = port * 10 + (c - '0');
        }
        if (port > 0 && port <= 65535) {
            parts.port = port;
        }
    }
    if (parts.host.empty()) {
        return std::nullopt;
    }
    return parts;
}

std::vector<std::string> extractUrls(const std::vector<std::string>& argv)
{
    static constexpr std::array<std::string_view, 6> kSchemes = {"http://", "https://", "ftp://", "ssh://",
                                                                 "git://", "rsync://"};
    std::vector<std::string> urls;
    for (const auto& arg : argv) {
        for (const auto scheme : kSchemes) {
            std::size_t pos = 0;
            while ((pos = arg.find(scheme, pos)) != std::string::npos) {
                std::size_t end = pos;
                while (end < arg.size()) {
                    const char c = arg[end];
                    if (std::isspace(static_cast<unsigned char>(c)) || c == '"' || c == '\'' || c == '`' ||
                        c == ')' || c == '|' || c == ';' || c == '<' || c == '>') {
                        break;
                    }
                    ++end;
                }
                std::string url = arg.substr(pos, end - pos);
                if (url.size() > scheme.size() && url.size() <= 2048 && parseUrl(url)) {
                    urls.push_back(std::move(url));
                }
                pos = end;
            }
        }
    }
    return urls;
}

NetworkPolicyInfo IsolatedNetwork::describe() const
{
    NetworkPolicyInfo info;
    info.mode = "isolated";
    info.description =
        "Private network namespace with only a loopback interface. No traffic can leave the sandbox; "
        "DNS resolution and external connections fail. Attempts are recorded from the syscall trace.";
    info.externalConnectivity = false;
    info.dnsResolution = false;
    info.observationMethod = "syscall-trace (socket, connect, bind, listen, sendto, sendmsg, sendmmsg)";
    return info;
}

}  // namespace tracepot
