#pragma once

#include "core/models/Report.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace tracepot {

struct DnsQuestion {
    std::string name;
    std::string type;  // A, AAAA, MX, ... or TYPE<n>
};

// Decodes the questions of a DNS query message (wire format). Returns nothing if the buffer is
// not a well-formed query. The buffer is untrusted; all reads are bounds-checked.
std::vector<DnsQuestion> decodeDnsQuery(std::string_view message);

// URLs (http, https, ftp, ssh, git) mentioned in a command line. These are inferences: the
// presence of a URL in argv does not prove a connection was attempted.
std::vector<std::string> extractUrls(const std::vector<std::string>& argv);

struct UrlParts {
    std::string scheme;
    std::string host;
    std::optional<int> port;
};
std::optional<UrlParts> parseUrl(std::string_view url);

enum class NetworkMode { Isolated };

// Network access policy for the sandbox. Only the isolated mode is implemented: the sandbox gets a
// private network namespace containing a loopback interface, so nothing can leave the sandbox.
// A future controlled gateway (e.g. a filtering proxy reachable through a socket bound into the
// sandbox) would implement this interface: contribute sandbox arguments, describe the policy, and
// return the events it observed on its side of the boundary.
class NetworkGateway {
public:
    virtual ~NetworkGateway() = default;
    [[nodiscard]] virtual NetworkPolicyInfo describe() const = 0;
    // Extra bubblewrap arguments required by the gateway (none for the isolated mode).
    [[nodiscard]] virtual std::vector<std::string> sandboxArguments() const = 0;
    // Events observed by the gateway itself (in addition to syscall-level observations).
    [[nodiscard]] virtual std::vector<NetworkEvent> collectEvents() = 0;
};

class IsolatedNetwork final : public NetworkGateway {
public:
    [[nodiscard]] NetworkPolicyInfo describe() const override;
    [[nodiscard]] std::vector<std::string> sandboxArguments() const override { return {}; }
    [[nodiscard]] std::vector<NetworkEvent> collectEvents() override { return {}; }
};

}  // namespace tracepot
