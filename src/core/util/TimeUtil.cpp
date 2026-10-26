#include "core/util/TimeUtil.hpp"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <ctime>

#include <sys/random.h>

namespace tracepot {

std::string isoTimestampUtc(std::chrono::system_clock::time_point time)
{
    return isoTimestampFromEpoch(epochSeconds(time));
}

std::string isoTimestampFromEpoch(double epoch)
{
    const auto whole = static_cast<std::time_t>(std::floor(epoch));
    auto millis = static_cast<int>(std::lround((epoch - static_cast<double>(whole)) * 1000.0));
    std::time_t seconds = whole;
    if (millis >= 1000) {
        millis -= 1000;
        ++seconds;
    }
    std::tm tm{};
    ::gmtime_r(&seconds, &tm);
    std::array<char, 40> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
    return buffer.data();
}

double epochSeconds(std::chrono::system_clock::time_point time)
{
    return std::chrono::duration<double>(time.time_since_epoch()).count();
}

std::string makeAnalysisId()
{
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&now, &tm);
    std::array<char, 32> stamp{};
    std::strftime(stamp.data(), stamp.size(), "%Y%m%dT%H%M%SZ", &tm);

    std::array<std::uint8_t, 4> random{};
    if (::getrandom(random.data(), random.size(), 0) != static_cast<ssize_t>(random.size())) {
        const auto ticks = static_cast<std::uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        for (std::size_t i = 0; i < random.size(); ++i) {
            random[i] = static_cast<std::uint8_t>(ticks >> (i * 8));
        }
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string id = "tracepot-";
    id += stamp.data();
    id += '-';
    for (const auto byte : random) {
        id += kHex[byte >> 4];
        id += kHex[byte & 0x0f];
    }
    return id;
}

}  // namespace tracepot
