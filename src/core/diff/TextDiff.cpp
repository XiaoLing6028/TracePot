#include "core/diff/TextDiff.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace tracepot {

namespace {

struct Lines {
    std::vector<std::string_view> lines;
    bool missingFinalNewline = false;
};

Lines splitLines(std::string_view text)
{
    Lines result;
    std::size_t start = 0;
    while (start < text.size()) {
        const auto newline = text.find('\n', start);
        if (newline == std::string_view::npos) {
            result.lines.push_back(text.substr(start));
            result.missingFinalNewline = true;
            break;
        }
        result.lines.push_back(text.substr(start, newline - start));
        start = newline + 1;
    }
    return result;
}

struct Op {
    char kind;  // ' ', '-', '+'
    std::size_t a;
    std::size_t b;
};

constexpr std::size_t kMaxLcsCells = 4'000'000;

std::vector<Op> computeOps(const std::vector<std::string_view>& a, const std::vector<std::string_view>& b)
{
    std::size_t prefix = 0;
    while (prefix < a.size() && prefix < b.size() && a[prefix] == b[prefix]) {
        ++prefix;
    }
    std::size_t suffix = 0;
    while (suffix < a.size() - prefix && suffix < b.size() - prefix &&
           a[a.size() - 1 - suffix] == b[b.size() - 1 - suffix]) {
        ++suffix;
    }
    std::vector<Op> ops;
    for (std::size_t i = 0; i < prefix; ++i) {
        ops.push_back({' ', i, i});
    }
    const std::size_t n = a.size() - prefix - suffix;
    const std::size_t m = b.size() - prefix - suffix;

    if (n > 0 && m > 0 && (n + 1) * (m + 1) <= kMaxLcsCells) {
        // Classic LCS table over the differing middle section.
        std::vector<std::uint32_t> table((n + 1) * (m + 1), 0);
        auto at = [&](std::size_t i, std::size_t j) -> std::uint32_t& { return table[i * (m + 1) + j]; };
        for (std::size_t i = n; i-- > 0;) {
            for (std::size_t j = m; j-- > 0;) {
                at(i, j) = a[prefix + i] == b[prefix + j] ? at(i + 1, j + 1) + 1 : std::max(at(i + 1, j), at(i, j + 1));
            }
        }
        std::size_t i = 0;
        std::size_t j = 0;
        while (i < n && j < m) {
            if (a[prefix + i] == b[prefix + j]) {
                ops.push_back({' ', prefix + i, prefix + j});
                ++i;
                ++j;
            } else if (at(i + 1, j) >= at(i, j + 1)) {
                ops.push_back({'-', prefix + i, 0});
                ++i;
            } else {
                ops.push_back({'+', 0, prefix + j});
                ++j;
            }
        }
        for (; i < n; ++i) {
            ops.push_back({'-', prefix + i, 0});
        }
        for (; j < m; ++j) {
            ops.push_back({'+', 0, prefix + j});
        }
    } else {
        for (std::size_t i = 0; i < n; ++i) {
            ops.push_back({'-', prefix + i, 0});
        }
        for (std::size_t j = 0; j < m; ++j) {
            ops.push_back({'+', 0, prefix + j});
        }
    }
    for (std::size_t k = 0; k < suffix; ++k) {
        ops.push_back({' ', a.size() - suffix + k, b.size() - suffix + k});
    }
    return ops;
}

}  // namespace

TextDiffResult unifiedDiff(std::string_view before, std::string_view after, std::string_view labelBefore,
                           std::string_view labelAfter, std::size_t context, std::size_t maxBytes)
{
    TextDiffResult result;
    if (before == after) {
        return result;
    }
    const Lines a = splitLines(before);
    const Lines b = splitLines(after);
    const std::vector<Op> ops = computeOps(a.lines, b.lines);

    // Number of lines of each side consumed before op k.
    std::vector<std::size_t> aBefore(ops.size() + 1, 0);
    std::vector<std::size_t> bBefore(ops.size() + 1, 0);
    for (std::size_t k = 0; k < ops.size(); ++k) {
        aBefore[k + 1] = aBefore[k] + (ops[k].kind != '+' ? 1 : 0);
        bBefore[k + 1] = bBefore[k] + (ops[k].kind != '-' ? 1 : 0);
    }

    std::string& out = result.diff;
    out += "--- ";
    out += labelBefore;
    out += "\n+++ ";
    out += labelAfter;
    out += '\n';

    auto appendLine = [&](char kind, std::string_view line, bool lastWithoutNewline) {
        out += kind;
        out += line;
        out += '\n';
        if (lastWithoutNewline) {
            out += "\\ No newline at end of file\n";
        }
    };

    std::size_t i = 0;
    while (i < ops.size()) {
        std::size_t change = i;
        while (change < ops.size() && ops[change].kind == ' ') {
            ++change;
        }
        if (change == ops.size()) {
            break;
        }
        const std::size_t start = change > context ? change - context : 0;
        std::size_t end = change;
        std::size_t j = change;
        while (j < ops.size()) {
            if (ops[j].kind != ' ') {
                end = j;
                ++j;
                continue;
            }
            std::size_t k = j;
            while (k < ops.size() && ops[k].kind == ' ') {
                ++k;
            }
            if (k < ops.size() && k - j <= 2 * context) {
                j = k;
                continue;
            }
            break;
        }
        const std::size_t stop = std::min(ops.size(), end + 1 + context);
        const std::size_t lenA = aBefore[stop] - aBefore[start];
        const std::size_t lenB = bBefore[stop] - bBefore[start];
        const std::size_t startA = lenA > 0 ? aBefore[start] + 1 : aBefore[start];
        const std::size_t startB = lenB > 0 ? bBefore[start] + 1 : bBefore[start];
        out += "@@ -" + std::to_string(startA) + "," + std::to_string(lenA) + " +" + std::to_string(startB) + "," +
               std::to_string(lenB) + " @@\n";
        for (std::size_t k = start; k < stop; ++k) {
            const Op& op = ops[k];
            if (op.kind == '+') {
                appendLine('+', b.lines[op.b], b.missingFinalNewline && op.b + 1 == b.lines.size());
            } else {
                const bool lastA = a.missingFinalNewline && op.a + 1 == a.lines.size();
                const bool lastB = op.kind == ' ' && b.missingFinalNewline && op.b + 1 == b.lines.size();
                appendLine(op.kind, a.lines[op.a], op.kind == '-' ? lastA : (lastA || lastB));
            }
            if (out.size() > maxBytes) {
                out.resize(maxBytes);
                out += "\n[diff truncated]\n";
                result.truncated = true;
                return result;
            }
        }
        i = stop;
    }
    return result;
}

}  // namespace tracepot
