#include "core/util/Glob.hpp"

#include <algorithm>
#include <vector>

namespace tracepot {

namespace {

enum class TokenKind { Literal, Star, DoubleStar, Question };

struct Token {
    TokenKind kind;
    char literal;
};

std::vector<Token> tokenize(std::string_view pattern)
{
    std::vector<Token> tokens;
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        const char c = pattern[i];
        if (c == '*') {
            if (i + 1 < pattern.size() && pattern[i + 1] == '*') {
                tokens.push_back({TokenKind::DoubleStar, 0});
                ++i;
            } else {
                tokens.push_back({TokenKind::Star, 0});
            }
        } else if (c == '?') {
            tokens.push_back({TokenKind::Question, 0});
        } else {
            tokens.push_back({TokenKind::Literal, c});
        }
    }
    return tokens;
}

}  // namespace

bool globMatch(std::string_view pattern, std::string_view text)
{
    const auto tokens = tokenize(pattern);
    const std::size_t n = tokens.size();
    const std::size_t m = text.size();
    // dp[j] == true means tokens[0..i) match text[0..j).
    std::vector<char> dp(m + 1, 0);
    std::vector<char> next(m + 1, 0);
    dp[0] = 1;
    for (std::size_t i = 0; i < n; ++i) {
        const Token& token = tokens[i];
        std::fill(next.begin(), next.end(), 0);
        switch (token.kind) {
        case TokenKind::Literal:
        case TokenKind::Question:
            for (std::size_t j = 0; j < m; ++j) {
                if (!dp[j]) {
                    continue;
                }
                const bool matches = token.kind == TokenKind::Question ? text[j] != '/' : text[j] == token.literal;
                if (matches) {
                    next[j + 1] = 1;
                }
            }
            break;
        case TokenKind::Star:
            for (std::size_t j = 0; j <= m; ++j) {
                // Either the star matches nothing here, or it extends a match by one non-'/' char.
                if (dp[j] || (j > 0 && next[j - 1] && text[j - 1] != '/')) {
                    next[j] = 1;
                }
            }
            break;
        case TokenKind::DoubleStar:
            for (std::size_t j = 0; j <= m; ++j) {
                if (dp[j] || (j > 0 && next[j - 1])) {
                    next[j] = 1;
                }
            }
            break;
        }
        dp.swap(next);
    }
    return dp[m] != 0;
}

}  // namespace tracepot
