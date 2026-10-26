#pragma once

#include <string>
#include <string_view>

namespace tracepot {

// Matches `text` against a path glob:
//   *   any sequence of characters except '/'
//   **  any sequence of characters including '/'
//   ?   any single character except '/'
// All other characters match literally. Matching is case-sensitive and runs in O(n*m).
bool globMatch(std::string_view pattern, std::string_view text);

}  // namespace tracepot
