#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace bindiff {

/// Extract printable ASCII strings of at least min_len characters.
std::unordered_set<std::string> extract_ascii_strings(
    const uint8_t* data, size_t len, size_t min_len = 4);

/// Extract printable UTF-16LE strings of at least min_len characters.
std::unordered_set<std::string> extract_utf16le_strings(
    const uint8_t* data, size_t len, size_t min_len = 4);

/// Extract both ASCII and UTF-16LE strings, merged into one set.
std::unordered_set<std::string> extract_all_strings(
    const uint8_t* data, size_t len, size_t min_len = 4);

} // namespace bindiff
