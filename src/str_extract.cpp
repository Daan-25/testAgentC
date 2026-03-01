#include "str_extract.h"

namespace bindiff {

std::unordered_set<std::string> extract_ascii_strings(
    const uint8_t* data, size_t len, size_t min_len)
{
    std::unordered_set<std::string> result;
    if (data == nullptr || len == 0) return result;
    std::string current;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        if (c >= 0x20 && c <= 0x7E) {
            current.push_back(static_cast<char>(c));
        } else {
            if (current.size() >= min_len)
                result.insert(current);
            current.clear();
        }
    }
    if (current.size() >= min_len)
        result.insert(current);
    return result;
}

std::unordered_set<std::string> extract_utf16le_strings(
    const uint8_t* data, size_t len, size_t min_len)
{
    std::unordered_set<std::string> result;
    if (data == nullptr || len < 2) return result;
    std::string current;
    // Process pairs of bytes; if low byte is printable and high byte is 0x00
    // then it's a UTF-16LE printable character (BMP ASCII range).
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t lo = data[i];
        uint8_t hi = data[i + 1];
        if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E) {
            current.push_back(static_cast<char>(lo));
        } else {
            if (current.size() >= min_len)
                result.insert(current);
            current.clear();
        }
    }
    if (current.size() >= min_len)
        result.insert(current);
    return result;
}

std::unordered_set<std::string> extract_all_strings(
    const uint8_t* data, size_t len, size_t min_len)
{
    auto ascii = extract_ascii_strings(data, len, min_len);
    auto utf16 = extract_utf16le_strings(data, len, min_len);
    ascii.insert(utf16.begin(), utf16.end());
    return ascii;
}

} // namespace bindiff
