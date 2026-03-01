#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bindiff {

/// Compute SHA-256 hash of a byte buffer, returns lowercase hex string.
std::string sha256_hex(const uint8_t* data, size_t len);

/// Convenience overload for vector.
inline std::string sha256_hex(const std::vector<uint8_t>& buf) {
    return sha256_hex(buf.data(), buf.size());
}

/// Compute SHA-256 of a file on disk, returns lowercase hex string.
/// Returns empty string on read error.
std::string sha256_file(const std::string& path);

} // namespace bindiff
