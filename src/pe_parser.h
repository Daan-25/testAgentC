#pragma once

#include "pe_types.h"
#include <string>
#include <vector>

namespace bindiff {

/// Options controlling PE parsing behavior.
struct ParseOptions {
    bool compute_section_hashes = true; // Compute SHA-256 per section
};

/// Parse a PE file (.exe or .dll) and return its metadata.
/// On failure, returns a PeInfo with valid==false and an error message.
PeInfo parse_pe(const std::string& file_path,
                const ParseOptions& opts = {});

/// Parse PE from an in-memory buffer (useful for testing).
PeInfo parse_pe_from_buffer(const std::vector<uint8_t>& buffer,
                            const std::string& label = "<buffer>",
                            const ParseOptions& opts = {});

} // namespace bindiff
