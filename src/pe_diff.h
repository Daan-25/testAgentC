#pragma once

#include "pe_types.h"
#include <cstdint>
#include <string>
#include <vector>

namespace bindiff {

/// Options controlling diff report output.
struct DiffOptions {
    bool show_hashes = true;      // Show SHA-256 file hashes + section hashes
    bool show_strings = true;     // Show strings diff
    size_t min_string_len = 4;    // Minimum string length
    size_t max_examples = 50;     // Max example strings to show
};

/// Compare two parsed PE files and return a human-readable diff report.
/// old_data/new_data are the raw file bytes, needed for strings extraction.
std::string diff_pe(const PeInfo& old_pe, const PeInfo& new_pe,
                    const std::vector<uint8_t>& old_data = {},
                    const std::vector<uint8_t>& new_data = {},
                    const DiffOptions& opts = {});

} // namespace bindiff
