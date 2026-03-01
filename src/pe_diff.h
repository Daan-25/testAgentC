#pragma once

#include "pe_types.h"
#include <string>

namespace bindiff {

/// Compare two parsed PE files and return a human-readable diff report.
std::string diff_pe(const PeInfo& old_pe, const PeInfo& new_pe);

} // namespace bindiff
