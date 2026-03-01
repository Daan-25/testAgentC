#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bindiff {

// PE format constants
constexpr uint16_t DOS_MAGIC = 0x5A4D;       // "MZ"
constexpr uint32_t PE_SIGNATURE = 0x00004550; // "PE\0\0"
constexpr uint16_t PE32_MAGIC = 0x10B;
constexpr uint16_t PE32PLUS_MAGIC = 0x20B;

// Machine types
constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x14C;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

// Data directory indices
constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

struct SectionInfo {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t characteristics;
    std::string content_hash; // SHA-256 of raw section bytes (empty if hashing disabled)
};

struct ImportFunction {
    std::string name;
    uint16_t ordinal;
    bool by_ordinal;
};

struct ImportEntry {
    std::string dll_name;
    std::vector<ImportFunction> functions;
};

struct ExportEntry {
    std::string name;
    uint32_t ordinal;
    uint32_t rva;
};

struct PeInfo {
    // Basic info
    std::string file_path;
    uint64_t file_size;
    bool valid;
    std::string error;

    // File header
    uint16_t machine;
    uint16_t num_sections;
    uint32_t timestamp;
    uint16_t characteristics;

    // Optional header
    bool is_pe32_plus; // true = 64-bit, false = 32-bit
    uint32_t entry_point;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint64_t image_base;
    uint32_t image_size;

    // Sections
    std::vector<SectionInfo> sections;

    // Imports
    std::vector<ImportEntry> imports;

    // Exports
    std::vector<ExportEntry> exports;

    std::string machine_name() const;
    std::string timestamp_str() const;
};

} // namespace bindiff
