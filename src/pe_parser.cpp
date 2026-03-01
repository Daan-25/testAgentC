#include "pe_parser.h"
#include "sha256.h"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

namespace bindiff {

// ---- helper: safe read from buffer ----

namespace {

struct BufReader {
    const uint8_t* data;
    size_t size;

    template <typename T>
    bool read(size_t offset, T& out) const {
        if (offset + sizeof(T) > size) return false;
        std::memcpy(&out, data + offset, sizeof(T));
        return true;
    }

    bool read_str(size_t offset, size_t max_len, std::string& out) const {
        if (offset >= size) return false;
        size_t end = std::min(offset + max_len, size);
        out.clear();
        for (size_t i = offset; i < end && data[i] != '\0'; ++i)
            out.push_back(static_cast<char>(data[i]));
        return true;
    }
};

uint32_t rva_to_offset(uint32_t rva, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        // Use max(VirtualSize, SizeOfRawData) for more robust RVA mapping
        uint32_t section_span = std::max(sec.virtual_size, sec.raw_data_size);
        if (rva >= sec.virtual_address &&
            rva < sec.virtual_address + section_span) {
            uint32_t offset = sec.raw_data_offset + (rva - sec.virtual_address);
            return offset;
        }
    }
    return 0;
}

} // anonymous namespace

// ---- PeInfo helpers ----

std::string PeInfo::machine_name() const {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86 (i386)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: {
            std::ostringstream oss;
            oss << "Unknown (0x" << std::hex << machine << ")";
            return oss.str();
        }
    }
}

std::string PeInfo::timestamp_str() const {
    time_t t = static_cast<time_t>(timestamp);
    struct tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    return buf;
}

// ---- Core parser ----

PeInfo parse_pe_from_buffer(const std::vector<uint8_t>& buffer,
                            const std::string& label,
                            const ParseOptions& opts) {
    PeInfo info{};
    info.file_path = label;
    info.file_size = buffer.size();
    info.valid = false;

    BufReader r{buffer.data(), buffer.size()};

    // 1. DOS header: check MZ magic at offset 0
    uint16_t dos_magic = 0;
    if (!r.read(0, dos_magic) || dos_magic != DOS_MAGIC) {
        info.error = "Not a valid PE file (missing MZ header)";
        return info;
    }

    // 2. e_lfanew at offset 0x3C -> PE header offset
    uint32_t pe_offset = 0;
    if (!r.read(0x3C, pe_offset)) {
        info.error = "DOS header truncated (cannot read e_lfanew)";
        return info;
    }

    // 3. PE signature
    uint32_t pe_sig = 0;
    if (!r.read(pe_offset, pe_sig) || pe_sig != PE_SIGNATURE) {
        info.error = "Not a valid PE file (bad PE signature)";
        return info;
    }

    // 4. COFF file header (20 bytes starting at pe_offset + 4)
    size_t coff_offset = pe_offset + 4;
    if (!r.read(coff_offset + 0, info.machine))       { info.error = "Truncated COFF header"; return info; }
    if (!r.read(coff_offset + 2, info.num_sections))   { info.error = "Truncated COFF header"; return info; }
    if (!r.read(coff_offset + 4, info.timestamp))      { info.error = "Truncated COFF header"; return info; }
    if (!r.read(coff_offset + 18, info.characteristics)){ info.error = "Truncated COFF header"; return info; }

    // 5. Optional header
    size_t opt_offset = coff_offset + 20;
    uint16_t opt_magic = 0;
    if (!r.read(opt_offset, opt_magic)) {
        info.error = "Missing optional header";
        return info;
    }

    info.is_pe32_plus = (opt_magic == PE32PLUS_MAGIC);

    if (!r.read(opt_offset + 16, info.entry_point)) { info.error = "Truncated optional header"; return info; }
    if (!r.read(opt_offset + 32, info.section_alignment)) { info.error = "Truncated optional header"; return info; }
    if (!r.read(opt_offset + 36, info.file_alignment)) { info.error = "Truncated optional header"; return info; }
    if (!r.read(opt_offset + 40, info.major_os_version)) { info.error = "Truncated optional header"; return info; }
    if (!r.read(opt_offset + 42, info.minor_os_version)) { info.error = "Truncated optional header"; return info; }

    if (info.is_pe32_plus) {
        if (!r.read(opt_offset + 24, info.image_base)) { info.error = "Truncated optional header"; return info; }
        if (!r.read(opt_offset + 56, info.image_size)) { info.error = "Truncated optional header"; return info; }
    } else {
        uint32_t ib32 = 0;
        if (!r.read(opt_offset + 28, ib32)) { info.error = "Truncated optional header"; return info; }
        info.image_base = ib32;
        if (!r.read(opt_offset + 56, info.image_size)) { info.error = "Truncated optional header"; return info; }
    }

    // Data directories: offset depends on PE32 vs PE32+
    size_t dd_offset;
    uint32_t num_data_dirs = 0;
    if (info.is_pe32_plus) {
        dd_offset = opt_offset + 112;
        r.read(opt_offset + 108, num_data_dirs);
    } else {
        dd_offset = opt_offset + 96;
        r.read(opt_offset + 92, num_data_dirs);
    }

    // Read export and import directory RVA/size
    uint32_t export_rva = 0, export_size = 0;
    uint32_t import_rva = 0, import_size = 0;
    if (num_data_dirs > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        r.read(dd_offset + IMAGE_DIRECTORY_ENTRY_EXPORT * 8, export_rva);
        r.read(dd_offset + IMAGE_DIRECTORY_ENTRY_EXPORT * 8 + 4, export_size);
    }
    if (num_data_dirs > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        r.read(dd_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8, import_rva);
        r.read(dd_offset + IMAGE_DIRECTORY_ENTRY_IMPORT * 8 + 4, import_size);
    }

    // 6. Section headers
    uint16_t opt_header_size = 0;
    r.read(coff_offset + 16, opt_header_size); // SizeOfOptionalHeader

    size_t section_offset = opt_offset + opt_header_size;

    info.sections.reserve(info.num_sections);
    for (uint16_t i = 0; i < info.num_sections; ++i) {
        size_t so = section_offset + i * 40;
        SectionInfo sec{};
        // Section name: 8 bytes
        char name_buf[9] = {};
        if (so + 40 > buffer.size()) break;
        std::memcpy(name_buf, buffer.data() + so, 8);
        sec.name = name_buf;

        r.read(so + 8,  sec.virtual_size);
        r.read(so + 12, sec.virtual_address);
        r.read(so + 16, sec.raw_data_size);
        r.read(so + 20, sec.raw_data_offset);
        r.read(so + 36, sec.characteristics);

        // Compute section content hash if requested and data is within bounds
        if (opts.compute_section_hashes &&
            sec.raw_data_size > 0 &&
            sec.raw_data_offset < buffer.size() &&
            static_cast<size_t>(sec.raw_data_offset) + sec.raw_data_size <= buffer.size()) {
            sec.content_hash = sha256_hex(
                buffer.data() + sec.raw_data_offset, sec.raw_data_size);
        }

        info.sections.push_back(sec);
    }

    // 7. Parse imports
    if (import_rva != 0 && import_size != 0) {
        uint32_t imp_offset = rva_to_offset(import_rva, info.sections);
        if (imp_offset != 0) {
            // Each import descriptor is 20 bytes; last one is all zeros
            for (size_t idx = 0; ; ++idx) {
                size_t desc = imp_offset + idx * 20;
                uint32_t ilt_rva = 0, name_rva = 0, ft_rva = 0;
                if (!r.read(desc + 0, ilt_rva)) break;   // OriginalFirstThunk
                if (!r.read(desc + 12, name_rva)) break;  // Name RVA
                if (!r.read(desc + 16, ft_rva)) break;    // FirstThunk
                if (ilt_rva == 0 && name_rva == 0) break;  // terminator

                ImportEntry entry{};
                uint32_t name_off = rva_to_offset(name_rva, info.sections);
                if (name_off != 0) {
                    r.read_str(name_off, 256, entry.dll_name);
                }

                // Fall back to FirstThunk if OriginalFirstThunk is 0
                uint32_t lookup_rva = (ilt_rva != 0) ? ilt_rva : ft_rva;

                // Walk the Import Lookup Table
                uint32_t ilt_off = rva_to_offset(lookup_rva, info.sections);
                if (ilt_off != 0) {
                    for (size_t fi = 0; ; ++fi) {
                        if (info.is_pe32_plus) {
                            uint64_t thunk = 0;
                            if (!r.read(ilt_off + fi * 8, thunk) || thunk == 0) break;
                            ImportFunction func{};
                            if (thunk & 0x8000000000000000ULL) {
                                func.by_ordinal = true;
                                func.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                            } else {
                                func.by_ordinal = false;
                                uint32_t hint_off = rva_to_offset(
                                    static_cast<uint32_t>(thunk & 0x7FFFFFFFFFFFFFFFULL),
                                    info.sections);
                                if (hint_off != 0) {
                                    r.read(hint_off, func.ordinal);
                                    r.read_str(hint_off + 2, 256, func.name);
                                }
                            }
                            entry.functions.push_back(func);
                        } else {
                            uint32_t thunk = 0;
                            if (!r.read(ilt_off + fi * 4, thunk) || thunk == 0) break;
                            ImportFunction func{};
                            if (thunk & 0x80000000U) {
                                func.by_ordinal = true;
                                func.ordinal = static_cast<uint16_t>(thunk & 0xFFFF);
                            } else {
                                func.by_ordinal = false;
                                uint32_t hint_off = rva_to_offset(thunk, info.sections);
                                if (hint_off != 0) {
                                    r.read(hint_off, func.ordinal);
                                    r.read_str(hint_off + 2, 256, func.name);
                                }
                            }
                            entry.functions.push_back(func);
                        }
                    }
                }

                info.imports.push_back(entry);
            }
        }
    }

    // 8. Parse exports
    if (export_rva != 0 && export_size != 0) {
        uint32_t exp_offset = rva_to_offset(export_rva, info.sections);
        if (exp_offset != 0) {
            uint32_t num_functions = 0, num_names = 0;
            uint32_t addr_table_rva = 0, name_ptr_rva = 0, ordinal_table_rva = 0;
            uint32_t ordinal_base = 0;

            r.read(exp_offset + 16, ordinal_base);
            r.read(exp_offset + 20, num_functions);
            r.read(exp_offset + 24, num_names);
            r.read(exp_offset + 28, addr_table_rva);
            r.read(exp_offset + 32, name_ptr_rva);
            r.read(exp_offset + 36, ordinal_table_rva);

            uint32_t addr_off = rva_to_offset(addr_table_rva, info.sections);
            uint32_t name_off = rva_to_offset(name_ptr_rva, info.sections);
            uint32_t ord_off  = rva_to_offset(ordinal_table_rva, info.sections);

            for (uint32_t i = 0; i < num_names && name_off && ord_off && addr_off; ++i) {
                ExportEntry exp{};
                uint32_t name_entry_rva = 0;
                uint16_t ordinal_index = 0;
                r.read(name_off + i * 4, name_entry_rva);
                r.read(ord_off + i * 2, ordinal_index);

                uint32_t fn_name_off = rva_to_offset(name_entry_rva, info.sections);
                if (fn_name_off != 0) {
                    r.read_str(fn_name_off, 256, exp.name);
                }

                exp.ordinal = ordinal_base + ordinal_index;

                uint32_t func_rva = 0;
                r.read(addr_off + ordinal_index * 4, func_rva);
                exp.rva = func_rva;

                info.exports.push_back(exp);
            }
        }
    }

    info.valid = true;
    return info;
}

PeInfo parse_pe(const std::string& file_path,
                const ParseOptions& opts) {
    PeInfo info{};
    info.file_path = file_path;
    info.valid = false;

    std::ifstream f(file_path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        info.error = "Cannot open file: " + file_path;
        return info;
    }

    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(size))) {
        info.error = "Failed to read file: " + file_path;
        return info;
    }

    return parse_pe_from_buffer(buffer, file_path, opts);
}

} // namespace bindiff
