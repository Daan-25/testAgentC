#include "pe_diff.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace bindiff {

namespace {

void header(std::ostringstream& out, const std::string& title) {
    out << "\n=== " << title << " ===\n";
}

void field(std::ostringstream& out, const std::string& name,
           const std::string& old_val, const std::string& new_val) {
    if (old_val != new_val) {
        out << "  " << name << ": " << old_val << " -> " << new_val << "\n";
    }
}

std::string hex32(uint32_t v) {
    std::ostringstream o;
    o << "0x" << std::hex << std::setfill('0') << std::setw(8) << v;
    return o.str();
}

std::string hex64(uint64_t v) {
    std::ostringstream o;
    o << "0x" << std::hex << std::setfill('0') << std::setw(16) << v;
    return o.str();
}

std::string dec(uint64_t v) {
    return std::to_string(v);
}

std::string section_flags(uint32_t ch) {
    std::string s;
    if (ch & 0x00000020) s += "Code ";
    if (ch & 0x00000040) s += "InitData ";
    if (ch & 0x00000080) s += "UninitData ";
    if (ch & 0x20000000) s += "Exec ";
    if (ch & 0x40000000) s += "Read ";
    if (ch & 0x80000000) s += "Write ";
    if (s.empty()) s = "(none)";
    return s;
}

} // anonymous namespace

std::string diff_pe(const PeInfo& old_pe, const PeInfo& new_pe) {
    std::ostringstream out;

    out << "Binary Diff Report\n";
    out << "Old: " << old_pe.file_path << "\n";
    out << "New: " << new_pe.file_path << "\n";

    if (!old_pe.valid || !new_pe.valid) {
        if (!old_pe.valid)
            out << "\nError parsing old file: " << old_pe.error << "\n";
        if (!new_pe.valid)
            out << "\nError parsing new file: " << new_pe.error << "\n";
        return out.str();
    }

    bool any_diff = false;

    // --- File size ---
    if (old_pe.file_size != new_pe.file_size) {
        header(out, "File Size");
        int64_t delta = static_cast<int64_t>(new_pe.file_size) -
                        static_cast<int64_t>(old_pe.file_size);
        out << "  " << dec(old_pe.file_size) << " -> " << dec(new_pe.file_size)
            << " bytes (" << (delta > 0 ? "+" : "") << delta << ")\n";
        any_diff = true;
    }

    // --- Architecture ---
    if (old_pe.machine != new_pe.machine) {
        header(out, "Architecture");
        out << "  " << old_pe.machine_name() << " -> " << new_pe.machine_name() << "\n";
        any_diff = true;
    }

    // --- Header fields ---
    {
        std::ostringstream hdr;
        bool hdr_diff = false;

        auto check = [&](const std::string& name,
                         const std::string& o, const std::string& n) {
            if (o != n) { field(hdr, name, o, n); hdr_diff = true; }
        };

        check("Entry point", hex32(old_pe.entry_point), hex32(new_pe.entry_point));
        check("Image base",  hex64(old_pe.image_base),  hex64(new_pe.image_base));
        check("Image size",  hex32(old_pe.image_size),   hex32(new_pe.image_size));
        check("Timestamp",   old_pe.timestamp_str(),     new_pe.timestamp_str());
        check("OS version",
              dec(old_pe.major_os_version) + "." + dec(old_pe.minor_os_version),
              dec(new_pe.major_os_version) + "." + dec(new_pe.minor_os_version));

        if (hdr_diff) {
            header(out, "PE Header Changes");
            out << hdr.str();
            any_diff = true;
        }
    }

    // --- Sections ---
    {
        std::map<std::string, const SectionInfo*> old_map, new_map;
        for (const auto& s : old_pe.sections) old_map[s.name] = &s;
        for (const auto& s : new_pe.sections) new_map[s.name] = &s;

        std::ostringstream sec_out;
        bool sec_diff = false;

        // Removed sections
        for (const auto& [name, sec] : old_map) {
            if (new_map.find(name) == new_map.end()) {
                sec_out << "  - Removed: " << name
                        << " (size=" << dec(sec->virtual_size) << ")\n";
                sec_diff = true;
            }
        }
        // Added sections
        for (const auto& [name, sec] : new_map) {
            if (old_map.find(name) == old_map.end()) {
                sec_out << "  + Added:   " << name
                        << " (size=" << dec(sec->virtual_size) << ")\n";
                sec_diff = true;
            }
        }
        // Modified sections
        for (const auto& [name, osec] : old_map) {
            auto it = new_map.find(name);
            if (it == new_map.end()) continue;
            const SectionInfo* nsec = it->second;

            std::ostringstream mod;
            bool modified = false;

            if (osec->virtual_size != nsec->virtual_size) {
                int64_t delta = static_cast<int64_t>(nsec->virtual_size) -
                                static_cast<int64_t>(osec->virtual_size);
                mod << "      Size: " << dec(osec->virtual_size) << " -> "
                    << dec(nsec->virtual_size) << " (" << (delta > 0 ? "+" : "")
                    << delta << ")\n";
                modified = true;
            }
            if (osec->characteristics != nsec->characteristics) {
                mod << "      Flags: " << section_flags(osec->characteristics)
                    << " -> " << section_flags(nsec->characteristics) << "\n";
                modified = true;
            }
            if (modified) {
                sec_out << "  ~ Changed: " << name << "\n" << mod.str();
                sec_diff = true;
            }
        }

        if (sec_diff) {
            header(out, "Section Changes");
            out << sec_out.str();
            any_diff = true;
        }
    }

    // --- Imports ---
    {
        std::map<std::string, std::set<std::string>> old_imp, new_imp;
        for (const auto& e : old_pe.imports) {
            auto& s = old_imp[e.dll_name];
            for (const auto& f : e.functions)
                s.insert(f.by_ordinal ? "#" + std::to_string(f.ordinal) : f.name);
        }
        for (const auto& e : new_pe.imports) {
            auto& s = new_imp[e.dll_name];
            for (const auto& f : e.functions)
                s.insert(f.by_ordinal ? "#" + std::to_string(f.ordinal) : f.name);
        }

        std::ostringstream imp_out;
        bool imp_diff = false;

        // Removed DLLs
        for (const auto& [dll, funcs] : old_imp) {
            if (new_imp.find(dll) == new_imp.end()) {
                imp_out << "  - Removed DLL: " << dll << " ("
                        << funcs.size() << " functions)\n";
                imp_diff = true;
            }
        }
        // Added DLLs
        for (const auto& [dll, funcs] : new_imp) {
            if (old_imp.find(dll) == old_imp.end()) {
                imp_out << "  + Added DLL:   " << dll << " ("
                        << funcs.size() << " functions)\n";
                for (const auto& fn : funcs)
                    imp_out << "      + " << fn << "\n";
                imp_diff = true;
            }
        }
        // Changed DLLs
        for (const auto& [dll, old_funcs] : old_imp) {
            auto it = new_imp.find(dll);
            if (it == new_imp.end()) continue;
            const auto& new_funcs = it->second;

            std::vector<std::string> added, removed;
            std::set_difference(new_funcs.begin(), new_funcs.end(),
                                old_funcs.begin(), old_funcs.end(),
                                std::back_inserter(added));
            std::set_difference(old_funcs.begin(), old_funcs.end(),
                                new_funcs.begin(), new_funcs.end(),
                                std::back_inserter(removed));

            if (!added.empty() || !removed.empty()) {
                imp_out << "  ~ Changed DLL: " << dll << "\n";
                for (const auto& f : removed)
                    imp_out << "      - " << f << "\n";
                for (const auto& f : added)
                    imp_out << "      + " << f << "\n";
                imp_diff = true;
            }
        }

        if (imp_diff) {
            header(out, "Import Changes");
            out << imp_out.str();
            any_diff = true;
        }
    }

    // --- Exports ---
    {
        std::set<std::string> old_exp, new_exp;
        for (const auto& e : old_pe.exports) old_exp.insert(e.name);
        for (const auto& e : new_pe.exports) new_exp.insert(e.name);

        std::vector<std::string> added, removed;
        std::set_difference(new_exp.begin(), new_exp.end(),
                            old_exp.begin(), old_exp.end(),
                            std::back_inserter(added));
        std::set_difference(old_exp.begin(), old_exp.end(),
                            new_exp.begin(), new_exp.end(),
                            std::back_inserter(removed));

        if (!added.empty() || !removed.empty()) {
            header(out, "Export Changes");
            for (const auto& e : removed)
                out << "  - Removed: " << e << "\n";
            for (const auto& e : added)
                out << "  + Added:   " << e << "\n";
            any_diff = true;
        }
    }

    if (!any_diff) {
        out << "\nNo significant differences found.\n";
    }

    return out.str();
}

} // namespace bindiff
