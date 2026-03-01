#include "pe_parser.h"
#include "pe_diff.h"
#include "sha256.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <old.exe|dll> <new.exe|dll> [options]\n"
        << "\n"
        << "Compares two Windows PE executables and prints a\n"
        << "human-readable report of what changed.\n"
        << "\n"
        << "Options:\n"
        << "  --min-len N       Minimum string length (default: 4)\n"
        << "  --max-examples N  Max example strings to display (default: 50)\n"
        << "  --out FILE        Write report to FILE (also prints to stdout)\n"
        << "  --no-strings      Disable strings scanning\n"
        << "  --no-hash         Disable SHA-256 hashing (file + section)\n"
        << "  --help            Show this help message\n"
        << "\n"
        << "Exit codes:\n"
        << "  0  Success\n"
        << "  2  Usage error\n"
        << "  3  File read error\n"
        << "  4  PE parse error\n";
}

// Read entire file into a vector; returns false on error.
static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return false;
    auto size = f.tellg();
    if (size < 0) return false;
    f.seekg(0);
    out.resize(static_cast<size_t>(size));
    return !!f.read(reinterpret_cast<char*>(out.data()),
                    static_cast<std::streamsize>(size));
}

int main(int argc, char* argv[]) {
    // Parse arguments
    std::string old_path, new_path, out_file;
    bindiff::DiffOptions diff_opts;
    bool no_hash = false;
    bool show_help = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            show_help = true;
        } else if (arg == "--min-len" && i + 1 < argc) {
            diff_opts.min_string_len = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (arg == "--max-examples" && i + 1 < argc) {
            diff_opts.max_examples = static_cast<size_t>(std::atoi(argv[++i]));
        } else if (arg == "--out" && i + 1 < argc) {
            out_file = argv[++i];
        } else if (arg == "--no-strings") {
            diff_opts.show_strings = false;
        } else if (arg == "--no-hash") {
            no_hash = true;
            diff_opts.show_hashes = false;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 2;
        } else if (old_path.empty()) {
            old_path = arg;
        } else if (new_path.empty()) {
            new_path = arg;
        } else {
            std::cerr << "Too many positional arguments.\n";
            print_usage(argv[0]);
            return 2;
        }
    }

    if (show_help) {
        print_usage(argv[0]);
        return 0;
    }

    if (old_path.empty() || new_path.empty()) {
        print_usage(argv[0]);
        return 2;
    }

    // Read files
    std::vector<uint8_t> old_data, new_data;
    if (!read_file(old_path, old_data)) {
        std::cerr << "Error: cannot read file: " << old_path << "\n";
        return 3;
    }
    if (!read_file(new_path, new_data)) {
        std::cerr << "Error: cannot read file: " << new_path << "\n";
        return 3;
    }

    // Parse PE
    bindiff::ParseOptions parse_opts;
    parse_opts.compute_section_hashes = !no_hash;

    auto old_pe = bindiff::parse_pe_from_buffer(old_data, old_path, parse_opts);
    auto new_pe = bindiff::parse_pe_from_buffer(new_data, new_path, parse_opts);

    if (!old_pe.valid) {
        std::cerr << "Error parsing " << old_path << ": " << old_pe.error << "\n";
        return 4;
    }
    if (!new_pe.valid) {
        std::cerr << "Error parsing " << new_path << ": " << new_pe.error << "\n";
        return 4;
    }

    // Generate report
    std::string report = bindiff::diff_pe(old_pe, new_pe, old_data, new_data,
                                           diff_opts);

    std::cout << report;

    // Write to file if requested
    if (!out_file.empty()) {
        std::ofstream ofs(out_file);
        if (!ofs.is_open()) {
            std::cerr << "Error: cannot write to " << out_file << "\n";
            return 3;
        }
        ofs << report;
        std::cerr << "Report written to " << out_file << "\n";
    }

    return 0;
}
