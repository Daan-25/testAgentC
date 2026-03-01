#include "pe_parser.h"
#include "pe_diff.h"

#include <iostream>
#include <string>

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <old.exe|dll> <new.exe|dll>\n"
              << "\n"
              << "Compares two Windows PE executables and prints a\n"
              << "human-readable report of what changed.\n";
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string old_path = argv[1];
    const std::string new_path = argv[2];

    auto old_pe = bindiff::parse_pe(old_path);
    auto new_pe = bindiff::parse_pe(new_path);

    std::cout << bindiff::diff_pe(old_pe, new_pe);

    if (!old_pe.valid || !new_pe.valid)
        return 2;

    return 0;
}
