#include <gtest/gtest.h>
#include "pe_diff.h"
#include "pe_types.h"

namespace {

using namespace bindiff;

// Build a default PeInfo for testing
PeInfo make_test_pe(const std::string& path = "test.exe") {
    PeInfo pe{};
    pe.file_path = path;
    pe.file_size = 4096;
    pe.valid = true;
    pe.machine = IMAGE_FILE_MACHINE_I386;
    pe.num_sections = 1;
    pe.timestamp = 0x60000000;
    pe.characteristics = 0x0102;
    pe.is_pe32_plus = false;
    pe.entry_point = 0x1000;
    pe.section_alignment = 0x1000;
    pe.file_alignment = 0x200;
    pe.major_os_version = 6;
    pe.minor_os_version = 0;
    pe.image_base = 0x00400000;
    pe.image_size = 0x3000;

    SectionInfo sec{};
    sec.name = ".text";
    sec.virtual_size = 512;
    sec.virtual_address = 0x1000;
    sec.raw_data_size = 512;
    sec.raw_data_offset = 0x200;
    sec.characteristics = 0x60000020;
    pe.sections.push_back(sec);

    return pe;
}

TEST(PeDiff, IdenticalFilesNoChanges) {
    auto pe = make_test_pe("same.exe");
    auto report = diff_pe(pe, pe);

    EXPECT_NE(report.find("No significant differences"), std::string::npos)
        << "Report:\n" << report;
}

TEST(PeDiff, FileSizeChange) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");
    new_pe.file_size = 8192;

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("File Size"), std::string::npos);
    EXPECT_NE(report.find("4096"), std::string::npos);
    EXPECT_NE(report.find("8192"), std::string::npos);
}

TEST(PeDiff, EntryPointChange) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");
    new_pe.entry_point = 0x2000;

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Entry point"), std::string::npos);
    EXPECT_NE(report.find("0x00001000"), std::string::npos);
    EXPECT_NE(report.find("0x00002000"), std::string::npos);
}

TEST(PeDiff, SectionAdded) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");

    SectionInfo new_sec{};
    new_sec.name = ".rsrc";
    new_sec.virtual_size = 1024;
    new_sec.characteristics = 0x40000040;
    new_pe.sections.push_back(new_sec);

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Section Changes"), std::string::npos);
    EXPECT_NE(report.find("Added"), std::string::npos);
    EXPECT_NE(report.find(".rsrc"), std::string::npos);
}

TEST(PeDiff, SectionRemoved) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");
    new_pe.sections.clear();

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Removed"), std::string::npos);
    EXPECT_NE(report.find(".text"), std::string::npos);
}

TEST(PeDiff, ImportDllAdded) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");

    ImportEntry imp{};
    imp.dll_name = "ADVAPI32.dll";
    ImportFunction fn{};
    fn.name = "RegOpenKeyExW";
    fn.by_ordinal = false;
    imp.functions.push_back(fn);
    new_pe.imports.push_back(imp);

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Import Changes"), std::string::npos);
    EXPECT_NE(report.find("ADVAPI32.dll"), std::string::npos);
    EXPECT_NE(report.find("RegOpenKeyExW"), std::string::npos);
}

TEST(PeDiff, ExportAdded) {
    auto old_pe = make_test_pe("old.dll");
    auto new_pe = make_test_pe("new.dll");

    ExportEntry exp{};
    exp.name = "MyNewFunction";
    exp.ordinal = 1;
    exp.rva = 0x1234;
    new_pe.exports.push_back(exp);

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Export Changes"), std::string::npos);
    EXPECT_NE(report.find("MyNewFunction"), std::string::npos);
}

TEST(PeDiff, ArchitectureChange) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");
    new_pe.machine = IMAGE_FILE_MACHINE_AMD64;

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Architecture"), std::string::npos);
    EXPECT_NE(report.find("x86"), std::string::npos);
    EXPECT_NE(report.find("x64"), std::string::npos);
}

TEST(PeDiff, InvalidOldFile) {
    PeInfo old_pe{};
    old_pe.valid = false;
    old_pe.error = "bad file";
    auto new_pe = make_test_pe("new.exe");

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Error parsing old file"), std::string::npos);
}

TEST(PeDiff, ImportFunctionChange) {
    auto old_pe = make_test_pe("old.exe");
    auto new_pe = make_test_pe("new.exe");

    ImportEntry imp_old{};
    imp_old.dll_name = "KERNEL32.dll";
    ImportFunction fn1{}; fn1.name = "CreateFileW"; fn1.by_ordinal = false;
    ImportFunction fn2{}; fn2.name = "ReadFile"; fn2.by_ordinal = false;
    imp_old.functions = {fn1, fn2};
    old_pe.imports.push_back(imp_old);

    ImportEntry imp_new{};
    imp_new.dll_name = "KERNEL32.dll";
    ImportFunction fn3{}; fn3.name = "CreateFileW"; fn3.by_ordinal = false;
    ImportFunction fn4{}; fn4.name = "WriteFile"; fn4.by_ordinal = false;
    imp_new.functions = {fn3, fn4};
    new_pe.imports.push_back(imp_new);

    auto report = diff_pe(old_pe, new_pe);
    EXPECT_NE(report.find("Changed DLL"), std::string::npos);
    EXPECT_NE(report.find("- ReadFile"), std::string::npos);
    EXPECT_NE(report.find("+ WriteFile"), std::string::npos);
}

} // namespace
