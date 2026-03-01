#include <gtest/gtest.h>
#include "pe_parser.h"
#include "pe_types.h"

#include <cstring>
#include <vector>

namespace {

using namespace bindiff;

// Helper: build a minimal valid PE32 (32-bit) buffer in memory.
// This creates a tiny PE with one section called ".text".
std::vector<uint8_t> make_minimal_pe32(
    uint16_t machine = IMAGE_FILE_MACHINE_I386,
    uint32_t entry_point = 0x1000,
    uint32_t timestamp = 0x60000000)
{
    // We need: DOS header (64 bytes) + PE sig (4) + COFF header (20) +
    // optional header (PE32 = 96 + 16*8=224 bytes) + 1 section header (40)
    // Total minimal: 64 + 4 + 20 + 224 + 40 = 352 bytes
    // Section raw data starts at 512 (aligned), size 512
    const size_t dos_size = 64;
    const size_t pe_offset = dos_size;
    const size_t coff_offset = pe_offset + 4;
    const size_t opt_offset = coff_offset + 20;
    const size_t opt_size = 224; // PE32 optional header with 16 data dirs
    const size_t sec_offset = opt_offset + opt_size;
    const size_t sec_raw_offset = 512;
    const size_t sec_raw_size = 512;
    const size_t total_size = sec_raw_offset + sec_raw_size;

    std::vector<uint8_t> buf(total_size, 0);

    auto write16 = [&](size_t off, uint16_t v) { std::memcpy(&buf[off], &v, 2); };
    auto write32 = [&](size_t off, uint32_t v) { std::memcpy(&buf[off], &v, 4); };

    // DOS header
    write16(0, DOS_MAGIC);        // e_magic = "MZ"
    write32(0x3C, static_cast<uint32_t>(pe_offset));  // e_lfanew

    // PE signature
    write32(pe_offset, PE_SIGNATURE);

    // COFF file header
    write16(coff_offset + 0, machine);       // Machine
    write16(coff_offset + 2, 1);             // NumberOfSections
    write32(coff_offset + 4, timestamp);     // TimeDateStamp
    write16(coff_offset + 16, static_cast<uint16_t>(opt_size)); // SizeOfOptionalHeader
    write16(coff_offset + 18, 0x0102);       // Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)

    // Optional header (PE32)
    write16(opt_offset + 0, PE32_MAGIC);     // Magic
    write32(opt_offset + 16, entry_point);   // AddressOfEntryPoint
    write32(opt_offset + 28, 0x00400000);    // ImageBase (PE32: offset 28)
    write32(opt_offset + 32, 0x1000);        // SectionAlignment
    write32(opt_offset + 36, 0x200);         // FileAlignment
    write16(opt_offset + 40, 6);             // MajorOperatingSystemVersion
    write16(opt_offset + 42, 0);             // MinorOperatingSystemVersion
    write32(opt_offset + 56, 0x3000);        // SizeOfImage
    write32(opt_offset + 92, 16);            // NumberOfRvaAndSizes

    // Section header: ".text"
    std::memcpy(&buf[sec_offset], ".text\0\0\0", 8);
    write32(sec_offset + 8, sec_raw_size);   // VirtualSize
    write32(sec_offset + 12, 0x1000);        // VirtualAddress
    write32(sec_offset + 16, sec_raw_size);  // SizeOfRawData
    write32(sec_offset + 20, static_cast<uint32_t>(sec_raw_offset)); // PointerToRawData
    write32(sec_offset + 36, 0x60000020);    // Characteristics: Code|Exec|Read

    return buf;
}

TEST(PeParser, RejectsEmptyBuffer) {
    std::vector<uint8_t> empty;
    auto info = parse_pe_from_buffer(empty, "empty");
    EXPECT_FALSE(info.valid);
    EXPECT_NE(info.error.find("MZ"), std::string::npos);
}

TEST(PeParser, RejectsNonPeFile) {
    std::vector<uint8_t> txt = {'H', 'e', 'l', 'l', 'o'};
    auto info = parse_pe_from_buffer(txt, "hello.txt");
    EXPECT_FALSE(info.valid);
}

TEST(PeParser, ParsesMinimalPe32) {
    auto buf = make_minimal_pe32();
    auto info = parse_pe_from_buffer(buf, "test.exe");

    EXPECT_TRUE(info.valid) << "Error: " << info.error;
    EXPECT_EQ(info.file_size, buf.size());
    EXPECT_EQ(info.machine, IMAGE_FILE_MACHINE_I386);
    EXPECT_FALSE(info.is_pe32_plus);
    EXPECT_EQ(info.entry_point, 0x1000u);
    EXPECT_EQ(info.image_base, 0x00400000u);
    EXPECT_EQ(info.num_sections, 1);
    ASSERT_EQ(info.sections.size(), 1u);
    EXPECT_EQ(info.sections[0].name, ".text");
    EXPECT_EQ(info.sections[0].virtual_size, 512u);
}

TEST(PeParser, MachineName) {
    auto buf = make_minimal_pe32(IMAGE_FILE_MACHINE_I386);
    auto info = parse_pe_from_buffer(buf);
    EXPECT_EQ(info.machine_name(), "x86 (i386)");

    // Change machine to AMD64
    buf = make_minimal_pe32(IMAGE_FILE_MACHINE_AMD64);
    info = parse_pe_from_buffer(buf);
    EXPECT_EQ(info.machine_name(), "x64 (AMD64)");
}

TEST(PeParser, TimestampString) {
    auto buf = make_minimal_pe32(IMAGE_FILE_MACHINE_I386, 0x1000, 0);
    auto info = parse_pe_from_buffer(buf);
    EXPECT_TRUE(info.valid);
    // Timestamp 0 = 1970-01-01 00:00:00 UTC
    EXPECT_EQ(info.timestamp_str(), "1970-01-01 00:00:00 UTC");
}

TEST(PeParser, DetectsDifferentEntryPoints) {
    auto buf1 = make_minimal_pe32(IMAGE_FILE_MACHINE_I386, 0x1000);
    auto buf2 = make_minimal_pe32(IMAGE_FILE_MACHINE_I386, 0x2000);
    auto info1 = parse_pe_from_buffer(buf1, "old.exe");
    auto info2 = parse_pe_from_buffer(buf2, "new.exe");

    EXPECT_TRUE(info1.valid);
    EXPECT_TRUE(info2.valid);
    EXPECT_NE(info1.entry_point, info2.entry_point);
}

TEST(PeParser, ParseNonExistentFile) {
    auto info = parse_pe("/nonexistent/path/file.exe");
    EXPECT_FALSE(info.valid);
    EXPECT_NE(info.error.find("Cannot open"), std::string::npos);
}

} // namespace
