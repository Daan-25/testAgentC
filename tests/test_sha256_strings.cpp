#include <gtest/gtest.h>
#include "sha256.h"
#include "str_extract.h"

#include <cstring>
#include <vector>

namespace {

using namespace bindiff;

// --- SHA-256 tests ---

TEST(Sha256, EmptyString) {
    // SHA-256 of empty input is well-known
    std::string hash = sha256_hex(nullptr, 0);
    EXPECT_EQ(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256, HelloWorld) {
    const char* msg = "hello world";
    std::string hash = sha256_hex(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    EXPECT_EQ(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST(Sha256, VectorOverload) {
    std::vector<uint8_t> data = {'a', 'b', 'c'};
    std::string hash = sha256_hex(data);
    EXPECT_EQ(hash, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// --- Strings extraction tests ---

TEST(Strings, AsciiBasic) {
    std::vector<uint8_t> raw = {'H','e','l','l','o', 0x00, 'W','o','r','l','d', 0x00, 'A','B'};
    auto result = extract_ascii_strings(raw.data(), raw.size(), 4);
    EXPECT_TRUE(result.count("Hello"));
    EXPECT_TRUE(result.count("World"));
    EXPECT_FALSE(result.count("AB")); // too short
}

TEST(Strings, AsciiMinLen) {
    std::vector<uint8_t> raw = {'a','b','c','d','e','f', 0x00, 'g','h', 0x00, 'i','j','k','l','m'};
    auto result = extract_ascii_strings(raw.data(), raw.size(), 5);
    EXPECT_TRUE(result.count("abcdef"));
    EXPECT_TRUE(result.count("ijklm"));
    EXPECT_FALSE(result.count("gh")); // below min_len
}

TEST(Strings, Utf16leBasic) {
    // "Test" in UTF-16LE: T\0e\0s\0t\0
    std::vector<uint8_t> data = {
        'T', 0, 'e', 0, 's', 0, 't', 0,
        0, 0, // null terminator (non-printable pair)
        'O', 0, 'K', 0
    };
    auto result = extract_utf16le_strings(data.data(), data.size(), 4);
    EXPECT_TRUE(result.count("Test"));
    EXPECT_FALSE(result.count("OK")); // too short
}

TEST(Strings, ExtractAll) {
    // Mix of ASCII and UTF-16LE
    std::vector<uint8_t> data;
    // ASCII: "hello" + three null bytes to align UTF-16LE to even offset
    for (char c : std::string("hello")) data.push_back(static_cast<uint8_t>(c));
    data.push_back(0);
    data.push_back(0);
    data.push_back(0);
    // UTF-16LE: "World" (now starts at even offset 8)
    for (char c : std::string("World")) {
        data.push_back(static_cast<uint8_t>(c));
        data.push_back(0);
    }
    auto result = extract_all_strings(data.data(), data.size(), 4);
    EXPECT_TRUE(result.count("hello"));
    EXPECT_TRUE(result.count("World"));
}

TEST(Strings, EmptyInput) {
    auto result = extract_ascii_strings(nullptr, 0, 4);
    EXPECT_TRUE(result.empty());
}

} // namespace
