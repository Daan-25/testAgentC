# bindiff — Binary Diff with Explanation

A CLI tool that compares two Windows PE executables (`.exe` / `.dll`) and
prints a human-readable report of what changed.

## Building

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Usage

```
./build/bindiff <old.exe|dll> <new.exe|dll> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--min-len N` | Minimum string length for extraction | 4 |
| `--max-examples N` | Max example strings to display | 50 |
| `--out FILE` | Write report to FILE (also prints to stdout) | — |
| `--no-strings` | Disable strings scanning | — |
| `--no-hash` | Disable SHA-256 hashing (file + section) | — |
| `--help` | Show help message | — |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Usage error |
| 3 | File read error |
| 4 | PE parse error |

### Example output

```
Binary Diff Report
Old: app_v1.exe
New: app_v2.exe

=== File Size ===
  1024 -> 1536 bytes (+512)

=== SHA-256 ===
  Old: a1b2c3d4e5f6...
  New: f6e5d4c3b2a1...
  Match: no

=== PE Header Changes ===
  Entry point: 0x00001000 -> 0x00002000
  Timestamp: 2021-01-14 08:25:36 UTC -> 2021-07-27 12:45:52 UTC

=== Section Changes ===
  + Added:   .rsrc (size=512)
  ~ Changed: .text
      Content: changed (hash differs)

=== Strings Changes ===
  Added:   12 strings
  Removed: 3 strings
  Top removed:
    - OldFunction
    - LegacyAPI
    - DeprecatedCall
  Top added:
    + NewFeature
    + UpdatedString
```

## What it compares

| Category | Details |
|----------|---------|
| **File size** | Overall size change with delta |
| **SHA-256** | File hashes with match/no-match indicator |
| **Architecture** | Machine type (x86, x64, ARM64) |
| **PE headers** | Entry point, image base/size, timestamp, OS version |
| **Sections** | Added / removed / modified sections with size deltas and content hash comparison |
| **Imports** | Added / removed DLLs and individual imported functions |
| **Exports** | Added / removed exported function names |
| **Strings** | Added / removed ASCII and UTF-16LE strings with counts and examples |

## Running tests

```bash
cd build && ctest --output-on-failure
```