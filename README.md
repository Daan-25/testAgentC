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
./build/bindiff <old.exe|dll> <new.exe|dll>
```

### Example output

```
Binary Diff Report
Old: app_v1.exe
New: app_v2.exe

=== File Size ===
  1024 -> 1536 bytes (+512)

=== PE Header Changes ===
  Entry point: 0x00001000 -> 0x00002000
  Timestamp: 2021-01-14 08:25:36 UTC -> 2021-07-27 12:45:52 UTC

=== Section Changes ===
  + Added:   .rsrc (size=512)
```

## What it compares

| Category | Details |
|----------|---------|
| **File size** | Overall size change with delta |
| **Architecture** | Machine type (x86, x64, ARM64) |
| **PE headers** | Entry point, image base/size, timestamp, OS version |
| **Sections** | Added / removed / modified sections with size deltas |
| **Imports** | Added / removed DLLs and individual imported functions |
| **Exports** | Added / removed exported function names |

## Running tests

```bash
cd build && ctest --output-on-failure
```