# Cirth — Binary Static Analysis Tool

Cirth is a fast, lightweight CLI tool written in Rust for performing static analysis on binary files.  
It extracts detailed metadata, detects patterns, and provides insights useful for reverse engineering, malware analysis, and security research.

---

## Features

### Binary Identification
- Detects file format:
  - ELF (Linux)
  - PE (Windows)
  - Mach-O (macOS)
- Identifies target operating system

### Architecture Analysis
- Detects CPU architecture:
  - x86
  - x86_64
  - ARM
  - Others (best effort)

### Linking Information
- Determines:
  - Static vs Dynamic linking

### Symbol Analysis
- Detects whether binary is:
  - Stripped (no symbols)
  - Contains debug/symbol info

### Imports & Libraries
- Extracts:
  - Imported functions
  - Shared libraries
  - Common APIs (`printf`, `scanf`, etc.)

### String Extraction
- Pulls printable strings from binaries
- Useful for:
  - Secrets discovery
  - Endpoint detection
  - Reverse engineering clues

### Security Heuristics
- Basic detection of:
  - Packed / obfuscated binaries
  - High entropy sections
  - Suspicious patterns

### Anti-Debug Detection (Heuristic)
- Detects indicators like:
  - `ptrace`
  - `IsDebuggerPresent`
  - `CheckRemoteDebuggerPresent`

### Language Detection (Heuristic)
- Attempts to infer:
  - Rust
  - C / C++
  - Go
