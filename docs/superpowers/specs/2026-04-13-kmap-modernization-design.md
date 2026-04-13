# Kmap Modernization Design

**Date:** 2026-04-13
**Status:** Approved

## Background

Kmap is a CLI network scanner forked from nmap. All `nmap`/`Nmap`/`NMAP` references have been renamed to `kmap`/`Kmap`/`KMAP`. The zenmap GUI has been removed — Kmap is CLI-only. The codebase is ~50k lines of C++ targeting an implicit C++98 standard with no smart pointers and limited modern language features.

## Goals

1. Enable C++17 and drop dangerous legacy patterns in key files
2. Add JSON output format (`-oJ`) using `nlohmann/json`
3. Add terminal color support with `--color=auto|always|never`

## Non-Goals

- Full codebase modernization sweep (only touch files we edit)
- Rewriting low-level packet parsing (`tcpip.cc`, raw `osscan2.cc` internals)
- Removing any existing output formats
- GUI, web, or non-CLI features

---

## Phase 1 — Foundation (C++17 + nlohmann/json + Security Fixes)

### C++17 Build Flag
- `configure.ac`: add `AX_CXX_COMPILE_STDCXX(17, noext, mandatory)` or manual `-std=c++17` via `CXXFLAGS`
- `Makefile.in`: add `-std=c++17` to `CXXFLAGS`
- Verify existing code still compiles under C++17 (no breaking deprecations expected)

### nlohmann/json
- Download `nlohmann/json.hpp` (single-header, v3.x) into `third-party/nlohmann/json.hpp`
- Add `third-party/` to include path in `Makefile.in`
- No build system changes beyond the include path

### Security Fixes
- `output.cc:719`: Replace `strcpy(protocol, IPPROTO2STR(...))` with `snprintf` or `std::string`
- `osscan2.cc:3053`: Validate `ntohs(ip->ip_len)` is within sane bounds (e.g. ≤ 65535, ≥ IP header size) before `safe_malloc`

### C++17 Modernization in Files Touched
- Replace `NULL` with `nullptr`
- Use `static_cast<>`/`reinterpret_cast<>` in place of C-style casts in edited files

---

## Phase 2 — JSON Output (`-oJ`)

### CLI Flag
- `-oJ <file>` added to option parsing in `kmap.cc` (mirrors existing `-oX`, `-oN`, `-oG`)
- `KmapOps.h`/`KmapOps.cc`: add `char *json_output_file` field, initialized to `nullptr`

### New Log Type
- `output.h`: add `LOG_JSON` constant alongside `LOG_NORMAL`, `LOG_XML`, `LOG_MACHINE`
- Wired into `log_write()` dispatch in `output.cc`

### JSON Serializer
- New file `output_json.cc` + `output_json.h`
- Uses `nlohmann::json` to build document incrementally
- Schema:
  ```json
  {
    "kmap": {
      "version": "...",
      "args": "...",
      "start": 1234567890,
      "startstr": "..."
    },
    "hosts": [
      {
        "status": { "state": "up", "reason": "echo-reply" },
        "address": { "addr": "192.168.1.1", "addrtype": "ipv4" },
        "hostnames": [...],
        "ports": [
          {
            "protocol": "tcp",
            "portid": 80,
            "state": { "state": "open", "reason": "syn-ack" },
            "service": { "name": "http", "product": "...", "version": "..." },
            "scripts": [...]
          }
        ],
        "os": { "osmatch": [...] }
      }
    ],
    "stats": {
      "uphosts": 1,
      "downhosts": 0,
      "totalhosts": 1,
      "elapsed": "1.23"
    }
  }
  ```
- Functions mirror XML output flow: `json_start_scan()`, `json_output_host()`, `json_end_scan()`
- Written to file at scan completion (not streamed, to allow valid JSON)

### Modernization in Files Touched
- `KmapOps.cc`: use `std::unique_ptr<char[]>` or `std::string` for new string fields
- `output_json.cc`: written fully in C++17 style

---

## Phase 3 — Terminal Colors (`--color`)

### New Header: `color.h`
- Thin ANSI escape code wrapper, header-only
- API:
  ```cpp
  namespace Color {
    std::string red(const std::string& s);
    std::string green(const std::string& s);
    std::string yellow(const std::string& s);
    std::string cyan(const std::string& s);
    std::string bold(const std::string& s);
    void set_color_mode(ColorMode mode); // NEVER, AUTO, ALWAYS
    bool colors_enabled();
  }
  enum class ColorMode { NEVER, AUTO, ALWAYS };
  ```
- `AUTO`: calls `isatty(STDOUT_FILENO)`; on Windows uses `_isatty(_fileno(stdout))`
- Respects `NO_COLOR` environment variable (if set, treat as NEVER regardless of flag)
- Windows: uses `SetConsoleTextAttribute` via `#ifdef _WIN32` in `color.h` OR ANSI via `ENABLE_VIRTUAL_TERMINAL_PROCESSING` (Windows 10+)

### CLI Flag
- `--color=auto|always|never` added to option parsing in `kmap.cc`
- Calls `Color::set_color_mode()` during option setup
- Default: `ColorMode::AUTO`

### Output Wiring (`output.cc`)
- Open ports → `Color::green("open")`
- Closed ports → `Color::red("closed")`
- Filtered ports → `Color::yellow("filtered")`
- Host up header → `Color::bold(Color::cyan("Kmap scan report for ..."))`
- Only applied to `LOG_NORMAL` (not XML, JSON, or machine-readable)

### Modernization in Files Touched
- `kmap.cc` option parsing: `nullptr`, C++ casts where touched
- `output.cc`: `nullptr`, remove C-style casts in edited sections

---

## Implementation Order

All three phases run in parallel via sub-agents:
- **Sub-agent 1** → Phase 1
- **Sub-agent 2** → Phase 2
- **Main agent** → Phase 3

Each agent works in an isolated git worktree on its own branch. After all three complete, branches are merged into `master`.

## Verification

Each phase must:
1. Compile cleanly with `make` (or `g++ -std=c++17` spot-check on key files)
2. Verify no `nmap` strings reintroduced
3. Phase 2: manual test `./kmap -oJ /tmp/out.json <target>` produces valid JSON
4. Phase 3: verify colors appear in TTY, absent when piped (`./kmap ... | cat`)
