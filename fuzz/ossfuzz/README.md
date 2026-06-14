# OSS-Fuzz / ClusterFuzzLite targets

libFuzzer entry points (`LLVMFuzzerTestOneInput`) for kmap's untrusted-input
parsers, runnable by OSS-Fuzz, [ClusterFuzzLite][cfl], or any libFuzzer/AFL++
engine. Each target is a single self-contained `.cc` that copies the shipping
parser **verbatim** (kept byte-identical to the source it mirrors), so no
kmap/sqlite linkage is needed and the build is trivial.

| Target | Mirrors | Surface |
|--------|---------|---------|
| `fuzz_dns.cc` | `asn_lookup.cc` `dns_skip_name` / `dns_extract_txt` | raw DNS responses incl. name-compression pointers |
| `fuzz_cidr.cc` | `fast_syn.cc` `parse_cidr` (+ `ip_to_u32`) | exclude-file CIDR/IP lines |
| `fuzz_jsonescape.cc` | `net_enrich.cc` `json_escape` | RFC 8259 escaping of arbitrary banner bytes |

## How it's built

- **OSS-Fuzz / ClusterFuzzLite:** clang builds each target with
  `-fsanitize=fuzzer,<address|undefined>` via [`.clusterfuzzlite/build.sh`](../../.clusterfuzzlite/build.sh)
  and [`Dockerfile`](../../.clusterfuzzlite/Dockerfile). The
  [`cflite_pr.yml`](../../.github/workflows/cflite_pr.yml) workflow fuzzes
  PR-changed code for a short budget on every pull request.
- **Local verification (no clang needed):** compile a target together with
  [`standalone_main.cc`](standalone_main.cc) under plain g++ — it supplies a
  libFuzzer-compatible `main` that drives the target with seedable pseudo-random
  inputs, or replays crash artifacts passed as file arguments:

  ```sh
  g++ -O1 -g -std=gnu++17 fuzz/ossfuzz/fuzz_dns.cc \
      fuzz/ossfuzz/standalone_main.cc -o /tmp/fdns
  /tmp/fdns 1 3000000           # seed=1, 3M iterations
  /tmp/fdns crash-artifact.bin  # replay a reported crash
  ```

  (Memory-safety detection comes from ASan in the clang build; the standalone
  run verifies the target compiles, links, and drives the parser correctly.)

## Enrolling in central OSS-Fuzz

The same sources support a `projects/kmap/` entry in
[google/oss-fuzz][ossfuzz]: a `project.yaml`, a `Dockerfile` that clones this
repo, and a `build.sh` that calls into `.clusterfuzzlite/build.sh`.

## Keeping targets in sync

Each target copies its parser verbatim from the source file named above. If you
change a parser, update the matching target (and the local harness in
`fuzz/`). The targets and the local harnesses are intentionally redundant —
local guard-page/UBSan-trap coverage on Windows, ASan/libFuzzer coverage here.

[cfl]: https://google.github.io/clusterfuzzlite/
[ossfuzz]: https://github.com/google/oss-fuzz
