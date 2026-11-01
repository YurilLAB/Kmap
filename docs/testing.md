# Reproducible local testing

Use a disposable checkout and keep generated databases and test results separate
from collected scan data. The commands below exercise local fixtures; the runtime
smoke test creates its own HTTP service bound to `127.0.0.1` and explicitly uses
unprivileged TCP connect mode with DNS disabled.

## Build and unit tests

On Linux, install the compiler/build dependencies described in the README, then:

```sh
./configure
make -j2
python3 tests/check_test_gate.py
make check-kmap
python3 tests/runtime_smoke.py ./kmap --artifacts test-results/runtime
python3 tests/http_metadata_smoke.py ./kmap --artifacts test-results/http-metadata
python3 tests/query_smoke.py ./kmap --artifacts test-results/query
python3 tests/query_filters.py ./kmap --artifacts test-results/query-filters
```

Configure detects stack protection separately for C and C++, preferring
`-fstack-protector-strong` with a `-fstack-protector` fallback. On ELF targets it
also tests full RELRO with both compiler drivers. Unsupported or warning-only
options are omitted. Defaults precede explicit `CFLAGS`, `CXXFLAGS` and
`LDFLAGS`, so user overrides retain precedence; `--disable-hardening` omits these
automatic stack/RELRO defaults. Existing platform PIE/NX defaults and the
Makefile's FORTIFY definition continue to apply.

The configure regression builds tiny offline C/C++ fixtures and checks their
ELF metadata, flag fallback, unsupported-option rejection and user overrides.
It requires Autoconf, make and readelf:

```sh
python3 tests/configure_hardening_test.py
python3 tests/subtool_ssp_test.py
python3 tests/distributed_configure_test.py
```

Nping and Ncat independently probe their own compiler driver for the stack
runtime link option. Their configured Makefiles retain that option for shared
archives built by Kmap, including libnetutil and Lua, without changing the
helpers' compile flags. The subtool regression executes their actual link
recipes against an archive requiring a separate runtime and verifies that
removing the driver option fails at the linker.

Normal builds use the checked-in configure scripts and do not require Autoconf.
After editing `m4/kmap_hardening.m4`, maintainers must explicitly regenerate all
three scripts with Autoconf and commit them together with the macro:

```sh
autoconf
(cd nping && autoconf)
(cd ncat && autoconf)
```

The distributed-configure regression checks the actual Makefile rules with
the macro newer than the generated scripts and no Autoconf on `PATH`.

`make check-kmap` builds the application and its libraries first and stops when
any test fails. It includes storage migration rollback, missing latency batches,
64-bit topology counters and strict graph JSON. It is a smaller, reviewed suite
than the inherited `make check`.

The critical-state regressions also exercise the actual checkpoint, work-ownership,
worker-joining and persistence-ordering helpers. They pause a claimed job before
publication, inject thread-launch/worker failures, reject checkpoint write and
replacement stages, and verify that failed commits cannot advance progress.
Storage tests use real SQLite locks, read-only files, interrupted writes and
page limits. A 100-cycle test checks statements, repeated open/query/export/close,
unfinished-transaction rollback and reopen behavior. These tests use inert jobs
and generated files; they do not establish whole-scanner cancellation latency,
cross-database atomicity or disk power-loss durability.

`make check-kmap` also runs `tests/checkpoint_recovery.py` against the built
checkpoint unit executable. Six children exit abruptly with the expected code
73 during partial write, flush, close and replacement stages, including a
first-ever checkpoint. The parent checks the surviving main/temporary files
and launches a fresh process to verify every recovered field. Each child has
a 10-second timeout and the suite a 90-second budget. Logs and fixtures remain
under a unique `test-results/checkpoint-recovery/` directory, including failures
and visible snapshot copies of checkpoint dotfiles for CI artifact upload.
This is process-crash recovery testing, not power-loss or disk-cache testing.
The sanitizer manifest runs the same mandatory parent driver with its
instrumented checkpoint unit executable. To run it separately:

```sh
python3 tests/checkpoint_recovery.py ./tests/checkpoint_persistence_test \
  --artifacts test-results/checkpoint-recovery-manual
```

For the native Windows build, see [windows-build.md](windows-build.md). The two
Python smoke scripts accept `mswin32/Release/kmap.exe` as their binary argument.
Run `python tests/windows_build_test.py` to test setup failure propagation with
inert local tools. Python 3.10+ is required for these test drivers.

The runtime driver checks XML and JSON against the same fixture, including an
open HTTP port, a reserved non-listening port, repeated scans, malformed CLI
input, and cleanup. POSIX also checks interruption after a real local connection;
Windows reports that interruption case as skipped. The query driver uses inert
documentation-range addresses stored in SQLite; it never scans those addresses.
The HTTP metadata driver serves header-like lines in a local response body and
checks that web recon ignores them for server, security, cookie and redirect
metadata while retaining real headers and the page title.

## Query accuracy and local performance

`query_filters.py` validates stored CVE identifiers, structured numeric metadata,
JSON formatting variants, malformed input and argument bounds against the actual
CLI. It is a mandatory CI step. All fixtures are offline SQLite records.

For descriptive performance measurements, use a fresh artifact directory:

```sh
python3 tests/query_performance.py prepare ./kmap --artifacts test-results/query-perf
python3 tests/query_performance.py contracts ./kmap --artifacts test-results/query-perf
python3 tests/query_performance.py benchmark ./kmap --artifacts test-results/query-perf
```

The driver checks result parity before accepting timings for deterministic
1,000/10,000/50,000-row fixtures. It records warmups, repeated wall/CPU timings,
and owned-child resource measurements where supported. Compare saved baseline
and candidate runs with the same driver, fixture parameters and machine under
quiet conditions. Raw records are retained; timing is not a CI threshold and
does not measure network scanning throughput. Different platforms, disk caches
and concurrent workloads can change these results.

`export_paths.py` checks that query, search, graph and topology exports refuse
store-file destinations. It covers existing and absent database/SQLite sidecar
paths, relative names and Windows case, trailing-dot/space and stream aliases.
Exports to distinct files inside the store remain valid.
These tests create no filesystem links. Do not move or replace store paths
concurrently with an export.

`graph_read_test.cc` checks SQLite read failures and graph depths against an
independent distance oracle for 100 small seeded graphs (seeds 1 and 1337).
`graph_contracts.py` exercises the actual offline CLI, including corrupt shards,
Unicode, empty stores, repeated output and closed output pipes. A nonzero pipe
exit is failure propagation, not evidence of graceful cancellation.

## Sanitizer harnesses

```sh
python3 tests/run_sanitizer_harnesses.py --validate-only
python3 tests/run_sanitizer_harnesses.py --output test-results/sanitizers
```

The executable manifest must match every `fuzz/*.cc` file. Each build/run gets a
fresh directory and temporary directory, so fixed checkpoint/database names
cannot overwrite user data or another run. Nonzero exits, timeouts, missing
tools, and incomplete plans fail the runner. Logs, commands, timings, fixtures,
compiler versions and incremental `results.json` are retained.

This Linux runner instruments project code and bundled SQLite with ASan/UBSan.
It preserves SQLite's `SQLITE_THREADSAFE=0` and `SQLITE_ENABLE_FTS5` production
defines. Passing these tests does not prove thread safety: some old harnesses
copy models/parsers instead of linking production functions. The manifest labels
that distinction. In particular, copied protocol/query models do not validate
the application's socket lifecycle or its CLI output.

## Coverage-guided JSON fuzzing

The JSON target includes the actual shared serializer and uses nlohmann's strict
parser plus repair/round-trip invariants as an independent oracle. Its committed
corpus includes ordinary text, Unicode, controls, a one-byte malformed UTF-8
input, a surrogate sequence and a truncated multibyte sequence.

```sh
mkdir -p test-results
clang++ -O1 -g -std=c++17 -fsanitize=fuzzer,address,undefined \
  -fno-sanitize-recover=all -fno-omit-frame-pointer \
  fuzz/ossfuzz/fuzz_jsonescape.cc -o test-results/fuzz_jsonescape
python3 tests/run_offline_fuzz.py --binary test-results/fuzz_jsonescape \
  --output test-results/json-seed1 --seconds 30 --seed 1
python3 tests/run_offline_fuzz.py --binary test-results/fuzz_jsonescape \
  --output test-results/json-seed1337 --seconds 30 --seed 1337
```

Use a new output directory per run. Limits are explicit: 4 KiB inputs, 512 MiB
RSS, 5 seconds per input, and a wall timeout beyond the requested fuzz budget.
Retain the generated corpus and any failure artifact. To replay one artifact:

```sh
test-results/fuzz_jsonescape path/to/crash-artifact
```

On a supported MSVC developer prompt, build the same target with separate
`/fsanitize=address /fsanitize=fuzzer` switches, `/std:c++17 /EHsc /O1 /Zi`.
That is Windows ASan coverage; it does **not** establish UBSan or leak-sanitizer
coverage. Sources: [LLVM libFuzzer options](https://llvm.org/docs/LibFuzzer.html#options),
[Clang ASan](https://clang.llvm.org/docs/AddressSanitizer.html), and
[Microsoft sanitizer flags](https://learn.microsoft.com/en-us/cpp/build/reference/fsanitize).

## CI interpretation

The multiplatform job selects its named C/C++ compiler. Unit/runtime and static
analysis jobs preserve diagnostics; tool invocation failures fail their gates.
The sanitizer job uses the same manifest runner as local testing, and the JSON
libFuzzer job saves corpus, artifacts and actual execution statistics.

ClusterFuzzLite retains its own crash/corpus artifacts. It has no configured
coverage storage here, so its code-change mode must not be described as proof
that only changed production functions were fuzzed. See the
[official integration documentation](https://google.github.io/clusterfuzzlite/running-clusterfuzzlite/github-actions/).

A local green run covers only the recorded platform, inputs and configuration.
Hosted CI, other operating systems, production-size data, live external services,
and inherited tests outside these entry points require separate validation.
