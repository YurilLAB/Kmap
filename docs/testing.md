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
python3 tests/query_smoke.py ./kmap --artifacts test-results/query
```

`make check-kmap` builds the application and its libraries first and stops when
any test fails. It includes storage migration rollback, missing latency batches,
64-bit topology counters and strict graph JSON. It is a smaller, reviewed suite
than the inherited `make check`.

For the native Windows build, see [windows-build.md](windows-build.md). The two
Python smoke scripts accept `mswin32/Release/kmap.exe` as their binary argument.
Run `python tests/windows_build_test.py` to test setup failure propagation with
inert local tools. Python 3.10+ is required for these test drivers.

The runtime driver checks XML and JSON against the same fixture, including an
open HTTP port, a reserved non-listening port, repeated scans, malformed CLI
input, and cleanup. POSIX also checks interruption after a real local connection;
Windows reports that interruption case as skipped. The query driver uses inert
documentation-range addresses stored in SQLite; it never scans those addresses.

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
