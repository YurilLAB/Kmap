#!/usr/bin/env python3
"""Check ClusterFuzzLite build outputs with inert compiler fixtures.

These tests exercise the real build script and ZIP creation. The compiler stub
only creates marker files; actual sanitizer builds run in the fuzzing jobs.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"fuzz_dns", "fuzz_cidr", "fuzz_jsonescape", "fuzz_proto",
           "fuzz_hassh", "fuzz_banner", "fuzz_stored_json"}
ARCHIVES = {"fuzz_jsonescape_seed_corpus.zip": "jsonescape",
            "fuzz_stored_json_seed_corpus.zip": "stored-json"}
COMPILER = """#!/usr/bin/env python3
import os
from pathlib import Path
import sys
output = Path(sys.argv[sys.argv.index('-o') + 1])
if output.name == os.environ.get('KMAP_FIXTURE_FAIL_TARGET'):
    raise SystemExit(47)
output.write_text('inert compiler fixture: ' + output.name + '\\n')
"""


def check_archive(output, archive_name, seeds):
    expected = {path.name: path.read_bytes() for path in seeds.iterdir()
                if path.is_file()}
    with zipfile.ZipFile(output / archive_name) as archive:
        names = archive.namelist()
        assert len(names) == len(set(names)), "duplicate archive entries"
        assert set(names) == set(expected), "missing, stale or nested seed entries"
        for name, contents in expected.items():
            assert archive.read(name) == contents, f"seed bytes changed: {name}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--script", type=Path, default=ROOT / ".clusterfuzzlite/build.sh")
    parser.add_argument("--artifacts", type=Path,
                        default=Path("test-results/clusterfuzzlite-build"))
    args = parser.parse_args()
    script = args.script.resolve(strict=True)
    output_root = args.artifacts.resolve()
    output_root.mkdir(parents=True, exist_ok=False)
    compiler = output_root / "fixture compiler.py"
    compiler.write_text(COMPILER)
    compiler.chmod(0o755)
    results = []

    def run(name, *, fail_target="", missing_corpus="", rebuild=False):
        work = output_root / name
        work.mkdir()
        seeds = {archive: work / "fuzz/corpus" / corpus for archive, corpus in ARCHIVES.items()}
        for archive, corpus in ARCHIVES.items():
            if missing_corpus != corpus:
                shutil.copytree(ROOT / "fuzz/corpus" / corpus, seeds[archive])
        output = work / "output with spaces"
        output.mkdir()
        env = {**os.environ, "CXX": str(compiler), "CXXFLAGS": "-O1 -g",
               "LIB_FUZZING_ENGINE": "-fsanitize=fuzzer", "OUT": str(output),
               "KMAP_FIXTURE_FAIL_TARGET": fail_target}

        def invoke(label):
            command = [str(script)]
            completed = subprocess.run(command, cwd=work, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=30, check=False)
            (work / (label + ".log")).write_bytes(completed.stdout)
            return completed.returncode

        code = invoke("build")
        if fail_target:
            assert code == 47, f"compiler failure was lost: exit {code}"
            assert not any((output / archive).exists() for archive in ARCHIVES), \
                "failed build published a seed archive"
        elif missing_corpus:
            assert code != 0, "missing mandatory JSON corpus did not fail the build"
        else:
            assert code == 0, f"build failed: exit {code}"
            assert {path.name for path in output.iterdir()} == TARGETS | set(ARCHIVES), \
                "fuzzer binary or JSON seed archive missing"
            for archive in ARCHIVES:
                check_archive(output, archive, seeds[archive])
            if rebuild:
                # Reusing OUT must not retain seeds removed from the checkout.
                for directory in seeds.values():
                    removed = next(path for path in sorted(directory.iterdir()) if path.is_file())
                    removed.unlink()
                    (directory / "new-binary-seed").write_bytes(b"\x00\xff\xed\xa0\x80")
                assert invoke("rebuild") == 0, "rebuild failed"
                for archive in ARCHIVES:
                    check_archive(output, archive, seeds[archive])
        return {"case": name, "status": "passed", "returncode": code}

    cases = [("committed-seed-bytes", {}),
             ("rebuild-removes-stale-seeds", {"rebuild": True}),
             ("compiler-error", {"fail_target": "fuzz_jsonescape"}),
             ("stored-json-compiler-error", {"fail_target": "fuzz_stored_json"}),
             ("missing-corpus", {"missing_corpus": "jsonescape"}),
             ("missing-stored-json-corpus", {"missing_corpus": "stored-json"})]
    for name, options in cases:
        try:
            results.append(run(name, **options))
        except (AssertionError, OSError, subprocess.TimeoutExpired,
                zipfile.BadZipFile, KeyError) as error:
            results.append({"case": name, "status": "failed", "error": str(error)})
        (output_root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    return 0 if all(result["status"] == "passed" for result in results) else 1


if __name__ == "__main__":
    sys.exit(main())
