#!/usr/bin/env python3
"""Bounded offline libFuzzer JSON serializer run with replayable evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600 or not 1 <= args.seed <= 2147483647:
        parser.error("seconds must be 1..600; seed must be 1..2147483647")
    binary = args.binary.resolve(strict=True)
    output = args.output.resolve()
    # Never overwrite prior evidence or silently reuse a changing corpus.
    output.mkdir(parents=True, exist_ok=False)
    corpus = output / "corpus"
    artifacts = output / "artifacts"
    corpus.mkdir()
    artifacts.mkdir()
    seeds = Path(__file__).resolve().parents[1] / "fuzz/corpus/jsonescape"
    seed_hashes = {}
    for path in sorted(seeds.iterdir()):
        if path.is_file():
            shutil.copyfile(path, corpus / path.name)
            seed_hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not seed_hashes:
        raise RuntimeError("JSON fuzz corpus is empty")
    command = [str(binary), str(corpus), f"-seed={args.seed}",
               f"-max_total_time={args.seconds}", "-timeout=5",
               "-rss_limit_mb=512", "-max_len=4096", "-print_final_stats=1",
               f"-artifact_prefix={artifacts}{os.sep}"]
    result = {"command": command, "seed": args.seed, "budget_seconds": args.seconds,
              "max_input_bytes": 4096, "initial_corpus_sha256": seed_hashes,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    started = time.monotonic()
    with (output / "fuzzer.log").open("wb") as log:
        try:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                       timeout=args.seconds + 30, check=False)
            result["returncode"] = completed.returncode
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            result["returncode"] = 124
        except OSError as exc:
            result["error"] = str(exc)
            result["returncode"] = 1
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    log_text = (output / "fuzzer.log").read_text(errors="replace")
    result["stats"] = dict(re.findall(r"stat::(\w+):\s*(\d+)", log_text))
    result["final_corpus_files"] = len(list(corpus.iterdir()))
    result["artifacts"] = [p.name for p in sorted(artifacts.iterdir())]
    if result["returncode"] == 0 and int(result["stats"].get("number_of_executed_units", 0)) == 0:
        result["error"] = "No libFuzzer execution statistics were produced"
        result["returncode"] = 1
    (output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result["returncode"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
