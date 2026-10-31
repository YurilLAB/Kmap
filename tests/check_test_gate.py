#!/usr/bin/env python3
"""Prove the actual check-kmap shell recipe propagates early/late failures."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shell", default="sh")
    parser.add_argument("--makefile", type=Path, default=Path(__file__).resolve().parents[1] / "Makefile.in")
    args = parser.parse_args()
    lines = args.makefile.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith("check-kmap:"))
    recipe = lines[index + 1].strip().lstrip("@")
    assert "$^" in recipe and "$$test" in recipe, "check-kmap recipe changed; update regression driver"
    command = recipe.replace("$^", "first second").replace("$$", "$")
    with tempfile.TemporaryDirectory(prefix="kmap-test-gate-") as tmp:
        directory = Path(tmp)
        for first, second in ((23, 0), (0, 19), (0, 0)):
            for name, code in (("first", first), ("second", second)):
                path = directory / name
                path.write_text(f"#!/bin/sh\nexit {code}\n", encoding="utf-8", newline="\n")
                path.chmod(0o700)
            run = subprocess.run([args.shell, "-c", command], cwd=directory, timeout=10)
            expected = first or second
            if run.returncode != expected:
                raise RuntimeError(f"check-kmap hides a failure: tests={first, second}, "
                                   f"exit={run.returncode}, expected={expected}")
    print("check-kmap gate: early failure, late failure, success propagated")


if __name__ == "__main__":
    main()
