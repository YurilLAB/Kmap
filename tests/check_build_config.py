#!/usr/bin/env python3
"""Check the reduced PCRE2 source/export contract, without building or scanning.

Optionally compare an existing archive's defined-symbol listing from
`dumpbin /linkermember:1` or `nm -g --defined-only` with the 8-bit export map.
This checks source/API consistency; it does not replace platform linker CI.
"""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap


def exported_symbols(text):
    public, private = text.split("global:", 1)[1].split("local:", 1)
    if not re.search(r"^\s*\*\s*;", private, re.M):
        raise ValueError("unlisted implementation/startup symbols must be local")
    return set(re.findall(r"^\s*(pcre2_[a-z0-9_]+)\s*;", public, re.M))


def check_map(text, expected):
    actual = exported_symbols(text)
    if actual != expected:
        raise ValueError(f"undefined exports={sorted(actual - expected)}; "
                         f"missing exports={sorted(expected - actual)}")


def definitions(source, annotation):
    # PCRE2 marks each public definition with this export annotation. Restrict
    # the match to the next definition so comments/internal calls cannot supply
    # an absent public function, as happened with removed JIT entry points.
    pattern = (annotation + r"(?:(?!" + annotation +
               r").)*?\b(pcre2_[a-z0-9_]+)\s*\(")
    return set(re.findall(pattern, source, re.S))


def check_vm_status(root):
    """Run the workflow's actual log wrapper, with inert success/failure children."""
    workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
    match = re.search(r"^          record\(\) \{\n.*?^          \}\n", workflow, re.M | re.S)
    if not match:
        raise ValueError("VM log wrapper missing")
    if os.name != "posix":
        print("VM command-status controls: not run (POSIX shell required; gated on Linux CI)")
        return
    helper = textwrap.dedent(match.group())
    with tempfile.TemporaryDirectory(prefix="kmap-build-contract-") as directory:
        for status in (0, 7):
            case = Path(directory) / str(status)
            case.mkdir()
            script = ("set -eu\nmkdir test-results\n" + helper +
                      "record fixture \"$1\" -c \"import sys; print('retained-output'); "
                      f"sys.exit({status})\"\n")
            result = subprocess.run(["sh", "-c", script, "build-contract", sys.executable],
                                    cwd=case, capture_output=True, timeout=10)
            if result.returncode != status:
                raise AssertionError(f"VM wrapper changed exit {status} to {result.returncode}")
            saved = (case / "test-results/fixture.log").read_text()
            if "retained-output" not in saved or b"retained-output" not in result.stdout:
                raise AssertionError("VM command log was not retained and echoed")
    print("VM command-status controls: success and failure preserved, both logs retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--symbols-file", type=Path)
    args = parser.parse_args()
    src = args.root / "libpcre" / "src"
    source = "\n".join(p.read_text(encoding="utf-8") for p in sorted(src.glob("*.c")))
    core = definitions(source, "PCRE2_EXP_DEFN")
    posix = definitions(source, "PCRE2POSIX_EXP_DEFN")
    if not core or not posix:
        raise ValueError("public source definitions could not be identified")
    for width in (8, 16, 32):
        expected = {name + "_" + str(width) for name in core}
        check_map((src / f"libpcre2-{width}.sym").read_text(), expected)
    check_map((src / "libpcre2-posix.sym").read_text(), posix)

    # Negative controls: a nonexistent export, a lost real API, and an
    # unversioned global must all be rejected by the same checker.
    reference = "V {\n global:\n pcre2_real;\n local:\n *;\n};\n"
    check_map(reference, {"pcre2_real"})
    for broken in (reference.replace(" pcre2_real;", " pcre2_real;\n pcre2_absent;"),
                   reference.replace(" pcre2_real;", ""),
                   reference.replace(" *;", " _init;")):
        try:
            check_map(broken, {"pcre2_real"})
        except ValueError:
            pass
        else:
            raise AssertionError("negative export-map control was accepted")

    if args.symbols_file:
        listing = args.symbols_file.read_text(encoding="utf-8", errors="replace")
        actual = set(re.findall(r"(?<![a-zA-Z0-9_])_?(pcre2_[a-z0-9_]+_8)(?![a-zA-Z0-9_])",
                                listing))
        expected = {name + "_8" for name in core}
        if actual != expected:
            raise ValueError(f"archive/source mismatch: absent={sorted(expected - actual)}, "
                             f"unexpected={sorted(actual - expected)}")
        print(f"compiled archive: {len(actual)} public 8-bit APIs match")
    check_vm_status(args.root)
    print(f"PCRE2 export contracts: {len(core)} APIs x 3 widths, {len(posix)} POSIX APIs; "
          "3 negative controls passed")


if __name__ == "__main__":
    main()
