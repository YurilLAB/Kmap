#!/usr/bin/env python3
"""--yuril-export must fail loudly and keep the last good export when the new
one cannot be written (here: a zero file-size limit, so every flush fails).

POSIX only (uses RLIMIT_FSIZE). Offline: a -sL list scan of 127.0.0.1.
Run from any directory: python3 tests/yuril_export_contracts.py ./kmap --artifacts DIR
"""

import argparse
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys

DATA = "kmap-yuril-export.json"
META = "kmap-yuril-export.meta.json"


def run(binary, directory, limit_size=False):
    def no_space():
        import resource
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    return subprocess.run([binary, "-sL", "-n", "127.0.0.1", "--yuril-export", str(directory)],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                          preexec_fn=no_space if limit_size else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--artifacts", type=Path, default=Path("test-results/yuril-export"))
    args = parser.parse_args()
    if sys.platform == "win32":
        print("yuril export contracts: skipped (needs RLIMIT_FSIZE)")
        return 0
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary.resolve())

    good = run(binary, out)
    assert good.returncode == 0, good.stdout + good.stderr
    data, meta = (out / DATA).read_bytes(), (out / META).read_bytes()
    assert data and json.loads(meta)["sha256"] == hashlib.sha256(data).hexdigest(), \
        "first export is not self-consistent"

    failed = run(binary, out, limit_size=True)
    (out / "failed.log").write_text(failed.stdout + failed.stderr)
    assert failed.returncode != 0, "export write failure exited 0"
    assert "Yuril export written" not in failed.stdout, "failure reported as written"
    assert (out / DATA).read_bytes() == data and (out / META).read_bytes() == meta, \
        "failed export replaced the previous one"
    print(f"yuril export contracts: passed; artifacts: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
