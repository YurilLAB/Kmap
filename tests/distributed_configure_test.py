#!/usr/bin/env python3
"""Check actual configure rules without Autoconf, including timestamp controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path('test-results/distributed-configure'))
    args = parser.parse_args()
    root, out = args.root.resolve(), args.output.resolve()
    make = shutil.which('make')
    require(make, 'make is required')
    out.mkdir(parents=True, exist_ok=False)
    empty_path = out / 'empty-path'
    empty_path.mkdir()
    env = {**os.environ, 'PATH': str(empty_path), 'LC_ALL': 'C'}
    records = []
    try:
        for name, relative, macro_path in (
                ('kmap', Path('.'), 'm4/kmap_hardening.m4'),
                ('nping', Path('nping'), '../m4/kmap_hardening.m4'),
                ('ncat', Path('ncat'), '../m4/kmap_hardening.m4')):
            folder = out / name
            folder.mkdir()
            work = folder / relative
            work.mkdir(parents=True, exist_ok=True)
            macro = folder / 'm4/kmap_hardening.m4'
            macro.parent.mkdir()
            macro.write_text('newer checked-in macro fixture\n')
            configured = work / 'configure'
            configured.write_text('#!/bin/sh\nexit 0\n')
            source = work / 'configure.ac'
            source.write_text('older source fixture\n')
            stamp = time.time() - 10
            os.utime(source, (stamp, stamp))
            os.utime(configured, (stamp + 1, stamp + 1))
            os.utime(macro, (stamp + 2, stamp + 2))
            before = hashlib.sha256(configured.read_bytes()).hexdigest()
            lines = (root / relative / 'Makefile.in').read_text().splitlines()
            index = next(i for i, line in enumerate(lines)
                         if '/configure:' in line and not line.startswith('#'))
            rule = [lines[index]]
            for line in lines[index + 1:]:
                if not line.startswith('\t'):
                    break
                rule.append(line)
            require(any('autoconf' in line for line in rule[1:]),
                    name + ': regression must execute the production regeneration recipe')
            header = '.DEFAULT_GOAL := all\nsrcdir = .\nall: ./configure\n'
            (work / 'fixture.mk').write_text(header + '\n'.join(rule) + '\n')
            p = subprocess.run([make, '-f', 'fixture.mk'], cwd=work, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            (work / 'current.log').write_bytes(p.stdout)
            require(p.returncode == 0, name + ': distributed build tried regeneration without Autoconf')
            require(hashlib.sha256(configured.read_bytes()).hexdigest() == before,
                    name + ': configure was modified')
            # Reintroducing the removed macro prerequisite must hit the actual
            # regeneration recipe and fail because Autoconf is unavailable.
            broken = [rule[0] + ' ' + macro_path, *rule[1:]]
            (work / 'negative.mk').write_text(header + '\n'.join(broken) + '\n')
            negative = subprocess.run([make, '-f', 'negative.mk'], cwd=work, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            (work / 'negative.log').write_bytes(negative.stdout)
            require(negative.returncode != 0 and b'autoconf' in negative.stdout,
                    name + ': negative timestamp control failed to invoke unavailable Autoconf')
            records.append({'tool': name, 'status': 'passed', 'returncode': p.returncode,
                            'negative_returncode': negative.returncode})
            print('PASS distributed configure without Autoconf: ' + name)
    finally:
        (out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
