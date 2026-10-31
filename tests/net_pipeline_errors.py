#!/usr/bin/env python3
"""Offline CLI contracts for phase errors and findings accuracy.

No target arguments are supplied. Report-only never enriches or discovers.
Enrich-only cases contain no shards, one corrupt file, or a directory in
place of a shard, so no host worker can run. All database addresses are inert
documentation-range values.
"""
import argparse
from contextlib import closing
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time


SCHEMA = """CREATE TABLE hosts (
ip TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT DEFAULT 'tcp',
first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
service TEXT, version TEXT, cves TEXT, web_title TEXT,
web_server TEXT, web_headers TEXT, web_paths TEXT,
enriched INTEGER DEFAULT 0, PRIMARY KEY(ip,port));"""
ROWS = [('192.0.2.10', 12346, 'fixture-b', '2.0'),
        ('192.0.2.2', 12345, 'fixture-a', '1.0'),
        ('192.0.2.2', 12347, 'fixture-c', '3.0'),
        ('203.0.113.1', 12348, 'fixture-d', '4.0')]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(directory):
    directory.mkdir()
    grouped = {}
    for row in ROWS:
        grouped.setdefault(int(ipaddress.IPv4Address(row[0])) >> 27, []).append(row)
    for shard, rows in grouped.items():
        with closing(sqlite3.connect(directory / f'shard_{shard:03}.db')) as db:
            db.executescript(SCHEMA)
            db.executemany('INSERT INTO hosts(ip,port,service,version,cves,first_seen,last_seen,enriched) '
                           "VALUES(?,?,?,?,'[]',100,200,1)", rows)
            db.commit()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--artifacts', type=Path, default=Path('test-results/pipeline-errors'))
    parser.add_argument('--total-timeout', type=float, default=120)
    args = parser.parse_args()
    require(0 < args.total_timeout <= 300, 'total timeout must be in (0, 300] seconds')
    binary = args.binary.resolve()
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parents[1]
    deadline = time.monotonic() + args.total_timeout
    results, commands = [], []
    finished = False
    binding = {'binary_sha256': digest(binary), 'driver_sha256': digest(Path(__file__)),
               'checkout_source_sha256': {name: digest(source / name) for name in ('net_enrich.cc', 'net_scan.cc', 'net_report.cc', 'net_db.cc')},
               'source_binding_note': 'Checkout hashes are observations, not proof of binary build inputs; retain the build attestation separately.'}
    env = dict(os.environ, KMAP_NO_ASN='1', KMAP_NO_DNS='1', KMAP_RAWSYN='0',
               KMAP_ASYNC_ENRICH='0', LC_ALL='C')
    valid = out / 'valid-data'
    fixture(valid)
    corrupt = out / 'corrupt-data'
    corrupt.mkdir()
    bad = corrupt / 'shard_024.db'
    bad.write_bytes(b'Owned offline test: not a SQLite database.\n')
    original_bad_hash = digest(bad)
    empty = out / 'empty-data'
    empty.mkdir()
    directory_data = out / 'directory-shard-data'
    directory_shard = directory_data / 'shard_024.db'
    directory_shard.mkdir(parents=True)
    directory_sentinel = directory_shard / 'preserve.txt'
    directory_sentinel.write_bytes(b'Preserve this owned directory fixture.\n')
    directory_sentinel_hash = digest(directory_sentinel)

    def save():
        (out / 'results.json').write_text(json.dumps({
            'binding': binding, 'cases': results, 'commands': commands,
            'scope': 'Actual offline phase CLI; no discovery targets or eligible enrichment hosts.',
            'status': ('failed' if any(r['status'] == 'failed' for r in results) else 'passed') if finished else 'running'
        }, indent=2) + '\n', encoding='utf-8')

    def run(name, data, findings, phase='--report-only', expect_error=False):
        require(phase in ('--report-only', '--enrich-only'), 'unsafe test phase')
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'overall CLI test budget exhausted')
        command = [str(binary), '--unprivileged', '-n', '--datadir', str(source),
                   '--net-scan', phase, '--data-dir', str(data), '--findings-dir', str(findings)]
        record = {'name': name, 'command': command, 'timeout_seconds': min(15, remaining)}
        commands.append(record)
        started = time.monotonic()
        try:
            with (out / (name + '.stdout.log')).open('wb') as stdout, \
                 (out / (name + '.stderr.log')).open('wb') as stderr:
                completed = subprocess.run(command, cwd=out, env=env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, timeout=record['timeout_seconds'])
            record['returncode'] = completed.returncode
        finally:
            record['elapsed_seconds'] = round(time.monotonic() - started, 4)
            save()
        text = (out / (name + '.stdout.log')).read_text(encoding='utf-8', errors='replace')
        error = (out / (name + '.stderr.log')).read_text(encoding='utf-8', errors='replace')
        require(completed.returncode in ((1, 2) if expect_error else (0,)),
                f'{name}: expected {"error" if expect_error else "success"}, got {completed.returncode}')
        if expect_error:
            require(any(word in (text + error).lower() for word in ('error', 'cannot', 'failed')),
                    name + ': error status lacks a diagnostic')
            require('report generation complete --' not in text, name + ': false report completion')
            require('NET-SCAN COMPLETE' not in text, name + ': false pipeline completion')
        return text

    def case(name, check):
        try:
            detail = check()
            results.append({'name': name, 'status': 'passed', 'detail': detail})
        except Exception as error:
            results.append({'name': name, 'status': 'failed', 'error': str(error)})
            print(name + ': ' + str(error), file=sys.stderr)
        save()

    case('corrupt-enrich', lambda: run('corrupt-enrich', corrupt, out / 'unused', '--enrich-only', True))
    case('corrupt-report', lambda: run('corrupt-report', corrupt, out / 'corrupt-findings', expect_error=True))
    case('empty-enrich', lambda: run('empty-enrich', empty, out / 'unused', '--enrich-only'))
    case('empty-report', lambda: run('empty-report', empty, out / 'empty-findings'))

    def check_directory_shard(name, phase):
        text = run(name, directory_data, out / (name + '-findings'), phase, True)
        require('enriching ' not in text.lower(), name + ': unexpected host worker path')
        require(directory_shard.is_dir() and digest(directory_sentinel) == directory_sentinel_hash,
                name + ': directory shard fixture changed')
        return {'error_propagated': True, 'no_host_workers': True, 'fixture_preserved': True}

    case('directory-shard-enrich', lambda: check_directory_shard('directory-shard-enrich', '--enrich-only'))
    case('directory-shard-report', lambda: check_directory_shard('directory-shard-report', '--report-only'))

    blocker = out / 'blocked-directory'
    blocker.write_bytes(b'Preserve this owned regular file.\n')
    blocker_hash = digest(blocker)
    case('output-directory-is-file', lambda: run('output-directory-is-file', valid, blocker, expect_error=True))
    blocked_file_dir = out / 'blocked-file-findings'
    blocked_file_dir.mkdir()
    (blocked_file_dir / 'findings_0000001-0000003.txt').mkdir()
    case('output-file-is-directory', lambda: run('output-file-is-directory', valid, blocked_file_dir, expect_error=True))

    def check_report():
        reports = out / 'valid-findings'
        run('valid-report', valid, reports)
        files = list(reports.glob('findings_*.txt'))
        require([p.name for p in files] == ['findings_0000001-0000003.txt'], 'wrong report file count/range')
        text = files[0].read_text(encoding='utf-8')
        expected_ips = sorted({r[0] for r in ROWS}, key=ipaddress.IPv4Address)
        require(re.findall(r'^  TARGET: (\S+)$', text, re.M) == expected_ips, 'report IPs missing, duplicated or out of numeric order')
        actual = []
        current_ip = None
        for line in text.splitlines():
            if line.startswith('  TARGET: '):
                current_ip = line.split()[-1]
            match = re.fullmatch(r'\s+(\d+)/tcp\s+open\s+(\S+)\s+(\S+)\s*', line)
            if match:
                actual.append((current_ip, int(match[1]), match[2], match[3]))
        require(sorted(actual) == sorted(ROWS), 'report identities/service/version differ from fixture')
        require(re.search(r'Total ports:\s+4\b', text) is not None, 'wrong report port count')
        run('report-reopen', valid, reports)
        repeated = files[0].read_text(encoding='utf-8')
        normalize = lambda s: '\n'.join(line for line in s.splitlines() if not line.startswith('  Generated:'))
        require(normalize(text) == normalize(repeated), 'repeated report changed stored result content')
        records = []
        for path in valid.glob('shard_*.db'):
            with closing(sqlite3.connect(path)) as db:
                require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'SQLite integrity failed')
                records.extend(db.execute('SELECT ip,port,service,version,first_seen,last_seen,enriched FROM hosts'))
        require(sorted(records) == sorted((*r, 100, 200, 1) for r in ROWS), 'report/reopen changed fixture records')
        return {'hosts': 3, 'ports': 4, 'repeat_parity': True, 'integrity': 'ok'}

    case('report-parity-and-reopen', check_report)
    if os.name == 'posix':
        def check_full():
            require(Path('/dev/full').exists(), 'required POSIX full-output fixture unavailable')
            destination = out / 'full-device-findings'
            destination.mkdir()
            (destination / 'findings_0000001-0000003.txt').symlink_to('/dev/full')
            return run('buffered-output-error', valid, destination, expect_error=True)
        case('buffered-output-error', check_full)
    else:
        results.append({'name': 'buffered-output-error', 'status': 'unsupported',
                        'reason': 'POSIX /dev/full fixture; Windows flush/close fault injection not exercised by this CLI driver.'})

    case('fixture-and-binary-preservation', lambda: require(
        digest(bad) == original_bad_hash and digest(blocker) == blocker_hash and
        directory_shard.is_dir() and digest(directory_sentinel) == directory_sentinel_hash and
        digest(binary) == binding['binary_sha256'], 'input fixture or tested binary unexpectedly changed'))
    failed = sum(r['status'] == 'failed' for r in results)
    passed = sum(r['status'] == 'passed' for r in results)
    unsupported = sum(r['status'] == 'unsupported' for r in results)
    finished = True
    save()
    print(f'pipeline error/report checks: {passed} passed, {failed} failed, {unsupported} unsupported; {out}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
