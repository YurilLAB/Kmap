#!/usr/bin/env python3
"""Actual watchlist collection/report/storage checks on two owned loopback ports.

The worker uses connect discovery and inert plaintext HTTP fixtures. ASN/DNS,
async enrichment and raw scanning are disabled; no active fingerprint output
is requested by the watchlist caller. No public targets or authentication.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import threading
import time
import traceback


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Endpoint:
    """Reserve one port for the complete run, accepting only in open phases."""
    def __init__(self, marker):
        self.marker = marker
        self.title = marker
        self.server = 'SimpleHTTP/0.6'
        self.socket = socket.socket()
        if os.name != 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('127.0.0.1', 0))
        self.port = self.socket.getsockname()[1]
        self.thread = None
        self.stop = threading.Event()
        self.accepted = 0
        self.errors = []
        self.records = []

    def start(self):
        self.socket.listen(8)
        self.socket.settimeout(.1)
        self.stop.clear()
        def serve():
            while not self.stop.is_set():
                try:
                    conn, address = self.socket.accept()
                except socket.timeout:
                    continue
                except OSError as error:
                    if not self.stop.is_set(): self.errors.append(repr(error))
                    break
                with conn:
                    self.accepted += 1
                    if self.accepted > 100:
                        self.errors.append('fixture connection budget exceeded')
                        break
                    conn.settimeout(.2)
                    body = ('<html><title>' + self.title + '</title></html>').encode()
                    response = (b'HTTP/1.0 200 OK\r\nServer: ' + self.server.encode() + b'\r\n'
                                b'Content-Type: text/html\r\nContent-Length: ' +
                                str(len(body)).encode() + b'\r\n\r\n' + body)
                    self.records.append({'time': time.time(), 'peer': list(address),
                                         'marker': self.marker, 'response_sha256': hashlib.sha256(response).hexdigest()})
                    with contextlib.suppress(ConnectionResetError, BrokenPipeError, socket.timeout):
                        conn.sendall(response)
        self.thread = threading.Thread(target=serve)
        self.thread.start()

    def close_listener(self):
        self.stop.set()
        if self.thread:
            self.thread.join(2)
            require(not self.thread.is_alive(), 'fixture accept thread did not join')
            self.thread = None
        self.socket.close()
        self.socket = socket.socket()
        if os.name != 'nt':
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Keep the port reserved but non-listening so another process cannot
        # turn our closed-port oracle into an unrelated open endpoint.
        self.socket.bind(('127.0.0.1', self.port))

    def finish(self):
        self.stop.set()
        if self.thread:
            self.thread.join(2)
            require(not self.thread.is_alive(), 'fixture thread did not stop')
        self.socket.close()
        require(not self.errors, 'fixture errors: ' + repr(self.errors))


def database_snapshot(path):
    with contextlib.closing(sqlite3.connect(path)) as db:
        require(db.execute('PRAGMA integrity_check').fetchone() == ('ok',), 'database integrity check')
        db.row_factory = sqlite3.Row
        rows = [dict(row) for row in db.execute(
            'SELECT ip,port,first_seen,last_seen,service,version,web_title,enriched,scan_count FROM hosts ORDER BY port')]
        meta = dict(db.execute('SELECT key,value FROM scan_meta'))
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        membership = None
        if 'watchlist_open' in tables:
            membership = [list(row) for row in db.execute('SELECT ip,port FROM watchlist_open ORDER BY ip,port')]
        baseline = None
        if 'watchlist_baseline' in tables:
            baseline = [dict(row) for row in db.execute('SELECT * FROM watchlist_baseline ORDER BY ip,port')]
        return {'rows': rows, 'meta': meta, 'membership': membership, 'completed_attributes': baseline}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--rapid', action='store_true', help='Run membership transitions without second-boundary waits; deliberate metadata change still waits for enrichment eligibility')
    args = parser.parse_args()
    binary, source, out = args.binary.resolve(), args.source.resolve(), args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    data = out / 'data'
    data.mkdir()
    findings = out / 'findings'
    targets = out / 'targets.txt'
    targets.write_text('127.0.0.1\n', encoding='ascii')
    started = time.monotonic()
    deadline = started + 90
    document = {'binary': str(binary), 'binary_sha256_before': digest(binary),
                'driver_sha256_before': digest(__file__), 'source_commit': subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
                'scope': 'Actual watchlist TCP collection -> SQLite -> current/diff reports; two owned plaintext loopback endpoints only',
                'rapid_membership_runs': args.rapid,
                'attribute_change_waits_next_second': True,
                'cases': [], 'assertions': []}
    env_overrides = {'KMAP_NO_ASN': '1', 'KMAP_NO_DNS': '1', 'KMAP_RAWSYN': '0',
                     'KMAP_ASYNC_ENRICH': '0', 'KMAP_WATCHLIST_CONCURRENCY': '1',
                     'KMAP_WATCHLIST_ENRICH_CONCURRENCY': '1', 'KMAP_HOST_PORT_PARALLELISM': '1',
                     'KMAP_PROBE_TIMEOUT_MS': '100', 'KMAP_ENRICH_CONNECT_TIMEOUT_MS': '100',
                     'KMAP_HOST_ENRICH_BUDGET_MS': '1000', 'LC_ALL': 'C'}
    document['environment_overrides'] = env_overrides
    env = {**os.environ, **env_overrides}

    def save():
        document['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (out / 'results.json').write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')

    def check(name, actual, expected):
        document['assertions'].append({'name': name, 'actual': actual, 'expected': expected, 'passed': actual == expected})

    endpoints = []
    try:
        a, b = Endpoint('watchlist-fixture-A'), Endpoint('watchlist-fixture-B')
        endpoints = [a, b]
        a.start(); b.start()
        document['fixture_ports'] = {'A': a.port, 'B': b.port}
        # A local client readiness exchange verifies the independently owned
        # services before Kmap starts. Connections never leave loopback.
        for endpoint in endpoints:
            with socket.create_connection(('127.0.0.1', endpoint.port), timeout=2) as conn:
                require(endpoint.marker.encode() in conn.recv(4096), 'fixture readiness marker missing')

        # A malformed CIDR host used to become 0.0.0.0 before expansion.
        # Restrict this runtime regression to /32; broad malformed ranges are
        # covered by the offline production-helper unit, without any probes.
        invalid_targets = out / 'invalid-targets.txt'
        invalid_targets.write_text('not-an-ip/32\n127.0.0.999/32\n', encoding='ascii')
        invalid_data = out / 'invalid-target-data'
        invalid_data.mkdir()
        invalid_command = [str(binary), '--unprivileged', '-n', '--datadir', str(source),
                           '--watchlist', str(invalid_targets), '--data-dir', str(invalid_data),
                           '--findings-dir', str(out / 'invalid-target-findings'),
                           '-p', f'{a.port},{b.port}']
        invalid_record = {'name': '00-invalid-cidr-hosts', 'command': invalid_command,
                          'expected_success': False}
        document['cases'].append(invalid_record)
        invalid_result = subprocess.run(invalid_command, cwd=out, env=env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=10)
        (out / 'invalid-targets.stdout.log').write_bytes(invalid_result.stdout)
        (out / 'invalid-targets.stderr.log').write_bytes(invalid_result.stderr)
        invalid_record['returncode'] = invalid_result.returncode
        check('invalid CIDR hosts rejected', invalid_result.returncode, 1)
        check('invalid CIDR hosts create no scan database', (invalid_data / 'watchlist.db').exists(), False)
        invalid_log = (invalid_data / 'kmap.log').read_text(encoding='utf-8')
        check('invalid CIDR hosts logged explicitly', invalid_log.count('invalid IPv4 address'), 2)
        check('invalid CIDR hosts leave no valid targets', 'no valid targets' in invalid_log, True)
        save()

        def run(name, destination=findings, success=True):
            # Distinct seconds exercise legacy timestamp behavior deterministically.
            if not args.rapid:
                now = time.time()
                time.sleep(max(0, int(now) + 1.03 - now))
            folder = out / name
            folder.mkdir()
            command = [str(binary), '--unprivileged', '-n', '--datadir', str(source),
                       '--watchlist', str(targets), '--data-dir', str(data),
                       '--findings-dir', str(destination), '-p', f'{a.port},{b.port}']
            record = {'name': name, 'command': command, 'expected_success': success}
            document['cases'].append(record)
            launch = time.monotonic()
            remaining = min(15, deadline - launch)
            require(remaining > 0, 'overall watchlist test budget exhausted')
            with (folder / 'stdout.log').open('wb') as stdout, (folder / 'stderr.log').open('wb') as stderr:
                result = subprocess.run(command, cwd=folder, env=env, stdin=subprocess.DEVNULL,
                                        stdout=stdout, stderr=stderr, timeout=remaining)
            record.update(returncode=result.returncode, elapsed_seconds=round(time.monotonic() - launch, 3))
            check(name + ': exit', result.returncode == 0, success)
            record['database'] = database_snapshot(data / 'watchlist.db')
            reports = {}
            if destination.is_dir():
                for path in sorted((destination / 'watchlist').glob('*.txt')):
                    if not path.is_file():
                        continue
                    text = path.read_text(encoding='utf-8')
                    (folder / path.name).write_text(text, encoding='utf-8')
                    reports[path.name.split('_', 1)[0]] = text
            record['report_sha256'] = {p.name: digest(p) for p in folder.glob('*.txt')}
            record['reports'] = reports
            save()
            return record

        first = run('01-both-open')
        b.close_listener()
        second = run('02-b-closed')
        third = run('03-b-stays-closed')
        expected_keys = sorted([['127.0.0.1', a.port], ['127.0.0.1', b.port]], key=lambda x: x[1])
        for record in (first, second, third):
            check(record['name'] + ': history retained', [[r['ip'], r['port']] for r in record['database']['rows']], expected_keys)
            check(record['name'] + ': original first_seen retained', [r['first_seen'] for r in record['database']['rows']],
                  [r['first_seen'] for r in first['database']['rows']])
        check('initial collected titles', {r['port']: r['web_title'] for r in first['database']['rows']},
              {a.port: a.marker, b.port: b.marker})
        for record, expected_open in ((first, [a.port, b.port]), (second, [a.port]), (third, [a.port])):
            full = record['reports'].get('full', '')
            observed = sorted(map(int, re.findall(r'^  (\d+)/tcp\b', full, re.M)))
            check(record['name'] + ': full report matches actual listeners', observed, sorted(expected_open))
        key_b = '127.0.0.1:' + str(b.port)
        check('second run reports closure once', len(re.findall(r'\[CLOSED\]\s+' + re.escape(key_b) + r'\b', second['reports'].get('diff', ''))), 1)
        check('third run does not repeat closure', len(re.findall(r'\[CLOSED\]\s+' + re.escape(key_b) + r'\b', third['reports'].get('diff', ''))), 0)
        # Failure to publish reports must not advance the comparison snapshot.
        invalid = out / 'findings-is-file'
        invalid.write_text('owned sentinel', encoding='ascii')
        before_failure = third['database']
        if args.rapid:
            # Enrichment eligibility uses last_seen > enriched_at in seconds.
            # Rapid membership checks remain above; this deliberate metadata
            # change needs a fresh eligible collection, not an assumed refresh.
            now = time.time()
            time.sleep(max(0, int(now) + 1.03 - now))
        b.start()
        a.server = 'SimpleHTTP/0.7'
        a.title = a.marker + '-updated'
        failed = run('04-report-path-failure', invalid, success=False)
        check('failed report retains metadata', failed['database']['meta'], before_failure['meta'])
        check('failed report retains membership', failed['database']['membership'], before_failure['membership'])
        check('failed report retains completed attributes', failed['database']['completed_attributes'], before_failure['completed_attributes'])
        check('invalid destination sentinel preserved', invalid.read_text(encoding='ascii'), 'owned sentinel')
        a_latest = next(r for r in failed['database']['rows'] if r['port'] == a.port)
        check('failed report retains latest collected version', a_latest['version'], a.server)
        check('failed report retains latest collected title', a_latest['web_title'], a.title)
        # The diff can succeed while the full report fails. That must not
        # acknowledge the newly reopened port as a completed comparison.
        partial_findings = out / 'full-report-is-directory'
        partial_watchlist = partial_findings / 'watchlist'
        partial_watchlist.mkdir(parents=True)
        full_name = next((findings / 'watchlist').glob('full_*.txt')).name
        (partial_watchlist / full_name).mkdir()
        partial = run('05-full-report-failure', partial_findings, success=False)
        check('partial report retains metadata', partial['database']['meta'], before_failure['meta'])
        check('partial report retains membership', partial['database']['membership'], before_failure['membership'])
        check('partial report retains completed attributes', partial['database']['completed_attributes'], before_failure['completed_attributes'])
        recovered = run('06-report-recovery')
        check('recovery does not repeat prior closure', '[CLOSED]' in recovered['reports'].get('diff', ''), False)
        check('recovery reports reopened B', len(re.findall(r'\[NEW PORT\]\s+' + re.escape(key_b) + r'\b', recovered['reports'].get('diff', ''))), 1)
        key_a = '127.0.0.1:' + str(a.port)
        check('recovery reports changed A once', len(re.findall(r'\[CHANGED\]\s+' + re.escape(key_a) + r'\b', recovered['reports'].get('diff', ''))), 1)
        check('recovery compares with completed version', 'SimpleHTTP/0.6 -> SimpleHTTP/0.7' in recovered['reports'].get('diff', ''), True)
        stable = run('07-changed-remains-stable')
        check('completed attribute change not repeated', '[CHANGED]' in stable['reports'].get('diff', ''), False)
        check('completed reopening not repeated', '[NEW PORT]' in stable['reports'].get('diff', ''), False)
        a.close_listener(); b.close_listener()
        empty = run('08-all-closed')
        empty_again = run('09-still-all-closed')
        check('all-closed report contains no current ports', re.findall(r'^  (\d+)/tcp\b', empty['reports'].get('full', ''), re.M), [])
        check('all-closed reports both closures', empty['reports'].get('diff', '').count('[CLOSED]'), 2)
        check('empty completed set does not repeat closures', '[CLOSED]' in empty_again['reports'].get('diff', ''), False)
        check('empty completed set retains historical rows', len(empty_again['database']['rows']), 2)
        document['fixture_connections'] = {e.marker: e.accepted for e in endpoints}
        require(all(e.accepted > 1 for e in endpoints), 'scanner did not reach both fixtures')
    except Exception:
        document['error'] = traceback.format_exc()
    finally:
        cleanup = []
        for endpoint in endpoints:
            try:
                endpoint.finish()
            except Exception:
                cleanup.append(traceback.format_exc())
        document['cleanup_errors'] = cleanup
        for endpoint in endpoints:
            (out / (endpoint.marker + '.jsonl')).write_text(
                ''.join(json.dumps(row) + '\n' for row in endpoint.records), encoding='utf-8')
        document['binary_sha256_after'] = digest(binary)
        document['driver_sha256_after'] = digest(__file__)
        check('binary unchanged during validation', document['binary_sha256_after'], document['binary_sha256_before'])
        check('driver unchanged during validation', document['driver_sha256_after'], document['driver_sha256_before'])
        document['status'] = 'passed' if not document.get('error') and not cleanup and all(a['passed'] for a in document['assertions']) else 'failed'
        save()
    print(json.dumps({'status': document['status'], 'elapsed_seconds': document['elapsed_seconds'],
                      'checks': len(document['assertions']),
                      'failed': [a['name'] for a in document['assertions'] if not a['passed']],
                      'error': document.get('error')}, indent=2))
    return 0 if document['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
