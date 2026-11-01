#!/usr/bin/env python3
"""Small, offline actual-CLI graph/cohort fixtures and failure contracts."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
import traceback
from query_smoke import make_fixture
from runtime_smoke import Runner, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--artifacts', type=Path, default=Path('test-results/graph-contracts'))
    args = parser.parse_args()
    runner = Runner(args.artifacts)
    binary = args.binary.resolve()
    repo = Path(__file__).resolve().parent.parent
    sources = ['entity_graph.cc', 'entity_graph.h', 'net_db.cc', 'net_db.h', 'net_scan.cc',
               'kmap.cc', 'json_escape.h', 'store_output.h', 'tests/graph_contracts.py',
               'tests/query_smoke.py', 'tests/runtime_smoke.py']
    def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
    before = {n: sha(repo/n) for n in sources}
    binary_before = sha(binary)
    os.environ.pop('KMAP_ARGS', None)
    os.environ.update(KMAP_NO_ASN='1', KMAP_NO_DNS='1')
    data = runner.artifacts/'normal'
    ips = ['192.0.2.10', '203.0.113.20', '198.51.100.30', '203.0.113.40']
    make_fixture(data, [(ip, 443, 'https', '[]', 'offline graph') for ip in ips])
    cases = []
    def run(name, directory, flags, good=True):
        runner.run(name, [str(binary), '--datadir', str(repo), '--data-dir', str(directory), *flags],
                   timeout=20, expect_success=good)
        return (runner.artifacts/(name+'.stdout.log')).read_bytes()
    def case(name, check):
        try:
            check()
            cases.append({'name': name, 'status': 'passed'})
        except Exception:
            cases.append({'name': name, 'status': 'failed', 'error': traceback.format_exc()})
    run('initialize', data, ['--net-query', '--nq-count', '--nq-format', 'json'])
    def insert(directory, ip, value, kind='tls_san'):
        ipu = int(ipaddress.IPv4Address(ip))
        db = sqlite3.connect(directory/f'shard_{ipu >> 27:03d}.db')
        try:
            db.execute('INSERT OR REPLACE INTO fingerprints(ip_u32,kind,value,port,observed_at) '
                       'VALUES(?,?,CAST(? AS TEXT),443,200)',
                       (ipu, kind, value))
            db.commit()
        finally:
            db.close()
    for ip, values in zip(ips, [['a.test'], ['a.test', 'b.test'], ['b.test', 'c.test'], ['c.test']]):
        for value in values: insert(data, ip, value)

    def depths():
        for depth in range(4):
            doc = json.loads(run(f'depth-{depth}', data,
                ['--entity-graph', ips[0], '--eg-depth', str(depth), '--eg-format', 'json']))
            actual = sorted(n['label'] for n in doc['nodes'] if n['type'] == 'ip')
            require(actual == sorted(ips[:depth+1]), f'wrong depth {depth} IPs')
            require(doc['cohort_ips'] == depth and not doc['cohort_limit_reached'], 'wrong cohort count/limit')
            ids = {n['id'] for n in doc['nodes']}
            edges = [(e['from'], e['to'], e['label']) for e in doc['edges']]
            require(len(edges) == len(set(edges)), 'duplicate edges')
            require(all(a in ids and b in ids for a, b, _ in edges), 'dangling edges')
    case('depths-zero-through-three', depths)
    def cluster():
        doc = json.loads(run('cluster', data, ['--net-cluster', ips[0], '--nc-format', 'json']))
        require(doc['cohort'] == [{'ip': ips[1], 'shared': 1, 'matches': ['tls_san:a.test']}], 'wrong cohort')
        doc = json.loads(run('minimum-two', data, ['--net-cluster', ips[0], '--nc-min-shared', '2', '--nc-format', 'json']))
        require(doc['cohort'] == [], 'minimum shared ignored')
    case('cohort-and-minimum', cluster)
    def repeat_files():
        flags = ['--entity-graph', ips[0], '--eg-format', 'json']
        require(json.loads(run('repeat1', data, flags)) == json.loads(run('repeat2', data, flags)), 'unstable graph')
        for mode, fmt, output in [('entity-graph', '--eg-format', '--eg-output'), ('net-cluster', '--nc-format', '--nc-output')]:
            path = runner.artifacts/(mode+'.json')
            run(mode+'-file', data, ['--'+mode, ips[0], fmt, 'json', output, str(path)])
            json.loads(path.read_bytes())
    case('repeat-and-file-json', repeat_files)
    corrupt = runner.artifacts/'corrupt'
    shutil.copytree(data, corrupt)
    bad = corrupt/'shard_025.db'
    bad.write_bytes(b'inert corrupt peer shard\n')
    bad_hash = sha(bad)
    def corrupt_peer():
        for mode in ['entity-graph', 'net-cluster']:
            run('corrupt-'+mode, corrupt, ['--'+mode, ips[0]], good=False)
        require(sha(bad) == bad_hash, 'corrupt file changed')
    case('corrupt-peer-rejected', corrupt_peer)
    invalid = runner.artifacts/'invalid-utf8'
    shutil.copytree(data, invalid)
    for ip in ips[:2]: insert(invalid, ip, b'bad\xff.test', 'hostname')
    def utf8():
        doc = json.loads(run('invalid-utf8', invalid, ['--net-cluster', ips[0], '--nc-format', 'json']).decode('utf-8'))
        require(doc['cohort'][0]['shared'] == 2, 'malformed UTF-8 lost match')
        require('hostname:bad\ufffd.test' in doc['cohort'][0]['matches'], 'UTF-8 repair differs')
    case('malformed-utf8-json', utf8)
    def invalid_empty():
        run('bad-seed', data, ['--entity-graph', '192.0.2.10junk'], good=False)
        run('bad-depth', data, ['--entity-graph', ips[0], '--eg-depth', '4'], good=False)
        empty = runner.artifacts/'empty'
        empty.mkdir()
        for mode in ['entity-graph', 'net-cluster']:
            run('empty-'+mode, empty, ['--'+mode, ips[0]], good=False)
        require(list(empty.iterdir()) == [], 'empty lookup created database')
    case('invalid-and-empty-input', invalid_empty)
    def pipes():
        for mode in ['entity-graph', 'net-cluster']:
            readfd, writefd = os.pipe()
            os.close(readfd)
            command = [str(binary), '--datadir', str(repo), '--data-dir', str(data), '--'+mode, ips[0]]
            start = time.monotonic()
            record = {'name': 'pipe-'+mode, 'command': command, 'timeout_seconds': 20, 'status': 'failed'}
            runner.results.append(record)
            try:
                result = subprocess.run(command, stdout=writefd, stderr=subprocess.PIPE, timeout=20)
                record['returncode'] = result.returncode
            except subprocess.TimeoutExpired:
                record['timed_out'] = True
                raise
            finally:
                os.close(writefd)
                record['elapsed_seconds'] = time.monotonic()-start
            (runner.artifacts/('pipe-'+mode+'.stderr.log')).write_bytes(result.stderr)
            record['status'] = 'passed' if result.returncode != 0 else 'failed'
            # POSIX SIGPIPE is a failure result, not proof of graceful cleanup.
            require(result.returncode != 0, 'closed stdout reported success')
    case('closed-stdout-is-failure', pipes)
    after = {n: sha(repo/n) for n in sources}
    cases.append({'name': 'source-and-binary-stable', 'status': 'passed' if
                  before == after and binary_before == sha(binary) else 'failed'})
    runner.save(cases=cases, source_inputs_start=before, source_inputs_end=after,
                binary_sha256=binary_before, driver_sha256=sha(Path(__file__)))
    print(json.dumps(cases, indent=2))
    return 0 if all(c['status'] == 'passed' for c in cases) else 1


if __name__ == '__main__':
    raise SystemExit(main())
