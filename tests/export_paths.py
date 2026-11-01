#!/usr/bin/env python3
"""Offline CLI checks that catalog exports preserve the store they read.

All paths and databases are disposable fixtures. No links are created and no
network operation is requested. Exact, relative and Windows case aliases are
covered; hard-link/symlink identity requires separate platform evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time

from query_performance import SCHEMA


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--artifacts', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    repo = Path(__file__).resolve().parents[1]
    out = args.artifacts.resolve()
    out.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + 120
    binding = {'binary_sha256': digest(binary), 'driver_sha256': digest(Path(__file__))}
    cases = []
    finished = False
    env = {k: v for k, v in os.environ.items() if k != 'KMAP_ARGS'}
    env.update(KMAP_NO_ASN='1', KMAP_NO_DNS='1')

    def save():
        (out / 'results.json').write_text(json.dumps({
            'binding': binding, 'cases': cases,
            'scope': 'Offline exact/relative/case path aliases; link creation not exercised.',
            'status': ('failed' if any(c['status'] == 'failed' for c in cases) else 'passed') if finished else 'running'
        }, indent=2) + '\n', encoding='utf-8')

    kinds = ['exact', 'relative', 'excluded-shard', 'topology', 'wal', 'shm',
             'journal', 'count', 'inside-store', 'existing-output', 'text-count',
             'absent-shard', 'absent-wal', 'absent-shm', 'absent-journal', 'absent-topology',
             'absent-relative-shard', 'absent-relative-wal',
             'search-alias', 'search-distinct', 'topo-alias', 'topo-distinct',
             'cluster-alias', 'entity-alias']
    if os.name == 'nt':
        kinds += ['case-alias', 'absent-dot-shard', 'absent-space-wal', 'absent-stream-shard']
    for kind in kinds:
        record = {'case': kind}
        try:
            data = out / kind
            data.mkdir()
            shard = data / 'shard_024.db'
            with sqlite3.connect(shard) as db:
                db.executescript(SCHEMA)
                db.execute("INSERT INTO hosts(ip,port,first_seen,last_seen,service,enriched) "
                           "VALUES('192.0.2.1',443,100,200,'https',1)")
            # Close the connection before measuring exact preservation.
            db.close()
            target = shard
            protected = [shard]
            options = []
            refuse = kind not in ('inside-store', 'existing-output', 'text-count', 'search-distinct', 'topo-distinct')
            absent = kind.startswith('absent-')
            child_cwd = out
            data_arg = str(data)
            if kind.startswith(('search-', 'topo-', 'cluster-', 'entity-')):
                warm = subprocess.run([str(binary), '--datadir', str(repo), '--net-query',
                                       '--data-dir', str(data), '--nq-count', '--nq-format', 'json'],
                                      cwd=out, env=env, capture_output=True, timeout=10)
                (data / 'prepare.stdout.log').write_bytes(warm.stdout)
                (data / 'prepare.stderr.log').write_bytes(warm.stderr)
                assert warm.returncode == 0 and json.loads(warm.stdout) == {'count': 1}
                if kind in ('cluster-alias', 'entity-alias'):
                    with sqlite3.connect(shard) as db:
                        db.execute("INSERT INTO fingerprints(ip_u32,kind,value,port,observed_at) VALUES(3221225985,'tls_san','fixture.test',443,200)")
                    db.close()
                if kind.startswith('topo-'):
                    topology = data / 'topo.db'
                    shutil.copy2(shard, topology)
                    with sqlite3.connect(topology) as db:
                        db.execute("INSERT INTO topo_nodes(ip_u32,path_count,last_seen,role) VALUES(3221225985,1,200,'target')")
                    db.close()
                    protected.append(topology)
                    target = topology
                if not refuse: target = data / 'export.json'
            elif absent:
                suffix = kind[len('absent-'):]
                relative = suffix.startswith('relative-')
                if relative: suffix = suffix[len('relative-'):]
                stream = suffix.startswith('stream-')
                if stream: suffix = suffix[len('stream-'):]
                trailing = '.' if suffix.startswith('dot-') else ' ' if suffix.startswith('space-') else ''
                if trailing: suffix = suffix.split('-', 1)[1]
                target = data / ('shard_025.db' if suffix == 'shard' else
                                 'topo.db' if suffix == 'topology' else shard.name + '-' + suffix)
                assert not target.exists()
                target_arg = target.name if relative else str(target) + trailing
                if stream: target_arg += '::$DATA'
                if relative: child_cwd, data_arg = data, '.'
            elif kind == 'relative':
                target = data / '..' / kind / shard.name
            elif kind == 'case-alias':
                target = data / shard.name.upper()
            elif kind == 'excluded-shard':
                target = data / 'shard_025.db'
                shutil.copy2(shard, target)
                protected.append(target)
                options += ['--nq-ip-range', '192.0.2.0/24']
            elif kind in ('topology', 'wal', 'shm', 'journal'):
                target = data / ('topo.db' if kind == 'topology' else shard.name + '-' + kind)
                target.write_bytes(b'Owned store-file preservation sentinel.\n')
                protected.append(target)
            elif kind == 'count':
                options.append('--nq-count')
            elif not refuse:
                target = data / 'export.json'
                if kind == 'existing-output':
                    target.write_bytes(b'Old output must be completely replaced.\n' * 100)
                if kind == 'text-count':
                    options += ['--nq-count', '--nq-format', 'text']
            before = {p.name: digest(p) for p in protected}
            command = [str(binary), '--datadir', str(repo), '--net-query',
                       '--data-dir', data_arg, '--nq-format', 'json',
                       '--nq-output', target_arg if absent else str(target), *options]
            if kind.startswith('search-'):
                command = [str(binary), '--datadir', str(repo), '--data-dir', data_arg,
                           '--search', 'https', '--search-format', 'json', '--search-output', str(target)]
            elif kind.startswith('topo-'):
                command = [str(binary), '--datadir', str(repo), '--data-dir', data_arg,
                           '--topo-export', str(target), '--topo-format', 'json']
            elif kind in ('cluster-alias', 'entity-alias'):
                mode, output = ('--net-cluster', '--nc-output') if kind == 'cluster-alias' else ('--entity-graph', '--eg-output')
                command = [str(binary), '--datadir', str(repo), '--data-dir', data_arg,
                           mode, '192.0.2.1', output, str(target)]
            record['command'] = command
            remaining = min(10, deadline - time.monotonic())
            assert remaining > 0, 'suite budget exhausted'
            completed = subprocess.run(command, cwd=child_cwd, env=env, stdin=subprocess.DEVNULL,
                                       capture_output=True, timeout=remaining)
            (data / 'stdout.log').write_bytes(completed.stdout)
            (data / 'stderr.log').write_bytes(completed.stderr)
            record['returncode'] = completed.returncode
            record['protected_before'] = before
            record['protected_after'] = {p.name: digest(p) for p in protected}
            if refuse:
                assert completed.returncode != 0, 'alias export falsely succeeded'
                assert record['protected_after'] == before, 'protected file changed'
                assert b'aliases a store file' in completed.stderr, 'missing alias diagnostic'
                if absent:
                    assert not target.exists(), 'refused export created a store file'
            else:
                assert completed.returncode == 0, 'distinct output failed'
                if kind == 'text-count':
                    assert target.read_text().strip() == '1', 'wrong text count'
                elif kind == 'topo-distinct':
                    graph = json.loads(target.read_text(encoding='utf-8'))
                    assert [r['ip'] for r in graph['nodes']] == ['192.0.2.1'] and graph['edges'] == []
                else:
                    rows = json.loads(target.read_text(encoding='utf-8'))
                    assert [(r['ip'], r['port']) for r in rows] == [('192.0.2.1', 443)]
                # Successful legacy-schema migration may change bytes, never data.
            with sqlite3.connect(shard) as db:
                assert db.execute('SELECT ip,port,service,first_seen,last_seen FROM hosts').fetchall() == [
                    ('192.0.2.1', 443, 'https', 100, 200)], 'stored record changed'
                assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            db.close()
            record['status'] = 'passed'
        except Exception as error:
            record.update(status='failed', error=str(error))
        cases.append(record)
        save()
    binding_end = {'binary_sha256': digest(binary), 'driver_sha256': digest(Path(__file__))}
    unchanged = binding == binding_end
    binding['end'] = binding_end
    cases.append({'case': 'binary-and-driver-preserved', 'status': 'passed' if unchanged else 'failed'})
    finished = True
    save()
    print(json.dumps({'cases': len(cases), 'failed': sum(c['status'] == 'failed' for c in cases)}, indent=2))
    return 1 if any(c['status'] == 'failed' for c in cases) else 0


if __name__ == '__main__':
    raise SystemExit(main())
