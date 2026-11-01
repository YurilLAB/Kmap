"""Actual watchlist reports over seeded persisted CVE states and owned loopback."""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import traceback

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary',type=Path)
parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[1])
parser.add_argument('--artifacts',type=Path,required=True)
args=parser.parse_args()
repo=args.repo.resolve();binary=args.binary.resolve();out=args.artifacts.resolve()
out.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('watchlist_contracts',repo/'tests/watchlist_contracts.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'status':'running','binary_sha256':sha(binary),'driver_sha256':sha(Path(__file__)),
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo).decode().strip(),
        'scope':'Actual watchlist discovery and report publication; persisted CVE states are seeded and enrichment made ineligible after bootstrap. No CVE lookup equivalence claim.',
        'budget_seconds':90,'cases':[]}
start=time.monotonic();endpoint=None
env={**os.environ,'KMAP_NO_ASN':'1','KMAP_NO_DNS':'1','KMAP_RAWSYN':'0','KMAP_ASYNC_ENRICH':'0',
     'KMAP_WATCHLIST_CONCURRENCY':'1','KMAP_WATCHLIST_ENRICH_CONCURRENCY':'1','KMAP_HOST_PORT_PARALLELISM':'1',
     'KMAP_PROBE_TIMEOUT_MS':'100','KMAP_ENRICH_CONNECT_TIMEOUT_MS':'100','KMAP_HOST_ENRICH_BUDGET_MS':'1000','LC_ALL':'C'}
env.pop('KMAP_ARGS',None)
def save():
    result['elapsed_seconds']=time.monotonic()-start
    (out/'results.json').write_text(json.dumps(result,indent=2)+'\n')
def run(name,data,findings,expected_code):
    folder=out/name;folder.mkdir()
    command=[str(binary),'--unprivileged','-n','--datadir',str(repo),'--watchlist',str(out/'targets.txt'),
             '--data-dir',str(data),'--findings-dir',str(findings),'-p',str(endpoint.port)]
    with (folder/'stdout.log').open('wb') as stdout,(folder/'stderr.log').open('wb') as stderr:
        completed=subprocess.run(command,cwd=out,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
                                 timeout=min(15,max(.1,90-(time.monotonic()-start))))
    assert completed.returncode==expected_code,(name,completed.returncode)
    stdout_text=(folder/'stdout.log').read_text(encoding='utf-8',errors='replace')
    if expected_code:
        diagnostic=(folder/'stderr.log').read_text(encoding='utf-8',errors='replace')
        expected_prefix=str(findings)+'/watchlist/full_'
        assert 'cannot create full report '+expected_prefix in diagnostic, (name,'wrong failure path')
        assert 'Diff report: '+str(findings)+'/watchlist/diff_' in stdout_text, (name,'diff was not published')
    return folder,command

def report_text(folder,findings):
    # Read this invocation's announced file, even when a previous invocation
    # wrote a report on the other side of midnight.
    stdout=(folder/'stdout.log').read_text(encoding='utf-8',errors='replace')
    names=re.findall(r'^\s*Full report: (.+)$',stdout,re.MULTILINE)
    assert len(names)==1, ('expected one published full report',names)
    path=Path(names[0].strip()).resolve()
    assert path.parent==(findings/'watchlist').resolve()
    assert re.fullmatch(r'full_\d{4}-\d{2}-\d{2}\.txt',path.name)
    return path.read_text(encoding='utf-8')
try:
    endpoint=helper.Endpoint('cve-report-fixture');endpoint.start()
    with socket.create_connection(('127.0.0.1',endpoint.port),timeout=2) as connection:
        assert b'cve-report-fixture' in connection.recv(4096)
    (out/'targets.txt').write_text('127.0.0.1\n')
    data=out/'bootstrap-data';data.mkdir()
    findings=out/'bootstrap-findings'
    run('bootstrap',data,findings,0)
    template=out/'template.db';shutil.copyfile(data/'watchlist.db',template)
    a='[{"id":"CVE-2099-0001"}]';b='[{"id":"CVE-2099-0002"}]'
    scenarios=[('changed-retry',a,b,b,1),('reverted-retry',a,a,b,0),
               ('removed-retry',a,'[]','[]',1),('added-retry','[]',b,'[]',1),
               ('empty-equivalent','', '[]', a,0),('null-current-equivalent','[]',None,a,0)]
    for name,completed,current,prior,expected in scenarios:
        data=out/(name+'-data');data.mkdir();shutil.copyfile(template,data/'watchlist.db')
        def db_values():
            with contextlib.closing(sqlite3.connect(data/'watchlist.db')) as db:
                return {'current':db.execute('SELECT cves,prev_cves FROM hosts').fetchall(),
                        'completed':db.execute('SELECT cves FROM watchlist_baseline').fetchall()}
        with contextlib.closing(sqlite3.connect(data/'watchlist.db')) as db:
            db.execute('UPDATE watchlist_baseline SET cves=?',(completed,))
            db.execute('UPDATE hosts SET cves=?,prev_cves=?,enriched=1,enriched_at=4102444800',(current,prior))
            db.commit()
        # Let the actual diff open successfully, then fail actual full-report
        # creation. No completed baseline is allowed to advance on failure.
        bad=out/(name+'-bad-findings')
        day=datetime.date.today()
        for offset in (-1,0,1):
            full_name='full_'+(day+datetime.timedelta(days=offset)).isoformat()+'.txt'
            (bad/'watchlist'/full_name).mkdir(parents=True)
        before=db_values();run(name+'-failed-publication',data,bad,1);assert db_values()['completed']==before['completed']
        good=out/(name+'-findings');folder,command=run(name+'-retry',data,good,0)
        full=report_text(folder,good)
        (folder/'full.txt').write_text(full)
        actual=full.count('CVE list changed since prior scan')
        row={'name':name,'command':command,'expected_notices':expected,'actual_notices':actual,
             'before':before,'after':db_values(),'status':'passed' if actual==expected else 'failed'}
        assert row['after']['completed']==[(current or '',)]
        result['cases'].append(row);save()
        stable_folder,_=run(name+'-stable',data,good,0)
        stable=report_text(stable_folder,good)
        (stable_folder/'full.txt').write_text(stable)
        result['cases'].append({'name':name+'-stable','expected_notices':0,
            'actual_notices':stable.count('CVE list changed since prior scan'),
            'status':'passed' if 'CVE list changed since prior scan' not in stable else 'failed'})
    result['status']='passed' if all(c['status']=='passed' for c in result['cases']) else 'failed'
except BaseException:
    result.update(status='failed',error=traceback.format_exc())
finally:
    if endpoint:
        endpoint.finish();result['fixture_accepted']=endpoint.accepted;result['fixture_errors']=endpoint.errors
    result['driver_sha256_after']=sha(Path(__file__))
    if result['driver_sha256_after']!=result['driver_sha256']:result.update(status='failed',binding_error='driver changed')
    result['binary_sha256_after']=sha(binary)
    if result['binary_sha256_after']!=result['binary_sha256']:result.update(status='failed',binding_error='binary changed')
    save()
print(json.dumps({'status':result['status'],'cases':len(result['cases']),'results':str(out/'results.json')}))
sys.exit(0 if result['status']=='passed' else 1)
