#!/usr/bin/env python3
"""Drive the local server's EZ runner the same way the UI does and report.
usage: python test/ez-run.py <port> <evidence-dir> <out-json> [--require Tool,Tool,...]"""
import json, sys, time, urllib.request
port, evidence, outp = sys.argv[1], sys.argv[2], sys.argv[3]
req = sys.argv[sys.argv.index('--require') + 1].split(',') if '--require' in sys.argv else []
H = {'X-Sudo-Z': '1', 'Content-Type': 'application/json'}
def call(path, body=None):
    r = urllib.request.Request(f'http://localhost:{port}{path}', data=json.dumps(body).encode() if body is not None else None, headers=H)
    return json.load(urllib.request.urlopen(r, timeout=60))
caps = call('/api/caps'); print('caps:', json.dumps(caps))
job = call('/api/ez/run', {'path': evidence})
t0 = time.time()
while job['status'] != 'done' and time.time() - t0 < 3600:
    time.sleep(5); job = call(f"/api/job/{job['id']}")
    print(f"  {job['done']}/{job['total']} {job.get('current', '')}", flush=True)
json.dump(job, open(outp, 'w'), indent=1)
print('\n| Tool | Input | Result | CSV files | Error |\n|---|---|---|---|---|')
for r in job['results']:
    err = ' / '.join(l.strip() for l in (r.get('error') or '').strip().splitlines()[-3:])[:240]
    print(f"| {r['tool']} | {r.get('label', '')} | {'OK' if r['ok'] else 'SKIP' if r.get('skipped') else 'FAIL'} | {len(r.get('files', []))} | {err} |")
for r in job['results']:
    if not r['ok'] and not r.get('skipped'): print(f"\n--- {r['tool']} output (tail) ---\n{r.get('error', '')}")
print(f"\nrun folder: {job['dir']}")
failed = [t for t in req if not any(r['tool'] == t and r['ok'] for r in job['results'])]
if failed: print('REQUIRED TOOLS FAILED OR DID NOT RUN:', ', '.join(failed)); sys.exit(1)
