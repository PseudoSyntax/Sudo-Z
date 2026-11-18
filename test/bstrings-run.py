#!/usr/bin/env python3
"""Run the real bstrings.exe through the Sudo-Z server and compare with the in-browser scanner format.
usage: python test/bstrings-run.py <port> <folder>"""
import json, re, sys, time, urllib.request
port, root = sys.argv[1], sys.argv[2]
H = {'X-Sudo-Z': '1', 'Content-Type': 'application/json'}
def call(path, body=None):
    req = urllib.request.Request(f'http://localhost:{port}{path}', data=json.dumps(body).encode() if body is not None else None, headers=H, method='POST' if body is not None else 'GET')
    with urllib.request.urlopen(req, timeout=60) as r: return r.read()
job = json.loads(call('/api/bstrings/run', {'path': root, 'lr': 'ipv4', 'ro': True, 'min': 3, 'mask': r'\.(evtx|txt|pf)$'}))
for _ in range(600):
    j = json.loads(call(f"/api/job/{job['id']}"))
    if j['status'] != 'running': break
    time.sleep(2)
hits = sum(r['hits'] for r in j['results'])
print(f"bstrings.exe: status {j['status']}, {len(j['results'])} files, {hits} hits {j.get('error', '')}")
bad = [r for r in j['results'] if not r['ok']]
if bad: print('errors:', bad[:3])
first = next((r for r in j['results'] if r['file']), None)
if first:
    text = call(f"/api/job/{job['id']}/file/{first['file']}").decode('utf-8', 'replace').splitlines()
    print('sample:', text[:3])
    ok = all(re.match(r'^.*\t~?0x[0-9A-F]+ \([AU]\)$', l) for l in text if l)
    print('line format matches the console parser:', ok)
    if not ok: sys.exit(1)
sys.exit(0 if j['status'] == 'done' and hits > 0 and not bad else 1)
