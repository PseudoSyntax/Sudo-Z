#!/usr/bin/env python3
"""Check that every plugin group the local runner uses exists in the installed Volatility 3.
usage: python test/vol-plugins.py <path-to-vol> [server.py]"""
import ast, re, subprocess, sys
vol = sys.argv[1]
srv = sys.argv[2] if len(sys.argv) > 2 else 'tools/server.py'
groups = ast.literal_eval(re.search(r'VOL_PLUGINS = (\[.*?\n\])', open(srv).read(), re.S).group(1))
out = subprocess.run([vol, '-h'], capture_output=True, text=True).stdout
names = set(re.findall(r'^\s+((?:windows|linux|mac)\.[A-Za-z0-9_.]+)', out, re.M))
ver = re.search(r'Framework ([\d.]+)', out)
print(f'Volatility {ver.group(1) if ver else "?"}: {len(names)} plugins')
bad = 0
for alts in groups:
    hit = next((a for a in alts if any(n == a or n.startswith(a + '.') for n in names)), None)
    print(f'  {"ok " if hit else "MISSING"} {hit or " / ".join(alts)}')
    bad += hit is None
sys.exit(1 if bad else 0)
