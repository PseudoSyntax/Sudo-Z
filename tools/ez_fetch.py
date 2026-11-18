#!/usr/bin/env python3
"""Fetch Eric Zimmerman's .NET 10 tool builds without PowerShell.

Mirrors Get-ZimmermanTools.ps1: read https://tools.ericzimmermanstools.com,
take every https://...zip link that contains /net/ (the .NET 10 builds),
skip kape / All*.zip, download and extract into <dest>/net/<Tool>/.
Used by `sudo-z setup ez` on Linux/macOS. Standard library only.
"""
import io, re, sys, urllib.request, zipfile
from pathlib import Path

INDEX = 'https://tools.ericzimmermanstools.com'
UA = {'User-Agent': 'sudo-z-setup'}

def get(url, timeout=120):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()

def main():
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else 'ez')
    page = get(INDEX).decode('utf-8', 'replace')
    urls = sorted(set(re.findall(r'(?i)\bhttps://[-A-Z0-9+&@#/%?=~_|$!:,.;]*[A-Z0-9+&@#/%=~_|$]\.zip', page)))
    urls = [u for u in urls if '/net/' in u and not re.search(r'/(kape|All|All_\d+)\.zip$', u, re.I)]
    if not urls:
        sys.exit('no .NET builds found on ' + INDEX)
    net = dest / 'net'
    net.mkdir(parents=True, exist_ok=True)
    ok = 0
    for u in urls:
        name = u.rsplit('/', 1)[-1]
        try:
            data = get(u, 600)
            target = net / name[:-4]
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for m in z.infolist():
                    p = (target / m.filename).resolve()
                    if not str(p).startswith(str(target.resolve())):
                        continue  # zip-slip guard
                    if m.is_dir():
                        p.mkdir(parents=True, exist_ok=True)
                    else:
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_bytes(z.read(m))
            ok += 1
            print(f'  ok  {name}')
        except Exception as e:
            print(f'  ERR {name}: {e}')
    print(f'[sudo-z] {ok}/{len(urls)} EZ tool packages extracted to {net}')
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
