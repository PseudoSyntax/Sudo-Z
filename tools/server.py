#!/usr/bin/env python3
"""Sudo-Z local companion server (home install only).

Serves the console on http://localhost and adds what a browser cannot do:
  * Volatility 3 on memory images (by path, so multi-GB images never pass through the browser)
  * the original Eric Zimmerman tools on a folder (KAPE / Velociraptor output), if installed

Security: binds 127.0.0.1 only, rejects requests whose Host header is not
localhost, and requires an X-Sudo-Z header on API calls (a custom header
cannot be sent cross-origin without a CORS preflight, which is never allowed),
so other websites open in your browser cannot drive it.

Standard library only. Usage: python3 tools/server.py [port] [--no-browser]
"""
import json, mimetypes, os, platform, re, shutil, subprocess, sys, threading, time, uuid, webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, unquote

APP = Path(__file__).resolve().parent.parent          # .../app
HOME = APP.parent                                      # install dir (holds venv/, ez/, runs/)
RUNS = HOME / 'runs'
IS_WIN = os.name == 'nt'
JOBS = {}
LOCK = threading.Lock()

# Volatility 3 plugins run for an IOC sweep. New 2.2x names first, legacy names as fallback.
VOL_PLUGINS = [
    ['windows.info'], ['windows.pslist'], ['windows.psscan'], ['windows.pstree'], ['windows.cmdline'],
    ['windows.netscan'], ['windows.malware.malfind', 'windows.malfind'], ['windows.malware.psxview', 'windows.psxview'],
    ['windows.malware.ldrmodules', 'windows.ldrmodules'], ['windows.malware.hollowprocesses', 'windows.hollowprocesses'],
    ['windows.malware.processghosting', 'windows.processghosting'], ['windows.malware.suspicious_threads', 'windows.suspicious_threads'],
    ['windows.svcscan'], ['windows.dlllist'], ['windows.cmdscan'], ['windows.consoles'], ['windows.malware.drivermodule', 'windows.drivermodule'],
    ['windows.registry.userassist'],
]

def version():
    try: return (HOME / 'version.txt').read_text().strip()[:12]
    except OSError: return 'dev'

# ------------------------------------------------------------------ capability detection
def vol_cmd():
    cands = []
    venv = HOME / 'venv' / ('Scripts' if IS_WIN else 'bin')
    for n in (['vol.exe', 'vol'] if IS_WIN else ['vol']):
        if (venv / n).exists(): cands.append([str(venv / n)])
    w = shutil.which('vol') or shutil.which('vol3')
    if w: cands.append([w])
    try:
        import importlib.util
        if importlib.util.find_spec('volatility3'):
            cands.append([sys.executable, '-c', 'import sys; from volatility3.cli import main; sys.argv[0]="vol"; main()'])
    except Exception: pass
    for c in cands:
        try:
            out = subprocess.run(c + ['-h'], capture_output=True, text=True, timeout=60)
            m = re.search(r'Volatility 3 Framework ([\d.]+)', out.stdout + out.stderr)
            if out.returncode == 0 or m: return c, (m.group(1) if m else 'unknown')
        except Exception: continue
    return None, None

# EZ tools that refuse to run off Windows (verified on Linux CI runners)
WINDOWS_ONLY = {
    'SrumECmd': 'Windows-only: needs the Windows ESE libraries. Sudo-Z parses SRUM itself on any OS.',
    'SumECmd': 'Windows-only: needs the Windows ESE libraries. Sudo-Z reads SUM with its own ESE parser.',
}
EZ_TOOLS = ['EvtxECmd', 'PECmd', 'LECmd', 'JLECmd', 'RECmd', 'AmcacheParser', 'AppCompatCacheParser', 'MFTECmd', 'RBCmd', 'SBECmd', 'SrumECmd', 'SumECmd', 'SQLECmd', 'WxTCmd', 'RecentFileCacheParser', 'bstrings']

def ez_tools():
    roots = [HOME / 'ez', Path(os.environ.get('SUDOZ_EZ_DIR', '')) if os.environ.get('SUDOZ_EZ_DIR') else None, Path('C:/Tools/ZimmermanTools') if IS_WIN else None]
    found = {}
    for root in [r for r in roots if r and r.exists()]:
        for t in EZ_TOOLS:
            if t in found: continue
            for p in root.rglob(t + ('.exe' if IS_WIN else '.dll')):
                found[t] = str(p); break
            if t not in found and not IS_WIN:
                for p in root.rglob(t + '.exe'):
                    found[t] = str(p.with_suffix('.dll')) if p.with_suffix('.dll').exists() else str(p)  # .exe only = Windows-only build
                    break
    return found

def dotnet_path():
    p = HOME / 'dotnet' / ('dotnet.exe' if IS_WIN else 'dotnet')
    return str(p) if p.exists() else shutil.which('dotnet')

def tool_env():
    env = dict(os.environ)
    private = HOME / 'dotnet'
    if private.exists():
        env['DOTNET_ROOT'] = str(private)  # lets framework-dependent .exe builds find the private runtime
        env['PATH'] = str(private) + os.pathsep + env.get('PATH', '')
    return env

def ez_cmd(path):
    if path.lower().endswith('.exe'):
        return [path] if IS_WIN else None
    d = dotnet_path()
    return [d, path] if d else None

CAPS = {}
def detect_caps():
    vc, vv = vol_cmd()
    CAPS.clear()
    CAPS.update({
        'local': True, 'version': version(), 'os': platform.system(), 'python': platform.python_version(),
        'vol3': {'available': bool(vc), 'version': vv},
        'ez': {'tools': sorted(ez_tools().keys()), 'dotnet': bool(dotnet_path())},
        'runs': str(RUNS),
    })
    CAPS['_volcmd'] = vc

# ------------------------------------------------------------------ jobs
def new_job(kind, total):
    jid = uuid.uuid4().hex[:12]
    d = RUNS / f'{time.strftime("%Y%m%d-%H%M%S")}-{kind}-{jid[:6]}'
    d.mkdir(parents=True, exist_ok=True)
    job = {'id': jid, 'kind': kind, 'dir': str(d), 'status': 'running', 'done': 0, 'total': total, 'current': '', 'results': [], 'log': [], 'started': time.time()}
    with LOCK: JOBS[jid] = job
    return job

def jlog(job, msg):
    with LOCK:
        job['log'].append(msg); job['log'] = job['log'][-200:]

def run_vol(job, image, plugins):
    base = CAPS.get('_volcmd')
    for alts in plugins:
        name = alts[0]
        job['current'] = name
        ok = False
        for plugin in alts:
            out = Path(job['dir']) / f'{plugin}.json'
            jlog(job, f'vol {plugin}')
            try:
                with open(out, 'w', encoding='utf-8') as fh:
                    p = subprocess.run(base + ['-q', '-r', 'json', '-f', image, plugin], stdout=fh, stderr=subprocess.PIPE, text=True, timeout=7200)
                err = (p.stderr or '').strip()
                if p.returncode == 0 and out.stat().st_size > 2:
                    job['results'].append({'plugin': plugin, 'file': out.name, 'ok': True}); ok = True; break
                if re.search(r'invalid choice|not found|No such plugin|unrecognized', err, re.I):
                    out.unlink(missing_ok=True); continue  # try legacy name
                job['results'].append({'plugin': plugin, 'file': out.name if out.exists() and out.stat().st_size > 2 else None, 'ok': False, 'error': err[-600:]})
                ok = True; break
            except subprocess.TimeoutExpired:
                job['results'].append({'plugin': plugin, 'ok': False, 'error': 'timed out'}); ok = True; break
            except Exception as e:
                job['results'].append({'plugin': plugin, 'ok': False, 'error': str(e)}); ok = True; break
        if not ok: job['results'].append({'plugin': name, 'ok': False, 'error': 'plugin not available in this Volatility version'})
        job['done'] += 1
    job['status'] = 'done'; job['current'] = ''

def ez_plan(root):
    """KAPE !EZParser style: which tool runs on what inside a folder."""
    r = Path(root); plan = []
    def find(pattern):
        return [p for p in r.rglob(pattern) if p.is_file()]
    tools = ez_tools()
    def add(tool, args, label):
        if tool in tools: plan.append((tool, args, label))
    if find('*.evtx'): add('EvtxECmd', ['-d', str(r)], 'event logs')
    if find('*.pf'): add('PECmd', ['-d', str(r), '-q'], 'prefetch')
    if find('*.lnk'): add('LECmd', ['-d', str(r), '-q'], 'shortcuts')
    if find('*Destinations-ms'): add('JLECmd', ['-d', str(r), '-q'], 'jump lists')
    # dirty hives: replay .LOG1/.LOG2 when they were collected, otherwise tell the tool to proceed without them (--nl)
    has_logs = lambda h: any(h.with_name(h.name + ext).exists() for ext in ('.LOG1', '.LOG2', '.LOG', '.log1', '.log2', '.log'))
    if any(find(n) for n in ['NTUSER.DAT', 'SYSTEM', 'SOFTWARE', 'SAM', 'UsrClass.dat']) and 'RECmd' in tools:
        batch = next(Path(tools['RECmd']).parent.rglob('Kroll_Batch.reb'), None) or next(Path(tools['RECmd']).parent.rglob('*.reb'), None)
        any_logs = bool(find('*.LOG1') or find('*.LOG2'))
        if batch: add('RECmd', ['-d', str(r), '--bn', str(batch)] + ([] if any_logs else ['--nl']), 'registry (batch)')
    for h in find('Amcache.hve'): add('AmcacheParser', ['-f', str(h), '-i'] + ([] if has_logs(h) else ['--nl']), 'amcache')
    for h in find('SYSTEM'): add('AppCompatCacheParser', ['-f', str(h)] + ([] if has_logs(h) else ['--nl']), 'shimcache')
    for m in find('$MFT'): add('MFTECmd', ['-f', str(m)], '$MFT')
    for j in find('$J'): add('MFTECmd', ['-f', str(j)], '$J')
    if find('$I*'): add('RBCmd', ['-d', str(r), '-q'], 'recycle bin')
    if any(find(n) for n in ['NTUSER.DAT', 'UsrClass.dat']): add('SBECmd', ['-d', str(r)], 'shellbags')
    for s in find('SRUDB.dat'): add('SrumECmd', ['-f', str(s)], 'SRUM')
    for s in find('Current.mdb'): add('SumECmd', ['-d', str(s.parent)], 'SUM / UAL')
    for a in find('ActivitiesCache.db'): add('WxTCmd', ['-f', str(a)], 'timeline')
    for f in find('RecentFileCache.bcf'): add('RecentFileCacheParser', ['-f', str(f)], 'recentfilecache')
    if 'SQLECmd' in tools: add('SQLECmd', ['-d', str(r)], 'sqlite (maps)')
    return plan

def run_ez(job, root):
    plan = ez_plan(root)
    job['total'] = len(plan)
    tools = ez_tools()
    for tool, args, label in plan:
        job['current'] = f'{tool} ({label})'
        if not IS_WIN and tool in WINDOWS_ONLY:
            job['results'].append({'tool': tool, 'label': label, 'ok': False, 'skipped': True, 'error': WINDOWS_ONLY[tool]}); job['done'] += 1; continue
        out = Path(job['dir']) / tool
        out.mkdir(exist_ok=True)
        cmd = ez_cmd(tools[tool])
        if not cmd:
            job['results'].append({'tool': tool, 'ok': False, 'error': 'Windows-only build on this OS' if tools[tool].lower().endswith('.exe') else '.NET runtime not found (sudo-z setup dotnet)'}); job['done'] += 1; continue
        jlog(job, f'{tool} {" ".join(args)}')
        try:
            p = subprocess.run(cmd + args + ['--csv', str(out)], capture_output=True, text=True, timeout=7200, env=tool_env(), stdin=subprocess.DEVNULL)
            files = [str(x.relative_to(job['dir'])) for x in out.rglob('*') if x.is_file()]
            err = ''
            if p.returncode:
                err = ((p.stderr or '').strip() or (p.stdout or '').strip())[-800:] or f'exit code {p.returncode}'
            job['results'].append({'tool': tool, 'label': label, 'ok': p.returncode == 0, 'files': files, 'error': err, 'exit': p.returncode})
        except Exception as e:
            job['results'].append({'tool': tool, 'label': label, 'ok': False, 'error': str(e)})
        job['done'] += 1
    job['status'] = 'done'; job['current'] = ''

# ------------------------------------------------------------------ HTTP
class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw): super().__init__(*a, directory=str(APP), **kw)
    def log_message(self, fmt, *args): pass
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()
    def guess_type(self, path):
        if str(path).endswith(('.js', '.mjs')): return 'text/javascript; charset=utf-8'
        return mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
    def host_ok(self):
        h = (self.headers.get('Host') or '').split(':')[0].lower()
        return h in ('localhost', '127.0.0.1', '[::1]')
    def send_json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def api_guard(self):
        if not self.host_ok(): self.send_json({'error': 'bad host'}, 403); return False
        if self.headers.get('X-Sudo-Z') != '1': self.send_json({'error': 'missing X-Sudo-Z header'}, 403); return False
        return True
    def do_GET(self):
        if not self.host_ok(): return self.send_error(403)
        u = urlparse(self.path)
        if u.path.startswith('/api/'):
            if not self.api_guard(): return
            if u.path == '/api/caps': return self.send_json({k: v for k, v in CAPS.items() if not k.startswith('_')})
            m = re.match(r'^/api/job/([0-9a-f]+)$', u.path)
            if m:
                j = JOBS.get(m.group(1))
                return self.send_json(j) if j else self.send_json({'error': 'no such job'}, 404)
            m = re.match(r'^/api/job/([0-9a-f]+)/file/(.+)$', u.path)
            if m:
                j = JOBS.get(m.group(1))
                if not j: return self.send_json({'error': 'no such job'}, 404)
                p = (Path(j['dir']) / unquote(m.group(2))).resolve()
                if not str(p).startswith(str(Path(j['dir']).resolve())) or not p.is_file(): return self.send_json({'error': 'not found'}, 404)
                data = p.read_bytes()
                self.send_response(200); self.send_header('Content-Type', 'application/octet-stream'); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data); return
            return self.send_json({'error': 'unknown endpoint'}, 404)
        return super().do_GET()
    def do_POST(self):
        if not self.api_guard(): return
        n = int(self.headers.get('Content-Length') or 0)
        try: body = json.loads(self.rfile.read(n) or b'{}')
        except Exception: return self.send_json({'error': 'bad json'}, 400)
        u = urlparse(self.path)
        if u.path == '/api/vol3/run':
            if not CAPS['vol3']['available']: return self.send_json({'error': 'Volatility 3 not installed. Run: sudo-z setup vol'}, 400)
            img = os.path.expanduser(str(body.get('image', '')).strip().strip('"'))
            if not os.path.isfile(img): return self.send_json({'error': f'memory image not found: {img}'}, 400)
            plugins = VOL_PLUGINS
            if body.get('plugins'): plugins = [[p] for p in body['plugins'] if re.match(r'^[a-z]+(\.[a-z0-9_]+)+$', p)]
            job = new_job('vol3', len(plugins)); job['image'] = img
            threading.Thread(target=run_vol, args=(job, img, plugins), daemon=True).start()
            return self.send_json(job)
        if u.path == '/api/ez/run':
            root = os.path.expanduser(str(body.get('path', '')).strip().strip('"'))
            if not os.path.isdir(root): return self.send_json({'error': f'folder not found: {root}'}, 400)
            if not CAPS['ez']['tools']: return self.send_json({'error': 'Eric Zimmerman tools not installed. Run: sudo-z setup ez'}, 400)
            job = new_job('ez', 0); job['path'] = root
            threading.Thread(target=run_ez, args=(job, root), daemon=True).start()
            return self.send_json(job)
        if u.path == '/api/rescan':
            detect_caps(); return self.send_json({k: v for k, v in CAPS.items() if not k.startswith('_')})
        if u.path == '/api/open':
            j = JOBS.get(str(body.get('job', '')))
            if j:
                try:
                    if IS_WIN: os.startfile(j['dir'])  # noqa
                    elif sys.platform == 'darwin': subprocess.Popen(['open', j['dir']])
                    else: subprocess.Popen(['xdg-open', j['dir']])
                except Exception as e: return self.send_json({'error': str(e)}, 500)
                return self.send_json({'ok': True})
            return self.send_json({'error': 'no such job'}, 404)
        return self.send_json({'error': 'unknown endpoint'}, 404)

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    port = int(args[0]) if args else 8765
    detect_caps()
    srv = None
    for p in range(port, port + 20):
        try: srv = ThreadingHTTPServer(('127.0.0.1', p), Handler); port = p; break
        except OSError: continue
    if not srv: sys.exit(f'no free port between {port} and {port + 19}')
    url = f'http://localhost:{port}/'
    v = CAPS['vol3']; e = CAPS['ez']
    print(f'[sudo-z] serving {APP}')
    print(f'[sudo-z] Volatility 3: {"v" + v["version"] if v["available"] else "not installed (sudo-z setup vol)"}')
    print(f'[sudo-z] EZ tools: {len(e["tools"])} found' + ('' if e['tools'] else ' (sudo-z setup ez)'))
    print(f'[sudo-z] open {url}   (Ctrl+C to stop)')
    if '--no-browser' not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try: srv.serve_forever()
    except KeyboardInterrupt: pass

if __name__ == '__main__':
    main()
