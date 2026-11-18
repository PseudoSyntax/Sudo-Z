#!/usr/bin/env python3
"""Sudo-Z local companion server (home install only).

Serves the console on http://localhost and adds what a browser cannot do:
  * Volatility 3 on memory images (by path, so multi-GB images never pass through the browser)
  * the original Eric Zimmerman tools on a folder (KAPE / Velociraptor output), if installed
  * KAPE triage collection (Windows, elevated) from a live drive, a folder or a mounted VHD/VHDX
  * random-access reads of disk images by path, so the console can triage multi-GB images in place

Security: binds 127.0.0.1 only, rejects requests whose Host header is not
localhost, and requires an X-Sudo-Z header on API calls (a custom header
cannot be sent cross-origin without a CORS preflight, which is never allowed),
so other websites open in your browser cannot drive it.

Standard library only. Usage: python3 tools/server.py [port] [--no-browser]
"""
import base64, json, mimetypes, os, platform, re, shutil, subprocess, sys, threading, time, uuid, webbrowser
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs

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
    ['windows.registry.userassist'], ['windows.handles'], ['windows.filescan'],
    # injection and EDR evasion
    ['windows.malware.pebmasquerade'], ['windows.malware.skeleton_key_check', 'windows.skeleton_key_check'], ['windows.malware.direct_system_calls', 'windows.direct_system_calls'],
    ['windows.malware.indirect_system_calls', 'windows.indirect_system_calls'], ['windows.malware.unhooked_system_calls', 'windows.unhooked_system_calls'], ['windows.etwpatch'], ['windows.suspended_threads'],
    # kernel rootkits: syscall tables (global and per-thread), DKOM cross-views, callbacks, IRP and timer hooks
    ['windows.ssdt'], ['windows.kthread_ssdt'], ['windows.modules'], ['windows.modscan'], ['windows.driverscan'], ['windows.unloadedmodules'],
    ['windows.callbacks'], ['windows.driverirp'], ['windows.timers'], ['windows.orphan_kernel_threads'],
]
# Sudo-Z's own Volatility plugins (windows.kthread_ssdt)
VOL_EXTRA = APP / 'tools' / 'volplugins'

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

def kape_path():
    if not IS_WIN: return None
    cands = [os.environ.get('SUDOZ_KAPE', ''), str(HOME / 'kape' / 'kape.exe'), r'C:\KAPE\kape.exe', r'C:\Tools\KAPE\kape.exe', r'C:\Tools\kape\kape.exe',
             os.path.expandvars(r'%USERPROFILE%\Downloads\KAPE\kape.exe'), os.path.expandvars(r'%USERPROFILE%\Desktop\KAPE\kape.exe')]
    for c in cands:
        if c and os.path.isfile(c): return c
    k = HOME / 'kape'
    if k.exists():
        for p in k.rglob('kape.exe'): return str(p)
    return None

def is_admin():
    if not IS_WIN: return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False

def kape_targets(kp):
    """Compound target names shipped with this KAPE copy (for the picker)."""
    try:
        root = Path(kp).parent / 'Targets'
        names = sorted({p.stem for p in root.rglob('*.tkape') if p.parent.name.lower() == 'compound' or p.stem.startswith('!')})
        return names[:200]
    except Exception: return []

CAPS = {}
def detect_caps():
    vc, vv = vol_cmd()
    CAPS.clear()
    CAPS.update({
        'local': True, 'version': version(), 'os': platform.system(), 'python': platform.python_version(),
        'vol3': {'available': bool(vc), 'version': vv},
        'ez': {'tools': sorted(ez_tools().keys()), 'dotnet': bool(dotnet_path())},
        'runs': str(RUNS),
        'kape': {'available': bool(kape_path()), 'path': kape_path(), 'windows': IS_WIN, 'admin': is_admin(), 'targets': kape_targets(kape_path()) if kape_path() else []},
        'images': True,
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
                    extra = ['-p', str(VOL_EXTRA)] if VOL_EXTRA.is_dir() else []
                    p = subprocess.run(base + extra + ['-q', '-r', 'json', '-f', image, plugin], stdout=fh, stderr=subprocess.PIPE, text=True, timeout=7200)
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
    job['status'] = 'done'; job['current'] = ''; job['finished'] = time.time()

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

# ------------------------------------------------------------------ KAPE
MOUNTABLE = ('.vhd', '.vhdx', '.iso')
def psq(v): return "'" + str(v).replace("'", "''") + "'"

def run_kape(job, source, target, modules, vss):
    d = Path(job['dir']); tout = d / 'tout'; mout = d / 'mout'; log = d / 'kape.log'; flag = d / 'done.flag'
    kp = kape_path(); is_img = os.path.isfile(source)
    mod = f"--module '!EZParser' --mdest {psq(mout)} --mef csv" if modules else ''
    ps = f"""$ErrorActionPreference = 'Continue'
$log = {psq(log)}
function L($m) {{ Add-Content -LiteralPath $log -Value $m }}
$img = {psq(source) if is_img else '$null'}
$letters = @(); $mounted = $false
try {{
  if ($img) {{
    L "mounting $img read-only"
    Mount-DiskImage -ImagePath $img -Access ReadOnly | Out-Null; $mounted = $true; Start-Sleep -Seconds 3
    $letters = @(Get-DiskImage -ImagePath $img | Get-Disk | Get-Partition | Where-Object {{ $_.DriveLetter }} | ForEach-Object {{ "$($_.DriveLetter):" }})
    if (-not $letters) {{ L 'ERROR the image mounted but Windows gave it no drive letter (BitLocker, an unknown file system, or only hidden partitions)' }}
  }} else {{ $letters = @({psq(source)}) }}
  foreach ($d in $letters) {{
    $dest = Join-Path {psq(tout)} ($d.Substring(0,1))
    L "KAPE $d -> $dest (target {target})"
    & {psq(kp)} --tsource $d --tdest $dest --target {psq(target)} {'--vss' if vss else ''} {mod} 2>&1 | ForEach-Object {{ Add-Content -LiteralPath $log -Value $_ }}
    L "KAPE exit code $LASTEXITCODE"
  }}
}} catch {{ L ("ERROR " + $_) }}
finally {{
  if ($mounted) {{ Dismount-DiskImage -ImagePath $img | Out-Null; L 'image dismounted' }}
  Set-Content -LiteralPath {psq(flag)} -Value 'done'
}}
"""
    script = d / 'kape-job.ps1'; script.write_text(ps, encoding='utf-8-sig')
    log.write_text('', encoding='utf-8')
    base = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass']
    if is_admin():
        cmd = base + ['-File', str(script)]
    else:  # ask for elevation; the UAC prompt appears on this machine
        jlog(job, 'requesting administrator rights (UAC prompt)')
        elev = f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"' + {psq(script)} + '\"')"
        cmd = base + ['-EncodedCommand', base64.b64encode(elev.encode('utf-16-le')).decode()]
    job['current'] = 'starting KAPE'
    try: proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True)
    except Exception as e:
        job['status'] = 'error'; job['error'] = str(e); return
    seen = 0
    while True:
        done = proc.poll() is not None
        try:
            lines = log.read_text(encoding='utf-8', errors='replace').splitlines()
            for ln in lines[seen:]:
                if ln.strip(): jlog(job, ln.strip()); job['current'] = ln.strip()[:160]
            seen = len(lines)
        except OSError: pass
        if done: break
        time.sleep(1)
    out = (proc.stdout.read() if proc.stdout else '') or ''
    if not flag.exists():
        job['status'] = 'error'; job['error'] = ('Elevation was declined or PowerShell failed. ' + out.strip())[-600:]; job['current'] = ''; return
    files = [x for x in tout.rglob('*') if x.is_file()] if tout.exists() else []
    job['results'] = [{'file': str(x.relative_to(d)).replace(os.sep, '/'), 'size': x.stat().st_size} for x in files]
    job['modules'] = [str(x.relative_to(d)).replace(os.sep, '/') for x in mout.rglob('*.csv')] if mout.exists() else []
    job['total'] = job['done'] = len(files)
    job['status'] = 'done' if files else 'error'
    if not files: job['error'] = 'KAPE finished without collecting any files. See the log.'
    job['current'] = ''

# ------------------------------------------------------------------ disk images by path
def image_segments(path):
    """x.E01 -> x.E01, x.E02 ... ; x.001 -> x.001, x.002 ..."""
    p = Path(path); m = re.match(r'^(.*\.)(E|Ex|e|ex)?(\d{2,3})$', p.name)
    if not m: return [p]
    prefix, letter, num = m.group(1), m.group(2) or '', m.group(3)
    segs = []
    for i in range(int(num), int(num) + 10000):
        q = p.with_name(f'{prefix}{letter}{str(i).zfill(len(num))}')
        if not q.exists(): break
        segs.append(q)
    return segs or [p]

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
            if u.path == '/api/jobs':
                with LOCK: lst = [{**{k: v for k, v in j.items() if k not in ('log', 'results')}, 'log_tail': j['log'][-3:], 'count': len(j['results'])} for j in JOBS.values()]
                return self.send_json(sorted(lst, key=lambda j: -j['started']))
            if u.path in ('/api/image/stat', '/api/image/read'):
                q = parse_qs(u.query); path = os.path.expanduser(unquote(q.get('path', [''])[0]).strip().strip('"'))
                if not os.path.isfile(path): return self.send_json({'error': f'image not found: {path}'}, 404)
                if u.path == '/api/image/stat':
                    return self.send_json({'segments': [{'path': str(x), 'name': x.name, 'size': x.stat().st_size} for x in image_segments(path)]})
                off = int(q.get('off', ['0'])[0]); ln = min(int(q.get('len', ['0'])[0]), 64 * 1024 * 1024)
                with open(path, 'rb') as fh:
                    fh.seek(off); data = fh.read(max(0, ln))
                self.send_response(200); self.send_header('Content-Type', 'application/octet-stream'); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data); return
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
                self.send_response(200); self.send_header('Content-Type', 'application/octet-stream'); self.send_header('Content-Length', str(p.stat().st_size)); self.end_headers()
                with open(p, 'rb') as fh: shutil.copyfileobj(fh, self.wfile, 1024 * 1024)
                return
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
            job = new_job('vol3', len(plugins)); job['image'] = img; job['source'] = img
            threading.Thread(target=run_vol, args=(job, img, plugins), daemon=True).start()
            return self.send_json(job)
        if u.path == '/api/ez/run':
            root = os.path.expanduser(str(body.get('path', '')).strip().strip('"'))
            if not os.path.isdir(root): return self.send_json({'error': f'folder not found: {root}'}, 400)
            if not CAPS['ez']['tools']: return self.send_json({'error': 'Eric Zimmerman tools not installed. Run: sudo-z setup ez'}, 400)
            job = new_job('ez', 0); job['path'] = root; job['source'] = root
            threading.Thread(target=run_ez, args=(job, root), daemon=True).start()
            return self.send_json(job)
        if u.path == '/api/kape/run':
            if not IS_WIN: return self.send_json({'error': 'KAPE is a Windows program. On this OS, collect with KAPE on the Windows host (or drop the disk image into the console, which reads E01/VHD/VHDX/raw itself).'}, 400)
            if not kape_path(): return self.send_json({'error': 'KAPE not found. Download it from Kroll (free, registration required), unzip it to ' + str(HOME / 'kape') + ' or C:\\KAPE, then press RESCAN.'}, 400)
            src = os.path.expanduser(str(body.get('source', '')).strip().strip('"'))
            target = str(body.get('target') or '!SANS_Triage').strip()
            if not re.match(r'^[!\w.,\- ]{1,200}$', target): return self.send_json({'error': 'bad target name'}, 400)
            if re.match(r'^[A-Za-z]:\\?$', src): src = src[0].upper() + ':'
            elif os.path.isfile(src):
                if not src.lower().endswith(MOUNTABLE): return self.send_json({'error': 'Windows can only mount VHD, VHDX and ISO for KAPE. For E01, raw or QCOW2 use ANALYSE IMAGE instead: Sudo-Z reads those directly.'}, 400)
            elif not os.path.isdir(src): return self.send_json({'error': f'source not found: {src}'}, 400)
            job = new_job('kape', 0); job['source'] = src; job['target'] = target
            threading.Thread(target=run_kape, args=(job, src, target, bool(body.get('modules')), bool(body.get('vss'))), daemon=True).start()
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
