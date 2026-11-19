#!/usr/bin/env python3
"""Run MemProcFS forensic mode on a memory image and write its forensic CSVs to a folder.

Uses the MemProcFS Python API, so nothing is mounted: no Dokany on Windows and no
FUSE on Linux. The virtual file system is read straight through the API.

usage: mpfs_run.py <image> <outdir> [--forensic N] [--elastic-license] [--yara-rules PATH]

Forensic mode levels (MemProcFS): 1 in-memory sqlite, 2 temp sqlite deleted on exit,
3 temp sqlite kept, 4 named vmm.sqlite3. Default 1.
"""
import argparse, json, os, sys, time

# the forensic CSVs worth collecting; missing ones are skipped without complaint
CSV_FILES = [
    "findevil.csv", "process.csv", "net.csv", "netdns.csv", "services.csv", "tasks.csv",
    "drivers.csv", "devices.csv", "modules.csv", "unloaded_modules.csv", "threads.csv",
    "handles.csv", "prefetch.csv", "files.csv", "yara.csv", "virtualmachines.csv",
    "eventlog.csv", "amcache_files.csv", "amcache_applications.csv",
]
TEXT_FILES = ["/forensic/findevil/findevil.txt", "/forensic/timeline/timeline_all.txt"]


def read_vfs(vmm, path, chunk=4 * 1024 * 1024):
    """Read a virtual file whole. The API has no size call, so read until short."""
    out, offset = bytearray(), 0
    while True:
        try:
            part = vmm.vfs.read(path, chunk, offset)
        except Exception:
            break
        if not part:
            break
        out += part
        offset += len(part)
        if len(part) < chunk:
            break
        if offset > 2 * 1024 * 1024 * 1024:
            break
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("outdir")
    ap.add_argument("--forensic", default="1")
    ap.add_argument("--elastic-license", action="store_true", help="accept Elastic License 2.0 so the built-in FindEvil YARA rules run")
    ap.add_argument("--yara-rules", default="")
    ap.add_argument("--timeout", type=int, default=7200)
    a = ap.parse_args()

    try:
        import memprocfs
    except ImportError:
        print(json.dumps({"error": "the memprocfs package is not installed. Run: sudo-z setup memprocfs"}))
        return 2

    args = ["-device", a.image, "-forensic", str(a.forensic)]
    if a.elastic_license:
        args += ["-license-accept-elastic-license-2.0"]
    if a.yara_rules:
        args += ["-forensic-yara-rules", a.yara_rules]

    try:
        vmm = memprocfs.Vmm(args)
    except Exception as e:
        print(json.dumps({"error": f"MemProcFS could not open the image: {e}"}))
        return 3
    try:
        vmm.initialize_plugins()
    except Exception as e:
        print(json.dumps({"error": f"MemProcFS plugin init failed: {e}"}))
        return 3

    # forensic mode runs in the background; wait for it
    started = time.time()
    last = -1
    while time.time() - started < a.timeout:
        try:
            pct = int(read_vfs(vmm, "/forensic/progress_percent.txt").decode(errors="replace").strip() or 0)
        except Exception:
            pct = -1
        if pct != last and pct >= 0:
            print(json.dumps({"progress": pct}), flush=True)
            last = pct
        if pct >= 100:
            break
        time.sleep(2)

    os.makedirs(a.outdir, exist_ok=True)
    written = []
    for name in CSV_FILES:
        data = read_vfs(vmm, "/forensic/csv/" + name)
        if len(data) > 2:
            with open(os.path.join(a.outdir, name), "wb") as fh:
                fh.write(data)
            written.append(name)
    tl = read_vfs(vmm, "/forensic/csv/timeline_all.csv") or read_vfs(vmm, "/forensic/timeline/timeline_all.csv")
    if len(tl) > 2:
        with open(os.path.join(a.outdir, "timeline_all.csv"), "wb") as fh:
            fh.write(tl)
        written.append("timeline_all.csv")
    for path in TEXT_FILES:
        data = read_vfs(vmm, path)
        if len(data) > 2:
            with open(os.path.join(a.outdir, os.path.basename(path)), "wb") as fh:
                fh.write(data)
            written.append(os.path.basename(path))

    print(json.dumps({"done": True, "files": written, "percent": last}))
    return 0 if written else 4


if __name__ == "__main__":
    sys.exit(main())
