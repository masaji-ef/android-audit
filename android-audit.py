#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "rich>=13.7",
# ]
# ///
"""
android-audit.py — Android device audit over ADB.

Steps:
  1. props & device info
  2. package & permission lists
  3. key dumpsys snapshots
  4. per-package dumpsys (concurrent)
  5. APK pull (opt-in with --apks)
  6. optional tools (mvt-android, spytrap-adb) with live output
  7. analysis (components, permissions, installers)
  8. hashing (SHA-256 manifest)
  9. bugreport (opt-in with --bugreport)

Examples:
  ./android-audit.py
  ./android-audit.py --all
  ./android-audit.py --apks
  ./android-audit.py --debug --workers 8
  ./android-audit.py --bugreport
  ./android-audit.py --no-mvt
  ./android-audit.py --no-spytrap
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Thread
from typing import Iterable, Iterator, Sequence

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn, Progress, SpinnerColumn, TaskProgressColumn,
    TextColumn, TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

# ─────────────────────────── config ───────────────────────────

DUMPSYS_SERVICES: tuple[str, ...] = (
    "activity", "package", "appops", "deviceidle", "connectivity",
    "netstats", "usagestats", "battery", "power", "alarm", "window",
    "notification", "wifi", "bluetooth", "telephony", "account",
    "input_method", "location", "accessibility", "security", "keyguard",
)

COMPONENT_MARKERS: dict[str, str] = {
    "accessibility":         "BIND_ACCESSIBILITY_SERVICE",
    "notification_listener": "BIND_NOTIFICATION_LISTENER_SERVICE",
    "device_admin":          "BIND_DEVICE_ADMIN",
    "vpn":                   "BIND_VPN_SERVICE",
    "input_method":          "BIND_INPUT_METHOD",
    "wallpaper":             "BIND_WALLPAPER",
    "dream":                 "BIND_DREAM_SERVICE",
    "call_screening":        "BIND_SCREENING_SERVICE",
    "autofill":              "BIND_AUTOFILL_SERVICE",
    "quick_settings":        "BIND_QUICK_SETTINGS_TILE",
}

DANGEROUS_PERMISSIONS: frozenset[str] = frozenset({
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.USE_EXACT_ALARM",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
})

PERM_RE      = re.compile(r"android\.permission\.[A-Z_]+")
INSTALLER_RE = re.compile(r"installerPackageName=(\S+)")
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")

DEFAULT_BUGREPORT_TIMEOUT = 1800
DEFAULT_SPYTRAP_TIMEOUT   = 300
DEFAULT_MVT_TIMEOUT       = 600
DEFAULT_IOC_TIMEOUT       = 120
DEFAULT_WORKERS           = 4

# ─────────────────────────── logger ───────────────────────────

class Log:
    def __init__(self, console: Console, debug: bool = False) -> None:
        self.c = console
        self.debug_enabled = debug

    @staticmethod
    def _stamp() -> str:
        return datetime.now().strftime("%H:%M:%S")

    def info(self, msg: str) -> None:
        self.c.print(f"[dim]{self._stamp()}[/dim] [blue]\\[info][/blue] {msg}")

    def ok(self, msg: str) -> None:
        self.c.print(f"[dim]{self._stamp()}[/dim] [green]\\[ ok ][/green] {msg}")

    def warn(self, msg: str) -> None:
        self.c.print(f"[dim]{self._stamp()}[/dim] [yellow]\\[warn][/yellow] {msg}")

    def err(self, msg: str) -> None:
        self.c.print(f"[dim]{self._stamp()}[/dim] [red]\\[ err ][/red] {msg}")

    def dbg(self, msg: str) -> None:
        if self.debug_enabled:
            self.c.print(f"[dim]{self._stamp()}[/dim] [cyan]\\[ dbg ][/cyan] [dim]{msg}[/dim]")

# ─────────────────────────── adb ──────────────────────────────

@dataclass
class Adb:
    serial: str | None = None
    log: Log = field(default_factory=lambda: Log(Console(stderr=True)))

    def _cmd(self, args: Sequence[str]) -> list[str]:
        base = ["adb"]
        if self.serial:
            base += ["-s", self.serial]
        return base + list(args)

    def run(self, args: Sequence[str], *, capture: bool = True) -> subprocess.CompletedProcess[bytes]:
        cmd = self._cmd(args)
        self.log.dbg("$ " + " ".join(cmd))
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.DEVNULL if capture else None,
        )

    def shell(self, *args: str) -> bytes:
        return self.run(["shell", *args]).stdout or b""

    def pull(self, remote: str, local: Path) -> bool:
        local.parent.mkdir(parents=True, exist_ok=True)
        return self.run(["pull", remote, str(local)]).returncode == 0

    def devices(self) -> list[str]:
        out = subprocess.run(
            ["adb", "devices"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout.decode(errors="replace")
        result = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                result.append(parts[0])
        return result

# ─────────────────────────── helpers ──────────────────────────

def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while data := f.read(chunk):
            h.update(data)
    return h.hexdigest()


def make_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, complete_style="green", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("[dim]({task.completed}/{task.total})[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


class _Spinner:
    """Static label spinner for short external commands."""

    def __init__(self, console: Console, label: str):
        self.c = console
        self.label = label
        self._live: Live | None = None

    def __enter__(self):
        self._live = Live(
            Text(f"[cyan]⠋[/cyan] {self.label}", style="dim"),
            console=self.c, refresh_per_second=10, transient=True,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *exc):
        if self._live:
            self._live.__exit__(*exc)


class _StreamSpinner:
    """Live spinner that tails a subprocess's stdout, showing the last line."""

    def __init__(self, console: Console, label: str, log_file: Path | None = None):
        self.c = console
        self.label = label
        self.log_file = log_file
        self._last = ""

    def _render(self) -> Text:
        tail = self._last[-120:] if self._last else "starting…"
        return Text.from_markup(
            f"[cyan]⠋[/cyan] [bold]{self.label}[/bold]  [dim]{tail}[/dim]"
        )

    def run(self, cmd: list[str], timeout: int) -> int:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1,
            text=True,
            errors="replace",
        )
        fh = self.log_file.open("w", encoding="utf-8") if self.log_file else None
        start = time.monotonic()

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.rstrip("\n")
                if fh:
                    fh.write(line + "\n")
                    fh.flush()
                if line.strip():
                    self._last = line.strip()

        t = Thread(target=reader, daemon=True)
        t.start()

        with Live(self._render(), console=self.c,
                  refresh_per_second=10, transient=True) as live:
            while proc.poll() is None:
                if timeout and (time.monotonic() - start) > timeout:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    live.update(Text.from_markup(
                        f"[yellow]⠋[/yellow] [bold]{self.label}[/bold]  "
                        f"[yellow]timed out after {timeout}s[/yellow]"
                    ))
                    break
                live.update(self._render())
                time.sleep(0.2)

        t.join(timeout=2)
        if fh:
            fh.close()
        return proc.returncode or 0

# ─────────────────────────── options ──────────────────────────

@dataclass
class AuditOptions:
    pull_apks: bool = False
    run_mvt: bool = True
    run_spytrap: bool = True
    bugreport_timeout: int = 0
    spytrap_timeout: int = DEFAULT_SPYTRAP_TIMEOUT
    mvt_timeout: int = DEFAULT_MVT_TIMEOUT
    ioc_timeout: int = DEFAULT_IOC_TIMEOUT
    workers: int = DEFAULT_WORKERS
    debug: bool = False


@dataclass
class AuditResult:
    serial: str
    out_dir: Path
    total_pkgs: int = 0
    third_party: int = 0
    apk_count: int = 0
    apk_size: str = "-"
    total_size: str = "-"
    dumpsys_files: int = 0
    pkg_dumpsys: int = 0
    mvt_reports: int = 0
    mvt_ok: bool = False
    spytrap_lines: int = 0
    spytrap_hits: int = 0
    integrity_ok: bool = False
    suspicious_components: int = 0

# ─────────────────────────── audit ────────────────────────────

class Audit:
    def __init__(self, adb: Adb, console: Console, log: Log, opts: AuditOptions):
        self.adb = adb
        self.c = console
        self.log = log
        self.opts = opts
        self.out: Path = Path(".").resolve()
        self._system_pkgs: set[str] = set()

    # ── io helpers ────────────────────────────────────────────
    @staticmethod
    def _safe(name: str) -> str:
        return SAFE_NAME_RE.sub("_", name)

    def _write(self, rel: str, data: bytes) -> None:
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def _sh(self, rel: str, *args: str) -> None:
        self._write(rel, self.adb.shell(*args))

    # ── steps ─────────────────────────────────────────────────

    def step_props(self) -> None:
        self.log.info("step 1/9: props & device info")
        with make_progress(self.c) as prog:
            t = prog.add_task("collecting device info", total=5)
            for rel, *cmd in (
                ("props/getprop.txt", "getprop"),
                ("props/model.txt", "getprop", "ro.product.model"),
                ("props/android_version.txt", "getprop", "ro.build.version.release"),
                ("props/security_patch.txt", "getprop", "ro.build.version.security_patch"),
            ):
                self._sh(rel, *cmd)
                prog.advance(t)
            self._write("props/kernel.txt", self.adb.shell("cat", "/proc/version"))
            prog.advance(t)

    def step_packages(self) -> int:
        self.log.info("step 2/9: package & permission lists")
        with make_progress(self.c) as prog:
            t = prog.add_task("collecting package lists", total=5)
            for rel, *cmd in (
                ("packages/all_packages.txt",          "pm", "list", "packages", "-f"),
                ("packages/third_party_packages.txt",  "pm", "list", "packages", "-3", "-f"),
                ("packages/system_packages.txt",       "pm", "list", "packages", "-s", "-f"),
                ("permissions/permissions_list.txt",   "pm", "list", "permissions", "-g", "-f"),
                ("packages/users.txt",                 "pm", "list", "users"),
            ):
                self._sh(rel, *cmd)
                prog.advance(t)

        total = self._count_lines(self.out / "packages/all_packages.txt")
        third = self._count_lines(self.out / "packages/third_party_packages.txt")
        self.log.info(f"found {total} packages ({third} third-party)")
        return total

    def step_dumpsys(self) -> None:
        self.log.info(f"step 3/9: key dumpsys snapshots ({len(DUMPSYS_SERVICES)} services)")
        with make_progress(self.c) as prog:
            t = prog.add_task("dumpsys snapshots", total=len(DUMPSYS_SERVICES))
            for svc in DUMPSYS_SERVICES:
                self._sh(f"dumpsys/{svc}.txt", "dumpsys", svc)
                prog.advance(t)

    def step_per_package(self, total: int) -> None:
        pkgs = list(self._iter_packages())
        self.log.info(f"step 4/9: per-package dumpsys ({len(pkgs)} packages, {self.opts.workers} workers)")
        with make_progress(self.c) as prog:
            t = prog.add_task("per-package dumpsys", total=len(pkgs))
            with ThreadPoolExecutor(max_workers=self.opts.workers) as ex:
                futs = {ex.submit(self._dump_pkg, pkg): pkg for pkg in pkgs}
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception as e:
                        self.log.dbg(f"dumpsys {futs[f]} failed: {e}")
                    prog.advance(t)

    def _dump_pkg(self, pkg: str) -> None:
        data = self.adb.shell("dumpsys", "package", pkg)
        self._write(f"packages/dumpsys_{self._safe(pkg)}.txt", data)

    def step_apks(self, total: int) -> tuple[int, str]:
        if not self.opts.pull_apks:
            self.log.info("step 5/9: APK pull disabled (use --apks to enable)")
            return 0, "-"

        entries = list(self._iter_apk_entries())
        self.log.info(f"step 5/9: pulling APKs ({len(entries)} packages)")
        with make_progress(self.c) as prog:
            t = prog.add_task("pulling APKs", total=len(entries))
            with ThreadPoolExecutor(max_workers=self.opts.workers) as ex:
                futs = {ex.submit(self._pull_apk, pkg, remote): pkg
                        for pkg, remote in entries}
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception as e:
                        self.log.dbg(f"pull {futs[f]} failed: {e}")
                    prog.advance(t)

        apks_dir = self.out / "apks"
        apks = list(apks_dir.glob("*.apk"))
        size = self._human(self._du(apks_dir))
        self.log.ok(f"pulled {len(apks)} APKs ({size})")
        return len(apks), size

    def _pull_apk(self, pkg: str, remote: str) -> None:
        self.adb.pull(remote, self.out / "apks" / f"{self._safe(pkg)}.apk")

    def step_tools(self) -> tuple[int, bool, int, int]:
        self.log.info("step 6/9: optional analysis tools")
        mvt_reports = 0
        mvt_ok = False
        spytrap_lines = 0
        spytrap_hits = 0

        # ── MVT: mobile verification toolkit ─────────────────
        if self.opts.run_mvt and shutil.which("mvt-android"):
            self.log.info(f"  → mvt-android check-adb (timeout {self.opts.mvt_timeout}s)")
            mvt_log = self.out / "logs/mvt_android.txt"
            rc = _StreamSpinner(
                self.c, "mvt-android running…", mvt_log,
            ).run(
                ["mvt-android", "check-adb",
                 "--output", str(self.out / "reports/mvt")],
                self.opts.mvt_timeout,
            )
            if rc != 0:
                self.log.warn(f"mvt-android exited with code {rc} — see logs/mvt_android.txt")
            else:
                mvt_ok = True
            mvt_dir = self.out / "reports/mvt"
            if mvt_dir.exists():
                mvt_reports = sum(1 for p in mvt_dir.rglob("*") if p.is_file())
            self.log.ok(f"mvt-android finished ({mvt_reports} files)")
        else:
            self.log.info("  → mvt-android skipped")

        # ── spytrap-adb: stalkerware scanner ─────────────────
        if self.opts.run_spytrap and shutil.which("spytrap-adb"):
            with _Spinner(self.c, "spytrap-adb: downloading IoCs…"):
                try:
                    subprocess.run(
                        ["spytrap-adb", "download-ioc"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=self.opts.ioc_timeout,
                    )
                except subprocess.TimeoutExpired:
                    self.log.warn("spytrap-adb download-ioc timed out")

            self.log.info(f"  → spytrap-adb scan (timeout {self.opts.spytrap_timeout}s)")
            log_file = self.out / "logs/spytrap_adb.txt"
            rc = _StreamSpinner(
                self.c, "spytrap-adb scanning…", log_file,
            ).run(["spytrap-adb", "scan"], self.opts.spytrap_timeout)
            if rc != 0:
                self.log.warn(f"spytrap-adb exited with code {rc} — see logs/spytrap_adb.txt")
            if log_file.exists():
                spytrap_lines = self._count_lines(log_file)
                spytrap_hits = self._count_spytrap_hits(log_file)
                if spytrap_hits:
                    self.log.warn(f"spytrap-adb found {spytrap_hits} suspicious entries")
                else:
                    self.log.ok("spytrap-adb: no suspicious entries")
            self.log.ok(f"spytrap-adb finished ({spytrap_lines} lines)")
        else:
            self.log.info("  → spytrap-adb skipped")

        return mvt_reports, mvt_ok, spytrap_lines, spytrap_hits

    def step_analysis(self) -> dict:
        out_dir = self.out / "analysis"
        out_dir.mkdir(parents=True, exist_ok=True)

        components: dict[str, list[str]] = {k: [] for k in COMPONENT_MARKERS}
        dangerous_perms: dict[str, list[str]] = {}
        installers: dict[str, list[str]] = {}
        third_party: list[str] = []
        system_count = 0

        dump_files = sorted((self.out / "packages").glob("dumpsys_*.txt"))
        self.log.info(f"step 7/9: analyzing {len(dump_files)} packages")

        with make_progress(self.c) as prog:
            t = prog.add_task("analyzing packages", total=len(dump_files))
            for dump_file in dump_files:
                pkg = dump_file.stem[len("dumpsys_"):]
                try:
                    text = dump_file.read_text(errors="replace")
                except Exception:
                    prog.advance(t)
                    continue

                if pkg in self._system_pkgs:
                    system_count += 1
                else:
                    third_party.append(pkg)

                for name, marker in COMPONENT_MARKERS.items():
                    if marker in text:
                        components[name].append(pkg)

                perms = set(PERM_RE.findall(text))
                danger = sorted(perms & DANGEROUS_PERMISSIONS)
                if danger:
                    dangerous_perms[pkg] = danger

                m = INSTALLER_RE.search(text)
                if m:
                    installers.setdefault(m.group(1), []).append(pkg)

                prog.advance(t)

        non_system_flags: list[dict] = []
        for name, pkgs_list in components.items():
            non_sys = sorted(p for p in pkgs_list if p not in self._system_pkgs)
            if non_sys:
                non_system_flags.append({"component": name, "packages": non_sys})

        self._write_csv(
            out_dir / "components.csv",
            ["component", "package", "system"],
            [(name, pkg, "yes" if pkg in self._system_pkgs else "no")
             for name, pkgs_list in components.items()
             for pkg in pkgs_list],
        )

        self._write_csv(
            out_dir / "dangerous_permissions.csv",
            ["package", "permission", "system"],
            [(pkg, perm, "yes" if pkg in self._system_pkgs else "no")
             for pkg, perms in sorted(dangerous_perms.items())
             for perm in perms],
        )

        self._write_csv(
            out_dir / "installers.csv",
            ["installer", "package"],
            [(inst, pkg)
             for inst, pkgs_list in sorted(installers.items())
             for pkg in pkgs_list],
        )

        self._write_csv(
            out_dir / "third_party.csv",
            ["package"],
            [(p,) for p in sorted(third_party)],
        )

        report = {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "device": self.adb.serial,
            "packages_total": len(dump_files),
            "packages_system": system_count,
            "packages_third_party": len(third_party),
            "components": components,
            "non_system_with_sensitive_components": non_system_flags,
            "dangerous_permissions": dangerous_perms,
            "installers": installers,
        }
        (out_dir / "summary.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False)
        )
        (out_dir / "summary.md").write_text(
            self._render_markdown(report, third_party)
        )

        flagged = sum(len(f["packages"]) for f in non_system_flags)
        self.log.ok(f"analysis done ({flagged} non-system flagged components)")
        return report

    def step_hashes(self) -> None:
        self.log.info("step 8/9: hashing all collected files")
        manifest = self.out / "logs/sha256sums.txt"
        files = [p for p in self.out.rglob("*")
                 if p.is_file()
                 and p.name != "sha256sums.txt"
                 and "hashes" not in p.parts]
        with make_progress(self.c) as prog:
            t = prog.add_task("sha256 hashing", total=len(files))
            with manifest.open("w") as m:
                for p in files:
                    m.write(f"{sha256_of(p)}  {p.relative_to(self.out)}\n")
                    prog.advance(t)
        self.log.ok(f"hashed {len(files)} files → logs/sha256sums.txt")

    def step_bugreport(self) -> None:
        if self.opts.bugreport_timeout <= 0:
            self.log.info("step 9/9: bugreport disabled (use --bugreport to enable)")
            return
        self.log.info(f"step 9/9: bugreport (timeout {self.opts.bugreport_timeout}s)")
        dst = self.out / "bugreport.zip"
        try:
            with _Spinner(self.c, "bugreport generating…"):
                subprocess.run(
                    ["adb", "-s", self.adb.serial or "", "bugreport", str(dst)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=self.opts.bugreport_timeout,
                )
            size = self._human(dst.stat().st_size) if dst.exists() else "?"
            self.log.ok(f"bugreport saved ({size})")
        except subprocess.TimeoutExpired:
            self.log.warn("bugreport timed out")
        except KeyboardInterrupt:
            self.log.warn("bugreport skipped by user")

    def verify(self) -> bool:
        self.log.info("verifying integrity")
        manifest = self.out / "logs/sha256sums.txt"
        if not manifest.exists():
            return False
        with manifest.open() as m:
            for line in m:
                line = line.rstrip("\n")
                if not line:
                    continue
                digest, rel = line.split("  ", 1)
                p = self.out / rel
                if not p.exists() or sha256_of(p) != digest:
                    self.log.warn(f"integrity FAILED: {rel}")
                    return False
        self.log.ok("integrity OK")
        return True

    # ── runner ────────────────────────────────────────────────
    def run(self) -> AuditResult:
        serial = self.adb.serial or "unknown"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_name = f"audit_{serial}_{ts}"
        self.out = (Path.cwd() / out_name).resolve()

        self.c.rule(f"[bold cyan]auditing device: {serial}[/bold cyan]")
        self.log.info(f"output dir: {out_name}")

        for sub in ("props", "dumpsys", "packages", "apks",
                    "permissions", "logs", "reports", "hashes", "analysis"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)

        result = AuditResult(serial=serial, out_dir=self.out)
        self.step_props()
        result.total_pkgs = self.step_packages()
        self._system_pkgs = self._load_system_pkgs()
        result.third_party = result.total_pkgs - len(self._system_pkgs)
        self.step_dumpsys()
        self.step_per_package(result.total_pkgs)
        result.apk_count, result.apk_size = self.step_apks(result.total_pkgs)

        (result.mvt_reports,
         result.mvt_ok,
         result.spytrap_lines,
         result.spytrap_hits) = self.step_tools()

        report = self.step_analysis()
        result.suspicious_components = sum(
            len(f["packages"]) for f in report["non_system_with_sensitive_components"]
        )
        self.step_hashes()
        result.pkg_dumpsys = sum(1 for _ in (self.out / "packages").glob("dumpsys_*.txt"))
        result.dumpsys_files = sum(1 for _ in (self.out / "dumpsys").glob("*.txt"))
        self.step_bugreport()
        result.integrity_ok = self.verify()
        result.total_size = self._human(self._du(self.out))
        self._print_summary(result)
        return result

    # ── internals ─────────────────────────────────────────────
    def _iter_packages(self) -> Iterator[str]:
        path = self.out / "packages/all_packages.txt"
        if not path.exists():
            return
        for line in path.read_text(errors="replace").splitlines():
            if "=" not in line:
                continue
            _, _, pkg = line.rpartition("=")
            if pkg.strip():
                yield pkg.strip()

    def _iter_apk_entries(self) -> Iterator[tuple[str, str]]:
        path = self.out / "packages/all_packages.txt"
        if not path.exists():
            return
        for line in path.read_text(errors="replace").splitlines():
            if not line.startswith("package:"):
                continue
            body = line[len("package:"):]
            apk_path, _, pkg = body.rpartition("=")
            if pkg:
                yield pkg.strip(), apk_path.strip()

    def _load_system_pkgs(self) -> set[str]:
        path = self.out / "packages/system_packages.txt"
        if not path.exists():
            return set()
        result = set()
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                _, _, pkg = line.rpartition("=")
                if pkg.strip():
                    result.add(pkg.strip())
        return result

    @staticmethod
    def _count_lines(p: Path) -> int:
        if not p.exists():
            return 0
        return sum(1 for _ in p.open("rb"))

    @staticmethod
    def _count_spytrap_hits(p: Path) -> int:
        """Count meaningful spytrap-adb hits.

        Filters out:
          * system overlays (installer="null") — normal for LineageOS/AOSP
          * duplicate lines (spytrap logs each hit twice)
        """
        if not p.exists():
            return 0
        seen: set[str] = set()
        for line in p.read_text(errors="replace").splitlines():
            if "Suspicious High" not in line and "Suspicious Medium" not in line:
                continue
            if 'unknown installer: "null"' in line:
                continue
            # normalize: drop timestamp, keep signal
            m = re.search(r"(Suspicious (?:High|Medium):.*)$", line)
            if m:
                seen.add(m.group(1))
        return len(seen)

    @staticmethod
    def _du(p: Path) -> int:
        total = 0
        for f in p.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except OSError:
                    pass
        return total

    @staticmethod
    def _human(n: int) -> str:
        step = 1024.0
        for unit in ("B", "K", "M", "G", "T"):
            if n < step:
                return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
            n /= step
        return f"{n:.1f}P"

    @staticmethod
    def _write_csv(path: Path, header: list[str], rows: Iterable[tuple]) -> None:
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)

    def _render_markdown(self, report: dict, third_party: list[str]) -> str:
        L: list[str] = []
        a = L.append

        a(f"# Android Audit — {report['device']}")
        a("")
        a(f"- Generated: **{report['generated']}**")
        a(f"- Packages total: **{report['packages_total']}**")
        a(f"- System: **{report['packages_system']}**")
        a(f"- Third-party: **{report['packages_third_party']}**")
        a("")

        a("## Third-party packages")
        a("")
        for p in sorted(third_party):
            a(f"- `{p}`")
        a("")

        a("## Components of interest")
        a("")
        a("| Component | Total | Non-system packages |")
        a("|---|---|---|")
        for name, pkgs_list in report["components"].items():
            non_sys = [p for p in pkgs_list if p not in self._system_pkgs]
            cell = ", ".join(f"`{p}`" for p in non_sys) if non_sys else "—"
            a(f"| {name} | {len(pkgs_list)} | {cell} |")
        a("")

        a("## Non-system apps with sensitive components")
        a("")
        if not report["non_system_with_sensitive_components"]:
            a("_None._")
        else:
            for item in report["non_system_with_sensitive_components"]:
                a(f"### {item['component']}")
                for p in item["packages"]:
                    a(f"- `{p}`")
                a("")

        a("## Dangerous permissions on third-party apps")
        a("")
        rows = [(pkg, perms) for pkg, perms in report["dangerous_permissions"].items()
                if pkg not in self._system_pkgs]
        if not rows:
            a("_None._")
        else:
            a("| Package | Permissions |")
            a("|---|---|")
            for pkg, perms in sorted(rows):
                a(f"| `{pkg}` | {', '.join(f'`{p}`' for p in perms)} |")
        a("")

        a("## Installers")
        a("")
        a("| Installer | Count |")
        a("|---|---|")
        for inst, pkgs_list in sorted(report["installers"].items(),
                                      key=lambda x: -len(x[1])):
            a(f"| `{inst}` | {len(pkgs_list)} |")
        a("")

        return "\n".join(L)

    def _print_summary(self, r: AuditResult) -> None:
        t = Table.grid(padding=(0, 2))
        t.add_column(style="dim")
        t.add_column()
        t.add_row("output dir:", str(r.out_dir))
        t.add_row("total size:", r.total_size)
        t.add_row("packages:", f"{r.total_pkgs} ({r.third_party} third-party)")
        t.add_row("apks:", f"{r.apk_count} ({r.apk_size})")
        t.add_row("dumpsys files:", str(r.dumpsys_files))
        t.add_row("pkg dumpsys:", str(r.pkg_dumpsys))
        if r.mvt_reports or r.mvt_ok:
            t.add_row(
                "mvt reports:",
                Text(f"{r.mvt_reports} files",
                     style="green" if r.mvt_ok else "yellow"),
            )
        if r.spytrap_lines:
            t.add_row(
                "spytrap hits:",
                Text(str(r.spytrap_hits),
                     style="red" if r.spytrap_hits else "green"),
            )
        t.add_row(
            "suspicious components:",
            Text(str(r.suspicious_components),
                 style="red" if r.suspicious_components else "green"),
        )
        t.add_row(
            "integrity:",
            Text("OK", style="green") if r.integrity_ok
            else Text("FAILED", style="bold red"),
        )
        self.c.print(Panel(
            t,
            title=f"[bold green]summary: {r.serial}[/bold green]",
            border_style="green",
        ))

# ─────────────────────────── cli ──────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="android-audit.py",
        description="Android device audit over ADB.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("serial", nargs="?",
                   help="device serial (default: first authorized)")
    p.add_argument("--all", action="store_true",
                   help="audit every authorized device")
    p.add_argument("--debug", action="store_true",
                   help="verbose debug output")
    p.add_argument("--apks", action="store_true",
                   help="pull APKs (off by default)")
    p.add_argument("--bugreport", action="store_true",
                   help="generate bugreport (off by default)")
    p.add_argument("--no-tools", action="store_true",
                   help="skip both mvt-android and spytrap-adb")
    p.add_argument("--no-mvt", action="store_true",
                   help="skip mvt-android only")
    p.add_argument("--no-spytrap", action="store_true",
                   help="skip spytrap-adb only")
    p.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                   metavar="N",
                   help=f"parallel workers (default {DEFAULT_WORKERS})")
    p.add_argument("--bugreport-timeout", type=int,
                   default=DEFAULT_BUGREPORT_TIMEOUT, metavar="SEC")
    p.add_argument("--mvt-timeout", type=int,
                   default=DEFAULT_MVT_TIMEOUT, metavar="SEC")
    p.add_argument("--spytrap-timeout", type=int,
                   default=DEFAULT_SPYTRAP_TIMEOUT, metavar="SEC")
    p.add_argument("--ioc-timeout", type=int,
                   default=DEFAULT_IOC_TIMEOUT, metavar="SEC")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(stderr=False)
    log = Log(console, debug=args.debug)

    if not shutil.which("adb"):
        log.err("adb not found (install android-tools)")
        return 2

    run_mvt = not (args.no_tools or args.no_mvt)
    run_spytrap = not (args.no_tools or args.no_spytrap)

    opts = AuditOptions(
        pull_apks=args.apks,
        run_mvt=run_mvt,
        run_spytrap=run_spytrap,
        bugreport_timeout=args.bugreport_timeout if args.bugreport else 0,
        spytrap_timeout=args.spytrap_timeout,
        mvt_timeout=args.mvt_timeout,
        ioc_timeout=args.ioc_timeout,
        workers=max(1, args.workers),
        debug=args.debug,
    )

    adb = Adb(log=log)

    if args.all:
        devices = adb.devices()
        if not devices:
            log.err("no authorized devices")
            return 1
        log.info(f"auditing {len(devices)} device(s)")
    else:
        devices = [args.serial] if args.serial else adb.devices()[:1]
        if not devices:
            log.err("no authorized device (enable USB debugging)")
            return 1

    for serial in devices:
        adb.serial = serial
        audit = Audit(adb, console, log, opts)
        try:
            audit.run()
        except KeyboardInterrupt:
            log.warn("interrupted by user")
            return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
