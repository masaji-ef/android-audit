# android-audit

Minimal, reliable Android device audit over ADB.

## Features

- Device info, security patch age, verified boot, encryption
- Full package list (system + third-party) with per-package dumpsys
- Runtime security checks: Accessibility, Notification Listeners, Device Admins
- Dangerous permission scan
- Component scan (Accessibility / VPN / DeviceAdmin / NotifListener)
- Optional APK pull (`--apks`)
- Optional external scanners: `mvt-android`, `spytrap-adb`
- Optional `bugreport` (`--bugreport`)
- Parallel dumpsys and APK pull (`--workers N`)
- SHA-256 manifest + integrity verification
- Colored structured output with progress bars (rich)

## Requirements

- Linux (Arch / Debian / Ubuntu / Fedora) — recommended
- Windows 11 — via WSL2 or native Python 3.10+
- Python 3.10+
- adb (Android SDK Platform Tools)

### Linux packages

Arch / CachyOS:
```
sudo pacman -S android-tools android-udev python uv
```

Debian / Ubuntu:
```
sudo apt install android-tools-adb python3 python3-venv python3-pip
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Fedora:
```
sudo dnf install android-tools python3 python3-pip
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Windows 11

Option A — WSL2 (recommended):
```
wsl --install -d Ubuntu
```
Then follow the Debian/Ubuntu steps inside WSL.

Option B — native:
1. Install Python 3.10+ from python.org
2. Install Android SDK Platform Tools, add `adb.exe` to PATH
3. Install uv: `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"`

Note: native Windows may fail with mvt-android; use WSL2 for MVT.

### Optional tools

```
uv tool install mvt && mvt download-iocs     # MVT
sudo pacman -S spytrap-adb                   # spytrap (Arch)
cargo install spytrap-adb                    # spytrap (any OS)
uv tool install androguard                   # APK analysis
sudo pacman -S jadx                          # decompiler (Arch)
```

## Usage

```
chmod +x android-audit.py
./android-audit.py
```

### Options

```
./android-audit.py                 # first authorized device
./android-audit.py <serial>        # specific device
./android-audit.py --all           # every authorized device
./android-audit.py --debug         # verbose debug output
./android-audit.py --apks          # pull APKs (off by default)
./android-audit.py --bugreport     # generate bugreport (off by default)
./android-audit.py --workers 8     # parallel workers (default 4)
./android-audit.py --no-mvt        # skip mvt-android
./android-audit.py --no-spytrap    # skip spytrap-adb
./android-audit.py --no-tools      # skip both
./android-audit.py -h | --help
```

## Output

```
audit_<serial>_<timestamp>/
├── props/            # getprop, model, patch, kernel
├── packages/         # all / third-party / system, per-package dumpsys
├── dumpsys/          # 21 key services
├── permissions/
├── logs/             # sha256sums, mvt, spytrap logs
├── reports/mvt/
├── analysis/         # summary.md, summary.json, CSV reports
├── apks/             # only with --apks
└── bugreport.zip     # only with --bugreport
```

### Key files

- `analysis/summary.md` — human-readable report (start here)
- `analysis/summary.json` — machine-readable
- `analysis/components.csv` — Accessibility / VPN / Admin / NotifListener
- `analysis/dangerous_permissions.csv` — dangerous perms per package
- `analysis/installers.csv` — install source per package
- `logs/sha256sums.txt` — SHA-256 manifest

## Setup (dev)

```
python -m venv .venv
.venv/bin/pip install rich
.venv/bin/python android-audit.py
```

Or with uv (recommended):
```
uv run android-audit.py
```

## Notes

- `.venv/` is required and git-ignored.
- No root required. Some dumpsys services restricted by SELinux without root.
- spytrap-adb may report false positives for sideloaded apps (Aurora Store, F-Droid).
  The tool filters these.
- MVT check-adb requires an adb backup file, not a live USB scan.
  Use spytrap-adb for live scanning.

## License

MIT

