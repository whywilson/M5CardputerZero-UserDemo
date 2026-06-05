#!/usr/bin/env python3
"""Build a Debian package for the standalone RFID app.

This script follows the CardputerZero packaging layout:
    debian-<AppName>/
        DEBIAN/{control,postinst,prerm}
        usr/share/APPLaunch/{applications,apps/<pkg>,share/images,...}
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


FORCED_ICON_SOURCE = Path(
    "/Users/wilson/Github/M5CardputerZero-UserDemo/projects/APPLaunch/APPLaunch/share/images/ic_rfid.png"
)


def fail(msg: str, code: int = 1) -> int:
    print(f"[RFID][pack] ERROR: {msg}", file=sys.stderr)
    return code


def run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=True)


def load_meta(meta_path: Path) -> dict[str, str]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"failed to read {meta_path}: {exc}") from exc

    required = ["package_name", "version", "app_name", "bin_name", "description"]
    for key in required:
        if not str(meta.get(key, "")).strip():
            raise RuntimeError(f"missing required key in app-builder.json: {key}")
    return {k: str(v).strip() for k, v in meta.items()}


def ensure_binary(project_root: Path, bin_name: str, build_if_missing: bool) -> Path:
    bin_path = project_root / "dist" / bin_name
    if bin_path.exists():
        return bin_path

    if not build_if_missing:
        raise RuntimeError(
            f"missing binary: {bin_path}. Run 'scons -j$(nproc)' first or pass --build-if-missing"
        )

    env = os.environ.copy()
    env.setdefault("CardputerZero", "y")
    env.setdefault("CONFIG_REPO_AUTOMATION", "y")
    run(["scons", "-j1"], cwd=project_root, env=env)

    if not bin_path.exists():
        raise RuntimeError(f"binary still missing after build: {bin_path}")
    return bin_path


def write_text(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    if mode is not None:
        path.chmod(mode)


def copy_if_exists(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def create_package(
    project_root: Path,
    revision: str,
    maintainer: str,
    build_if_missing: bool,
    override_version: str | None,
) -> Path:
    meta = load_meta(project_root / "app-builder.json")

    package_name = meta["package_name"].lower()
    app_name = meta["app_name"]
    version = override_version or meta["version"]
    bin_name = meta["bin_name"]
    description = meta["description"]

    bin_src = ensure_binary(project_root, bin_name, build_if_missing)
    desktop_src = project_root / "applications" / "rfid.desktop"
    if not desktop_src.exists():
        raise RuntimeError(f"missing desktop entry: {desktop_src}")

    stage_dir = project_root / "build" / f"debian-{package_name}"
    out_deb = project_root / "build" / f"{package_name}_{version}-{revision}_arm64.deb"

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    if out_deb.exists():
        out_deb.unlink()

    debian_dir = stage_dir / "DEBIAN"
    app_root = stage_dir / "usr" / "share" / "APPLaunch"
    app_install_dir = app_root / "apps" / package_name

    (debian_dir).mkdir(parents=True, exist_ok=True)
    (app_root / "applications").mkdir(parents=True, exist_ok=True)
    (app_root / "apps").mkdir(parents=True, exist_ok=True)
    (app_root / "share" / "images").mkdir(parents=True, exist_ok=True)
    (app_install_dir).mkdir(parents=True, exist_ok=True)

    if FORCED_ICON_SOURCE.exists():
        forced_local_icon = project_root / "share" / "images" / "ic_rfid.png"
        copy_if_exists(FORCED_ICON_SOURCE, forced_local_icon)

    # Binary + desktop + share assets
    copy_if_exists(bin_src, app_install_dir / bin_name)
    (app_install_dir / bin_name).chmod(0o755)
    copy_if_exists(desktop_src, app_root / "applications" / desktop_src.name)

    share_src = project_root / "share"
    if share_src.exists():
        shutil.copytree(share_src, app_install_dir / "share", dirs_exist_ok=True)

    icon_rel = Path(meta.get("icon", "share/images/ic_rfid.png")).as_posix().strip()
    icon_dst = app_root / icon_rel
    if FORCED_ICON_SOURCE.exists():
        copy_if_exists(FORCED_ICON_SOURCE, icon_dst)
    else:
        icon_src = project_root / icon_rel
        copy_if_exists(icon_src, icon_dst)

    control = (
        f"Package: {package_name}\n"
        f"Version: {version}\n"
        "Architecture: arm64\n"
        f"Maintainer: {maintainer}\n"
        "Original-Maintainer: m5stack <m5stack@m5stack.com>\n"
        "Section: APPLaunch\n"
        "Priority: optional\n"
        "Homepage: https://www.m5stack.com\n"
        f"Packaged-Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Description: {description}\n"
    )

    postinst = f"""#!/bin/sh
set -e
APP_DIR="/usr/share/APPLaunch/apps/{package_name}"
mkdir -p "$APP_DIR/nfc_data"
mkdir -p "$APP_DIR/share/nfc/records"
mkdir -p "$APP_DIR/share/nfc/keys"
if id -u pi >/dev/null 2>&1; then
    chown -R pi:pi "$APP_DIR/nfc_data" "$APP_DIR/share/nfc"
fi
if [ -f \"/lib/systemd/system/APPLaunch.service\" ]; then
  systemctl restart APPLaunch.service || true
fi
exit 0
"""

    prerm = """#!/bin/sh
set -e
exit 0
"""

    write_text(debian_dir / "control", control)
    write_text(debian_dir / "postinst", postinst, mode=0o755)
    write_text(debian_dir / "prerm", prerm, mode=0o755)

    run(["dpkg-deb", "--root-owner-group", "-b", str(stage_dir), str(out_deb)])
    return out_deb


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build RFID Debian package for APPLaunch")
    parser.add_argument("--revision", default="m5stack1", help="Debian revision suffix")
    parser.add_argument("--version", default=None, help="Override version from app-builder.json")
    parser.add_argument(
        "--maintainer",
        default="wilson <wilson@example.com>",
        help="Maintainer field in DEBIAN/control",
    )
    parser.add_argument(
        "--build-if-missing",
        action="store_true",
        help="Run scons -j1 when dist binary is missing",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]

    if shutil.which("dpkg-deb") is None:
        return fail("dpkg-deb not found. Please install dpkg first.")

    try:
        out_deb = create_package(
            project_root=root,
            revision=args.revision,
            maintainer=args.maintainer,
            build_if_missing=args.build_if_missing,
            override_version=args.version,
        )
    except subprocess.CalledProcessError as exc:
        return fail(f"command failed with exit code {exc.returncode}")
    except Exception as exc:
        return fail(str(exc))

    print(f"[RFID][pack] OK: {out_deb}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
