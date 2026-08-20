#!/usr/bin/env python3
"""Build an installable Debian/Kali .deb from the Night Scout standalone bundle.

Default local developer flow::

    python -m pip install -e '.[release]'
    python scripts/build_deb.py
    sudo apt install ./release/nightscout_<version>_<arch>.deb

If ``release/dist/nightscout`` does not exist, this script first invokes
``scripts/build_binary.py --keep-build``.  Pass ``--bundle`` to package an
already-built one-folder bundle directly.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from recon import __version__
from recon.tooling import PlatformInfo, assert_supported_platform

from scripts.build_binary import verify_bundle


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "nightscout"
INSTALL_ROOT = Path("usr/lib/nightscout")
COMMAND_LINK = Path("usr/bin/nightscout")


ARCH_MAP = {
    "x86_64": "amd64",
    "aarch64": "arm64",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def deb_architecture(platform_info: PlatformInfo) -> str:
    try:
        return ARCH_MAP[platform_info.architecture]
    except KeyError as exc:  # pragma: no cover - platform gate protects this
        raise ValueError(f"unsupported Debian architecture: {platform_info.architecture}") from exc


def detect_glibc_floor() -> str:
    """Return the build host glibc major.minor used as the package ABI floor."""

    candidates: list[str] = []
    confstr = getattr(os, "confstr", None)
    if confstr is not None:
        try:
            value = confstr("CS_GNU_LIBC_VERSION")
        except (OSError, ValueError):
            value = None
        if value:
            candidates.append(str(value))

    libc_name, libc_version = platform.libc_ver()
    if libc_name.lower() == "glibc" and libc_version:
        candidates.append(libc_version)

    for candidate in candidates:
        match = re.search(r"(?<!\d)(\d+)\.(\d+)", candidate)
        if match:
            return f"{match.group(1)}.{match.group(2)}"

    raise RuntimeError(
        "could not determine build-host glibc version; refusing to create a Debian package "
        "with an unknown runtime ABI floor"
    )


def build_control(
    *,
    version: str,
    architecture: str,
    installed_size_kib: int,
    glibc_floor: str,
) -> str:
    return "\n".join(
        [
            f"Package: {PACKAGE_NAME}",
            f"Version: {version}",
            "Section: utils",
            "Priority: optional",
            f"Architecture: {architecture}",
            "Maintainer: Night Scout Contributors",
            f"Depends: ca-certificates, libc6 (>= {glibc_floor})",
            "Suggests: sudo",
            f"Installed-Size: {installed_size_kib}",
            "Description: Recursive scope-aware reconnaissance orchestrator",
            " Night Scout coordinates authorized bug-bounty attack-surface discovery",
            " with persistent scope, policy, provenance, budgets, and specialist tools.",
            " The package contains the standalone Night Scout runtime; external",
            " reconnaissance tools are installed explicitly by 'nightscout setup'.",
            "",
        ]
    )


def installed_size_kib(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return max(1, (total + 1023) // 1024)


def stage_package(bundle: Path, stage_root: Path, *, architecture: str) -> Path:
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, mode=0o755)

    install_dir = stage_root / INSTALL_ROOT
    install_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bundle, install_dir, symlinks=True)

    command_path = stage_root / COMMAND_LINK
    command_path.parent.mkdir(parents=True, exist_ok=True)
    # Relative from /usr/bin/nightscout to /usr/lib/nightscout/nightscout.
    command_path.symlink_to("../lib/nightscout/nightscout")

    doc_dir = stage_root / "usr/share/doc/nightscout"
    doc_dir.mkdir(parents=True, exist_ok=True)
    for name in ("README.md", "README_RU.md"):
        source = PROJECT_ROOT / name
        if source.is_file():
            shutil.copy2(source, doc_dir / name)

    control_dir = stage_root / "DEBIAN"
    control_dir.mkdir(parents=True, mode=0o755)
    control = build_control(
        version=__version__,
        architecture=architecture,
        installed_size_kib=installed_size_kib(install_dir),
        glibc_floor=detect_glibc_floor(),
    )
    control_path = control_dir / "control"
    control_path.write_text(control, encoding="utf-8")
    control_path.chmod(0o644)

    return stage_root


def verify_deb(path: Path, *, architecture: str) -> None:
    if not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"Debian package was not created: {path}")

    fields = subprocess.run(
        ["dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if fields.returncode != 0:
        raise RuntimeError(f"dpkg-deb --field failed: {fields.stderr.strip()}")
    output = fields.stdout
    for expected in (PACKAGE_NAME, __version__, architecture):
        if expected not in output:
            raise RuntimeError(f"package metadata missing {expected!r}: {output!r}")

    contents = subprocess.run(
        ["dpkg-deb", "--contents", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if contents.returncode != 0:
        raise RuntimeError(f"dpkg-deb --contents failed: {contents.stderr.strip()}")
    listing = contents.stdout
    if "./usr/lib/nightscout/nightscout" not in listing:
        raise RuntimeError("package is missing /usr/lib/nightscout/nightscout")
    if "./usr/bin/nightscout" not in listing:
        raise RuntimeError("package is missing /usr/bin/nightscout")


def build_deb_package(
    *,
    bundle: Path,
    output_dir: Path,
    platform_info: PlatformInfo | None = None,
) -> Path:
    platform_info = platform_info or assert_supported_platform()
    architecture = deb_architecture(platform_info)
    output_dir.mkdir(parents=True, exist_ok=True)

    verify_bundle(bundle)
    if shutil.which("dpkg-deb") is None:
        raise RuntimeError("dpkg-deb is required; install the Debian 'dpkg' package")

    package_path = output_dir / f"nightscout_{__version__}_{architecture}.deb"
    with tempfile.TemporaryDirectory(prefix="nightscout-deb-") as tmp:
        stage_root = Path(tmp) / "package"
        stage_package(bundle, stage_root, architecture=architecture)
        result = subprocess.run(
            [
                "dpkg-deb",
                "--root-owner-group",
                "--build",
                str(stage_root),
                str(package_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "dpkg-deb build failed: "
                + " ".join((result.stdout + " " + result.stderr).strip().split())
            )

    verify_deb(package_path, architecture=architecture)
    digest = sha256_file(package_path)
    checksum_path = package_path.with_suffix(package_path.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {package_path.name}\n", encoding="utf-8")
    return package_path


def _build_binary(output_dir: Path) -> None:
    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "build_binary.py"),
        "--output",
        str(output_dir),
    ]
    subprocess.run(command, cwd=PROJECT_ROOT, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "release")
    parser.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="Existing PyInstaller onedir bundle. Defaults to <output>/dist/nightscout.",
    )
    parser.add_argument(
        "--no-build-binary",
        action="store_true",
        help="Fail instead of invoking build_binary.py when the bundle is missing.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    platform_info = assert_supported_platform()
    output = args.output.expanduser().resolve()
    bundle = (
        args.bundle.expanduser().resolve()
        if args.bundle is not None
        else output / "dist" / "nightscout"
    )

    if args.dry_run:
        architecture = deb_architecture(platform_info)
        print(f"bundle={bundle}")
        print(f"output={output / f'nightscout_{__version__}_{architecture}.deb'}")
        print("install: sudo apt install ./<deb-file>")
        return 0

    if not bundle.is_dir():
        if args.no_build_binary or args.bundle is not None:
            raise SystemExit(f"standalone bundle not found: {bundle}")
        _build_binary(output)

    package_path = build_deb_package(
        bundle=bundle,
        output_dir=output,
        platform_info=platform_info,
    )
    checksum_path = package_path.with_suffix(package_path.suffix + ".sha256")
    print(package_path)
    print(checksum_path)
    print(f"install: sudo apt install ./{package_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
