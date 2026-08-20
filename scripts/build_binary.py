#!/usr/bin/env python3
"""Build a Debian/Kali standalone Night Scout one-folder distribution.

The build intentionally uses PyInstaller ``--onedir`` rather than ``--onefile``.
External specialist tools are NOT bundled; they are managed separately by
``nightscout tools install``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import argparse
import hashlib
import os
import shutil
import subprocess
import tarfile

from recon import __version__
from recon.tooling import assert_supported_platform


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def pyinstaller_command(*, dist_dir: Path, work_dir: Path, spec_dir: Path) -> list[str]:
    entry = PROJECT_ROOT / "recon" / "__main__.py"
    data_args = [
        (PROJECT_ROOT / "configs", "configs"),
        (PROJECT_ROOT / "migrations", "migrations"),
        (PROJECT_ROOT / "wordlists", "wordlists"),
        (PROJECT_ROOT / "scripts" / "tools_manifest.yaml", "scripts"),
    ]

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        "nightscout",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        "--hidden-import",
        "aiosqlite",
        "--hidden-import",
        "logging.config",
        "--hidden-import",
        "sqlalchemy.dialects.sqlite.aiosqlite",
        "--collect-submodules",
        "alembic",
        "--collect-submodules",
        "sqlalchemy",
    ]

    for source, destination in data_args:
        command.extend(["--add-data", f"{source}:{destination}"])

    command.append(str(entry))
    return command


def copy_user_facing_files(bundle: Path) -> None:
    examples = bundle / "examples"
    examples.mkdir(parents=True, exist_ok=True)
    shutil.copy2(PROJECT_ROOT / "configs" / "pipeline.example.yaml", examples / "pipeline.example.yaml")
    shutil.copy2(PROJECT_ROOT / "configs" / "scope.example.yaml", examples / "scope.example.yaml")
    shutil.copy2(
        PROJECT_ROOT / "configs" / "nuclei-templates.example.yaml",
        examples / "nuclei-templates.example.yaml",
    )
    shutil.copy2(PROJECT_ROOT / "README.md", bundle / "README.md")
    if (PROJECT_ROOT / "README_RU.md").is_file():
        shutil.copy2(PROJECT_ROOT / "README_RU.md", bundle / "README_RU.md")
    shutil.copy2(PROJECT_ROOT / "scripts" / "tools_manifest.yaml", bundle / "tools_manifest.yaml")


def verify_bundle(bundle: Path) -> None:
    binary = bundle / "nightscout"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"standalone executable missing: {binary}")

    version = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if version.returncode != 0 or "Night Scout" not in version.stdout:
        raise RuntimeError(f"standalone --version failed: {version.stdout} {version.stderr}")

    tools = subprocess.run(
        [str(binary), "tools", "list", "--json"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if tools.returncode != 0 or '"tools"' not in tools.stdout:
        raise RuntimeError(f"standalone tools manifest check failed: {tools.stdout} {tools.stderr}")


def create_tarball(bundle: Path, output_dir: Path, *, arch: str) -> Path:
    name = f"nightscout-{__version__}-debian-kali-{arch}"
    staged = output_dir / name
    if staged.exists():
        shutil.rmtree(staged)
    shutil.copytree(bundle, staged, symlinks=True)

    tar_path = output_dir / f"{name}.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    with tarfile.open(tar_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.add(staged, arcname=name, recursive=True)
    shutil.rmtree(staged)
    return tar_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "release")
    parser.add_argument("--keep-build", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    platform_info = assert_supported_platform()
    output = args.output.expanduser().resolve()
    dist_dir = output / "dist"
    work_dir = output / "build"
    spec_dir = output / "spec"
    for directory in (dist_dir, work_dir, spec_dir):
        directory.mkdir(parents=True, exist_ok=True)

    command = pyinstaller_command(dist_dir=dist_dir, work_dir=work_dir, spec_dir=spec_dir)
    if args.dry_run:
        print(" ".join(command))
        return 0

    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise SystemExit(
            "PyInstaller is not installed. Install the release extra: "
            "python -m pip install -e '.[release]'"
        ) from exc

    subprocess.run(command, cwd=PROJECT_ROOT, check=True)
    bundle = dist_dir / "nightscout"
    copy_user_facing_files(bundle)
    verify_bundle(bundle)

    tar_path = create_tarball(bundle, output, arch=platform_info.architecture)
    digest = sha256_file(tar_path)
    (tar_path.with_suffix(tar_path.suffix + ".sha256")).write_text(
        f"{digest}  {tar_path.name}\n", encoding="utf-8"
    )

    print(tar_path)
    print(f"sha256={digest}")

    if not args.keep_build:
        shutil.rmtree(work_dir, ignore_errors=True)
        shutil.rmtree(spec_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
