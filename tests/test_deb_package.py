from __future__ import annotations

import os
import subprocess
from pathlib import Path

from recon import __version__
from recon.tooling import PlatformInfo
from scripts.build_deb import build_deb_package


def _fake_bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    binary = bundle / "nightscout"
    binary.write_text(
        """#!/bin/sh
if [ \"$1\" = \"--version\" ]; then
  echo \"Night Scout 0.1.0\"
  exit 0
fi
if [ \"$1\" = \"tools\" ] && [ \"$2\" = \"list\" ]; then
  echo '{\"tools\":[{\"tool_id\":\"subfinder\"}]}'
  exit 0
fi
exit 2
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    (bundle / "_internal").mkdir()
    return bundle


def test_build_deb_packages_onedir_bundle_and_command_symlink(tmp_path: Path) -> None:
    platform_info = PlatformInfo(
        os_id="debian",
        pretty_name="Debian GNU/Linux",
        version_id="13",
        architecture="x86_64",
        goarch="amd64",
        asset_arch="x86_64",
    )
    package = build_deb_package(
        bundle=_fake_bundle(tmp_path),
        output_dir=tmp_path / "release",
        platform_info=platform_info,
    )

    assert package.name == f"nightscout_{__version__}_amd64.deb"
    assert package.with_suffix(".deb.sha256").is_file()

    fields = subprocess.check_output(
        ["dpkg-deb", "--field", str(package), "Package", "Architecture", "Depends"],
        text=True,
    )
    assert "nightscout" in fields
    assert "amd64" in fields
    assert "ca-certificates" in fields
    assert "libc6 (>= " in fields

    extracted = tmp_path / "extracted"
    subprocess.run(["dpkg-deb", "--extract", str(package), str(extracted)], check=True)
    installed = extracted / "usr/lib/nightscout/nightscout"
    command = extracted / "usr/bin/nightscout"
    assert installed.is_file()
    assert os.access(installed, os.X_OK)
    assert command.is_symlink()
    assert os.readlink(command) == "../lib/nightscout/nightscout"
