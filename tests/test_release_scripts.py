from __future__ import annotations

from pathlib import Path

from scripts.build_binary import pyinstaller_command


def test_pyinstaller_command_is_onedir_and_bundles_runtime_data(tmp_path: Path) -> None:
    command = pyinstaller_command(
        dist_dir=tmp_path / "dist",
        work_dir=tmp_path / "build",
        spec_dir=tmp_path / "spec",
    )
    joined = " ".join(command)
    assert "--onedir" in command
    assert "--onefile" not in command
    assert "configs:configs" in joined
    assert "migrations:migrations" in joined
    assert "wordlists:wordlists" in joined
    assert "tools_manifest.yaml:scripts" in joined
    assert "--hidden-import logging.config" in joined


def test_release_workflow_builds_installs_and_publishes_deb() -> None:
    workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "scripts/build_deb.py" in workflow
    assert "apt-get install -y ./release/nightscout_*.deb" in workflow
    assert "nightscout setup --skip-tools --skip-wordlists" in workflow
    assert 'gh release create "$tag"' in workflow
    assert "release/nightscout_*.deb.sha256" in workflow
