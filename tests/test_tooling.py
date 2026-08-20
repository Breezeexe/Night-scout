from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from recon.tooling import (
    InstallStrategy,
    PlatformInfo,
    ToolingError,
    assert_supported_platform,
    format_asset_regex,
    load_tools_manifest,
    select_tools,
    _safe_archive_path,
)


def test_tools_manifest_loads_and_covers_runtime_tools() -> None:
    manifest = load_tools_manifest()
    by_id = manifest.by_id()
    expected = {
        "pdtm",
        "subfinder",
        "dnsx",
        "httpx",
        "tlsx",
        "asnmap",
        "katana",
        "urlfinder",
        "nuclei",
        "arjun",
        "jadx",
        "apktool",
        "gitleaks",
        "trufflehog",
    }
    assert expected == set(by_id)


def test_default_selection_excludes_optional_pdtm_helper() -> None:
    manifest = load_tools_manifest()
    selected = select_tools(manifest)
    ids = [tool.tool_id for tool in selected]
    assert "pdtm" not in ids
    assert "subfinder" in ids
    assert "arjun" in ids
    assert "jadx" not in ids


def test_required_projectdiscovery_tools_use_verified_github_releases() -> None:
    manifest = load_tools_manifest()
    by_id = manifest.by_id()

    for tool_id in (
        "subfinder",
        "dnsx",
        "httpx",
        "tlsx",
        "asnmap",
        "katana",
        "urlfinder",
        "nuclei",
    ):
        spec = by_id[tool_id]
        assert spec.strategy is InstallStrategy.GITHUB_BINARY
        assert spec.repository == f"projectdiscovery/{tool_id}"
        assert spec.asset_regex
        assert spec.checksum_asset_regex


@pytest.mark.parametrize(
    ("tool_id", "version_output"),
    (
        ("dnsx", "projectdiscovery.io\n[INF] Current Version: 1.3.0\n"),
        ("asnmap", "[INF] Current Version: v1.1.1\n"),
    ),
)
def test_projectdiscovery_version_and_help_identity_probes(
    monkeypatch,
    tmp_path,
    tool_id,
    version_output,
) -> None:
    import recon.tooling as tooling

    manifest = load_tools_manifest()
    spec = manifest.by_id()[tool_id]
    binary = tmp_path / tool_id
    binary.write_text("placeholder", encoding="utf-8")
    binary.chmod(0o755)

    monkeypatch.setattr(tooling, "resolve_binary", lambda _binary, _manifest=None: str(binary))

    def fake_run(command, **_kwargs):
        if command[-1] == "-version":
            return SimpleNamespace(returncode=0, stdout=version_output, stderr="")
        assert command[-1] == "-h"
        return SimpleNamespace(
            returncode=0,
            stdout=f"{tool_id} is a ProjectDiscovery command\nUsage: {tool_id} [flags]\n",
            stderr="",
        )

    monkeypatch.setattr(
        tooling.subprocess,
        "run",
        fake_run,
    )

    status = tooling.probe_tool(spec, manifest)

    assert status.installed is True
    assert status.identity_ok is True


def test_apt_candidate_probe_forces_machine_locale(monkeypatch) -> None:
    import recon.tooling as tooling

    monkeypatch.setattr(tooling.shutil, "which", lambda binary: f"/usr/bin/{binary}")

    def fake_run(command, **kwargs):
        assert command == ["/usr/bin/apt-cache", "policy", "dnsx"]
        assert kwargs["env"]["LC_ALL"] == "C"
        assert kwargs["env"]["LANG"] == "C"
        return SimpleNamespace(
            returncode=0,
            stdout="dnsx:\n  Installed: 1.3.0-0kali1\n  Candidate: 1.3.0-0kali1\n",
        )

    monkeypatch.setattr(tooling.subprocess, "run", fake_run)

    assert tooling._apt_candidate_available("dnsx") is True


def test_apt_allowlist_handles_kali_httpx_name_collision() -> None:
    manifest = load_tools_manifest()
    by_id = manifest.by_id()
    assert by_id["subfinder"].apt["kali"].package == "subfinder"
    assert by_id["httpx"].apt["kali"].package == "httpx-toolkit"
    assert by_id["httpx"].apt["kali"].binary == "httpx-toolkit"
    # Debian intentionally has no guessed httpx APT mapping: python-httpx would
    # be the wrong executable for Night Scout.
    assert "debian" not in by_id["httpx"].apt


def test_linux_asset_regex_arch_substitution() -> None:
    manifest = load_tools_manifest()
    pdtm = manifest.by_id()["pdtm"]
    info = PlatformInfo(
        os_id="debian",
        pretty_name="Debian",
        version_id="13",
        architecture="x86_64",
        goarch="amd64",
        asset_arch="x64",
    )
    pattern = format_asset_regex(pdtm.asset_regex or "", info)
    import re

    assert re.search(pattern, "pdtm_0.1.3_linux_amd64.zip", re.IGNORECASE)
    assert not re.search(pattern, "pdtm_0.1.3_windows_amd64.zip", re.IGNORECASE)


def test_archive_path_traversal_is_rejected() -> None:
    assert _safe_archive_path("bin/tool").as_posix() == "bin/tool"
    with pytest.raises(ToolingError):
        _safe_archive_path("../escape")
    with pytest.raises(ToolingError):
        _safe_archive_path("/absolute")


def test_platform_gate_accepts_debian_rejects_ubuntu() -> None:
    debian = PlatformInfo(
        os_id="debian",
        pretty_name="Debian GNU/Linux",
        version_id="13",
        architecture="x86_64",
        goarch="amd64",
        asset_arch="x64",
    )
    assert assert_supported_platform(debian) == debian

    ubuntu = debian.model_copy(update={"os_id": "ubuntu", "pretty_name": "Ubuntu"})
    with pytest.raises(Exception):
        assert_supported_platform(ubuntu)


def test_apt_first_installs_allowlisted_package_before_upstream(monkeypatch, tmp_path) -> None:
    import recon.tooling as tooling

    manifest = load_tools_manifest()
    spec = manifest.by_id()["subfinder"]
    platform_info = PlatformInfo(
        os_id="kali",
        pretty_name="Kali GNU/Linux Rolling",
        version_id=None,
        architecture="x86_64",
        goarch="amd64",
        asset_arch="x64",
    )
    monkeypatch.setenv("NIGHTSCOUT_TOOL_ROOT", str(tmp_path / "tools"))
    monkeypatch.setattr(tooling, "_privilege_prefix", lambda: [])
    monkeypatch.setattr(tooling, "_apt_candidate_available", lambda package: package == "subfinder")

    calls: list[tuple[str, ...]] = []

    def fake_run(command, **kwargs):
        calls.append(tuple(str(item) for item in command))
        return SimpleNamespace(returncode=0)

    real_which = tooling.shutil.which

    def fake_which(binary):
        if binary == "subfinder":
            return "/usr/bin/subfinder"
        return real_which(binary)

    monkeypatch.setattr(tooling.subprocess, "run", fake_run)
    monkeypatch.setattr(tooling.shutil, "which", fake_which)
    monkeypatch.setattr(
        tooling,
        "probe_tool",
        lambda _spec, _manifest=None: tooling.ToolStatus(
            tool_id="subfinder",
            binary="subfinder",
            installed=True,
            required=True,
            path="/usr/bin/subfinder",
            version="subfinder v2.14.0",
            identity_ok=True,
            detail="subfinder v2.14.0",
        ),
    )

    result = tooling._try_install_with_apt(
        spec,
        manifest,
        platform_info=platform_info,
        apt_session=tooling._AptSession(),
    )

    assert result is not None
    assert result.source == "apt:kali:subfinder"
    assert not any("update" in command for command in calls)
    assert any(command[-3:] == ("--no-install-recommends", "subfinder")[-3:] for command in calls) or any(
        "install" in command and "subfinder" in command for command in calls
    )


def test_apt_first_does_not_guess_unmapped_debian_projectdiscovery_package() -> None:
    manifest = load_tools_manifest()
    for tool_id in ("subfinder", "dnsx", "httpx", "nuclei"):
        assert "debian" not in manifest.by_id()[tool_id].apt
