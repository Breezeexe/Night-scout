from __future__ import annotations

from pathlib import Path

import pytest

from recon.tooling import (
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


def test_default_selection_includes_pdtm_dependency() -> None:
    manifest = load_tools_manifest()
    selected = select_tools(manifest)
    ids = [tool.tool_id for tool in selected]
    assert "pdtm" in ids
    assert "subfinder" in ids
    assert "arjun" in ids
    assert "jadx" not in ids


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
