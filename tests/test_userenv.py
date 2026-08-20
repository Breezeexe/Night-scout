from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from recon.cli import _prepare_default_scope_for_run
from recon.runtime import load_runtime_configuration
from recon.userenv import (
    initialize_user_environment,
    preferred_pipeline_path,
    user_paths,
)


def _set_xdg(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))


def test_setup_creates_fail_closed_user_environment(monkeypatch, tmp_path: Path) -> None:
    _set_xdg(monkeypatch, tmp_path)
    paths = initialize_user_environment()

    assert paths.pipeline_path.is_file()
    assert paths.scope_path.is_file()
    assert paths.data_root.is_dir()
    assert paths.cache_root.is_dir()

    scope = yaml.safe_load(paths.scope_path.read_text(encoding="utf-8"))
    assert scope["rules"] == []
    assert scope["gate"]["allow_unknown_passive"] is False

    pipeline = yaml.safe_load(paths.pipeline_path.read_text(encoding="utf-8"))
    assert pipeline["scope_file"] == "scope.yaml"
    assert pipeline["storage"]["database"]["path"] == "nightscout.sqlite3"
    assert pipeline["storage"]["sensitive_evidence"]["root"] == "sensitive-evidence"

    cfg = load_runtime_configuration(pipeline_path=paths.pipeline_path)
    assert cfg.scope_path == paths.scope_path
    assert cfg.workspace_root == paths.data_root
    # Bundled/source resources do not get re-rooted into ~/.config/nightscout.
    assert cfg.resolve_resource("wordlists/manifest.yaml").is_file()


def test_noninteractive_scope_flags_add_only_explicit_rules(monkeypatch, tmp_path: Path) -> None:
    _set_xdg(monkeypatch, tmp_path)
    paths = initialize_user_environment()

    _prepare_default_scope_for_run(
        target="example.org",
        pipeline=paths.pipeline_path,
        scope=None,
        authorize_exact=False,
        authorize_subdomains=True,
    )

    payload = yaml.safe_load(paths.scope_path.read_text(encoding="utf-8"))
    rules = {(item["kind"], item["pattern"], item["state"]) for item in payload["rules"]}
    assert ("DOMAIN", "example.org", "IN_SCOPE") in rules
    assert ("DOMAIN", "*.example.org", "IN_SCOPE") in rules
    assert len(rules) == 2

    # A second invocation is idempotent rather than duplicating authorization.
    _prepare_default_scope_for_run(
        target="example.org",
        pipeline=paths.pipeline_path,
        scope=None,
        authorize_exact=False,
        authorize_subdomains=True,
    )
    payload = yaml.safe_load(paths.scope_path.read_text(encoding="utf-8"))
    assert len(payload["rules"]) == 2


def test_user_paths_follow_xdg(monkeypatch, tmp_path: Path) -> None:
    _set_xdg(monkeypatch, tmp_path)
    paths = user_paths()
    assert paths.config_root == (tmp_path / "config" / "nightscout").resolve()
    assert paths.data_root == (tmp_path / "data" / "nightscout").resolve()
    assert paths.cache_root == (tmp_path / "cache" / "nightscout").resolve()


def test_runtime_configuration_never_falls_back_to_bundled_examples(
    monkeypatch,
    tmp_path: Path,
    project_root: Path,
) -> None:
    """Operational defaults must remain inert before explicit setup/scope."""
    _set_xdg(monkeypatch, tmp_path)

    expected = user_paths().pipeline_path
    assert preferred_pipeline_path() == expected
    assert not expected.exists()

    with pytest.raises(ValueError, match="example pipeline is a template"):
        load_runtime_configuration(
            pipeline_path=project_root / "configs" / "pipeline.example.yaml"
        )

    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text(
            encoding="utf-8"
        )
    )
    pipeline["scope_file"] = str(
        project_root / "configs" / "scope.example.yaml"
    )
    explicit_example = tmp_path / "explicit-example-scope-pipeline.yaml"
    explicit_example.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="example scope is a template"):
        load_runtime_configuration(pipeline_path=explicit_example)

    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline_path = tmp_path / "pipeline.yaml"
    pipeline_path.write_text(
        yaml.safe_dump(pipeline, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(FileNotFoundError, match="scope config not found"):
        load_runtime_configuration(pipeline_path=pipeline_path)
