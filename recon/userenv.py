"""Per-user Night Scout configuration and workspace bootstrap.

Night Scout is installed system-wide by the Debian package, but mutable state
belongs to the invoking user.  The default layout follows the XDG base
specification on Debian/Kali::

    ~/.config/nightscout/
        pipeline.yaml
        scope.yaml
    ~/.local/share/nightscout/
        nightscout.sqlite3
        events.jsonl
        ...
    ~/.cache/nightscout/

`nightscout setup` initializes these files.  Scope starts empty and therefore
fails closed until the user explicitly authorizes a target (or supplies a
custom --scope file).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from recon.resources import default_pipeline_path, resource_path


class UserPaths(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_root: Path
    data_root: Path
    cache_root: Path
    pipeline_path: Path
    scope_path: Path
    wordlists_root: Path
    wordlists_manifest: Path
    wordlists_lock: Path


def _xdg_root(env_name: str, fallback: Path) -> Path:
    raw = os.environ.get(env_name, "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return fallback.expanduser().resolve()


def user_paths() -> UserPaths:
    home = Path.home()
    config_root = _xdg_root("XDG_CONFIG_HOME", home / ".config") / "nightscout"
    data_root = _xdg_root("XDG_DATA_HOME", home / ".local" / "share") / "nightscout"
    cache_root = _xdg_root("XDG_CACHE_HOME", home / ".cache") / "nightscout"
    return UserPaths(
        config_root=config_root,
        data_root=data_root,
        cache_root=cache_root,
        pipeline_path=config_root / "pipeline.yaml",
        scope_path=config_root / "scope.yaml",
        wordlists_root=data_root / "wordlists",
        wordlists_manifest=data_root / "wordlists" / "generated" / "manifest.local.yaml",
        wordlists_lock=data_root / "wordlists" / "generated" / "sources.lock.yaml",
    )


def preferred_pipeline_path() -> Path:
    """Return the managed user pipeline path, whether or not setup ran.

    Bundled example configuration is a template, not an execution default.
    Returning the expected user path makes every operational command fail
    closed with a useful ``FileNotFoundError`` until ``nightscout setup`` has
    created an explicit local policy.
    """
    return user_paths().pipeline_path


def is_default_user_pipeline(path: str | Path) -> bool:
    try:
        return Path(path).expanduser().resolve() == user_paths().pipeline_path.resolve()
    except OSError:
        return False


def initialize_user_environment(*, force: bool = False) -> UserPaths:
    """Create default per-user config/state directories without authorizing scope."""

    paths = user_paths()
    for directory in (paths.config_root, paths.data_root, paths.cache_root):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)

    refresh_user_wordlist_resources(paths)

    if force or not paths.pipeline_path.exists():
        pipeline = _load_yaml(default_pipeline_path())
        _prepare_user_pipeline(pipeline, paths)
        _atomic_write_yaml(paths.pipeline_path, pipeline, mode=0o600)

    if force or not paths.scope_path.exists():
        scope: dict[str, Any] = {
            "schema_version": 1,
            "target_id": "local-authorized-targets",
            "display_name": "Night Scout local authorized targets",
            "gate": {"allow_unknown_passive": False},
            "rules": [],
        }
        _atomic_write_yaml(paths.scope_path, scope, mode=0o600)

    return paths


def refresh_user_wordlist_resources(paths: UserPaths | None = None) -> UserPaths:
    """Refresh bundled base wordlists while preserving downloaded cache/lock data."""

    paths = paths or user_paths()
    source_root = resource_path("wordlists")
    if not source_root.is_dir():
        raise FileNotFoundError(f"bundled wordlists directory not found: {source_root}")

    paths.wordlists_root.mkdir(parents=True, exist_ok=True)
    (paths.wordlists_root / "cache").mkdir(parents=True, exist_ok=True)
    (paths.wordlists_root / "generated").mkdir(parents=True, exist_ok=True)
    os.chmod(paths.wordlists_root, 0o700)

    for name in ("manifest.yaml", "sources.yaml"):
        source = source_root / name
        if source.is_file():
            shutil.copy2(source, paths.wordlists_root / name)

    source_builtins = source_root / "builtins"
    destination_builtins = paths.wordlists_root / "builtins"
    if destination_builtins.exists():
        shutil.rmtree(destination_builtins)
    shutil.copytree(source_builtins, destination_builtins)

    # Before the first external sync, the generated manifest is simply the
    # bundled baseline.  setup/wordlists sync may rebuild it from the lock.
    if not paths.wordlists_manifest.exists():
        shutil.copy2(paths.wordlists_root / "manifest.yaml", paths.wordlists_manifest)

    return paths


def add_confirmed_domain_scope(
    domain: str,
    *,
    include_subdomains: bool = False,
    scope_path: str | Path | None = None,
) -> tuple[str, ...]:
    """Persist explicit user confirmation for one exact domain and optional wildcard.

    This helper is intentionally limited to the default local scope file. It
    does not infer authorization from DNS, certificates, IPs, or relationships.
    """

    normalized = _normalize_domain(domain)
    path = Path(scope_path).expanduser().resolve() if scope_path else user_paths().scope_path
    payload = _load_yaml(path)
    rules = payload.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("scope rules must be a list")

    added: list[str] = []
    existing = {
        (str(item.get("kind", "")), str(item.get("pattern", "")))
        for item in rules
        if isinstance(item, dict)
    }

    exact_key = ("DOMAIN", normalized)
    if exact_key not in existing:
        rule_id = _scope_rule_id(normalized, "exact")
        rules.append(
            {
                "rule_id": rule_id,
                "kind": "DOMAIN",
                "pattern": normalized,
                "state": "IN_SCOPE",
                "priority": 100,
                "tier": "user-confirmed",
                "reason": "User explicitly confirmed this exact domain via Night Scout CLI",
            }
        )
        added.append(rule_id)

    if include_subdomains:
        wildcard = f"*.{normalized}"
        wildcard_key = ("DOMAIN", wildcard)
        if wildcard_key not in existing:
            rule_id = _scope_rule_id(normalized, "wildcard")
            rules.append(
                {
                    "rule_id": rule_id,
                    "kind": "DOMAIN",
                    "pattern": wildcard,
                    "state": "IN_SCOPE",
                    "priority": 100,
                    "tier": "user-confirmed",
                    "reason": (
                        "User explicitly confirmed all subdomains of this domain "
                        "via Night Scout CLI"
                    ),
                }
            )
            added.append(rule_id)

    _atomic_write_yaml(path, payload, mode=0o600)
    return tuple(added)


def _prepare_user_pipeline(payload: dict[str, Any], paths: UserPaths) -> None:
    payload["profile_id"] = "default-balanced"
    payload["display_name"] = "Night Scout default authorized recon pipeline"
    payload["scope_file"] = "scope.yaml"

    storage = payload.setdefault("storage", {})
    storage.setdefault("database", {})["path"] = "nightscout.sqlite3"
    storage.setdefault("event_log", {})["path"] = "events.jsonl"
    storage.setdefault("content_store", {})["root"] = "content"
    storage.setdefault("artifact_store", {})["root"] = "artifacts"
    storage.setdefault("sensitive_evidence", {})["root"] = "sensitive-evidence"

    workers = payload.setdefault("workers", {})
    mobile = workers.get("mobile")
    if isinstance(mobile, dict):
        config = mobile.get("config")
        if isinstance(config, dict) and "sensitive_evidence_root" in config:
            config["sensitive_evidence_root"] = "sensitive-evidence"

    intelligence = payload.setdefault("intelligence", {})
    wordlists = intelligence.get("wordlists")
    if isinstance(wordlists, dict):
        wordlists["manifest"] = str(paths.wordlists_manifest)
        wordlists["corpus_root"] = str(paths.wordlists_root)

    vulnerabilities = intelligence.get("vulnerabilities")
    if isinstance(vulnerabilities, dict) and "nvd_cache_path" in vulnerabilities:
        vulnerabilities["nvd_cache_path"] = "cache/nvd.sqlite3"


def _load_yaml(path: str | Path) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    loaded = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"YAML root must be an object: {resolved}")
    return loaded


def _atomic_write_yaml(path: Path, payload: dict[str, Any], *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(
                payload,
                handle,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    if not candidate or "/" in candidate or ":" in candidate or " " in candidate:
        raise ValueError("target must be a bare DNS domain")
    try:
        ascii_value = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid DNS domain") from exc
    labels = ascii_value.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise ValueError("target must be a valid DNS domain")
    return ascii_value


def _scope_rule_id(domain: str, suffix: str) -> str:
    digest = hashlib.sha256(f"{domain}|{suffix}".encode("utf-8")).hexdigest()[:12]
    return f"cli-{suffix}-{digest}"
