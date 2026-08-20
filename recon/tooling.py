"""Linux-only external tool management for Night Scout.

Night Scout supports only Debian GNU/Linux and Kali Linux. Specialist tools are
installed into an isolated per-user directory by default so the runtime does
not need to mutate /usr/local/bin or overwrite distribution packages.

Managed layout::

    ~/.local/share/nightscout/tools/
    ├── bin/
    ├── apps/
    ├── downloads/
    └── tools.lock.yaml

The runtime prepends ``bin/`` to PATH automatically. Installation is APT-first
for explicitly allow-listed Debian/Kali packages.  Night Scout verifies binary
identity after package installation and uses PDTM/pipx/official GitHub releases
only as upstream fallbacks.

No target identifiers or reconnaissance data are sent to these upstreams.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.resources import default_tools_manifest_path


GITHUB_API = "https://api.github.com"
DEFAULT_MANAGED_ROOT = Path("~/.local/share/nightscout/tools")
SUPPORTED_OS_IDS = frozenset({"debian", "kali"})
SUPPORTED_ARCHES = frozenset({"x86_64", "aarch64"})
MAX_RELEASE_JSON_BYTES = 8 * 1024 * 1024
MAX_ASSET_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 200_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
APT_UPDATE_TIMEOUT_SECONDS = 300
APT_INSTALL_TIMEOUT_SECONDS = 900
PDTM_TIMEOUT_SECONDS = 300


class ToolingError(RuntimeError):
    pass


class UnsupportedPlatformError(ToolingError):
    pass


class InstallStrategy(StrEnum):
    PDTM = "pdtm"
    PIPX = "pipx"
    GITHUB_BINARY = "github_binary"
    GITHUB_ARCHIVE_APP = "github_archive_app"
    GITHUB_JAR = "github_jar"


class ToolRequirement(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"


class AptPackageSpec(BaseModel):
    """Allow-listed distro package for one Night Scout tool.

    ``binary`` may differ from the Night Scout-facing binary name.  Kali, for
    example, packages ProjectDiscovery httpx as ``httpx-toolkit`` to avoid the
    Python-httpx name collision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    package: str
    binary: str

    @field_validator("package", "binary")
    @classmethod
    def apt_nonempty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized


class PlatformInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    os_id: str
    pretty_name: str
    version_id: str | None = None
    architecture: str
    goarch: str
    asset_arch: str

    @property
    def supported(self) -> bool:
        return self.os_id in SUPPORTED_OS_IDS and self.architecture in SUPPORTED_ARCHES


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    binary: str
    requirement: ToolRequirement = ToolRequirement.REQUIRED
    workers: tuple[str, ...] = ()
    description: str = ""

    strategy: InstallStrategy

    project: str | None = None
    package: str | None = None
    repository: str | None = None

    asset_regex: str | None = None
    checksum_asset_regex: str | None = None
    entrypoint: str | None = None

    version_args: tuple[str, ...] = ("--version",)
    identity_regex: str | None = None

    prerequisite_commands: tuple[str, ...] = ()
    prerequisite_apt_packages: tuple[str, ...] = ()

    # Explicit per-distribution allow-list.  We never infer an APT package from
    # the tool ID because names can collide (notably ``httpx`` on Debian/Kali).
    apt: dict[str, AptPackageSpec] = Field(default_factory=dict)

    @field_validator("tool_id", "binary")
    @classmethod
    def nonempty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @model_validator(mode="after")
    def strategy_fields(self) -> "ToolSpec":
        if self.strategy is InstallStrategy.PDTM and not self.project:
            raise ValueError("pdtm tool requires project")
        if self.strategy is InstallStrategy.PIPX and not self.package:
            raise ValueError("pipx tool requires package")
        if self.strategy in {
            InstallStrategy.GITHUB_BINARY,
            InstallStrategy.GITHUB_ARCHIVE_APP,
            InstallStrategy.GITHUB_JAR,
        }:
            if not self.repository or not self.asset_regex:
                raise ValueError("GitHub strategy requires repository and asset_regex")
        if self.strategy is InstallStrategy.GITHUB_ARCHIVE_APP and not self.entrypoint:
            raise ValueError("github_archive_app requires entrypoint")
        unknown_apt_os = sorted(set(self.apt) - SUPPORTED_OS_IDS)
        if unknown_apt_os:
            raise ValueError(f"unsupported apt OS IDs: {', '.join(unknown_apt_os)}")
        return self


class ToolsManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1)
    supported_os_ids: tuple[str, ...] = ("debian", "kali")
    supported_arches: tuple[str, ...] = ("x86_64", "aarch64")
    managed_root: str = str(DEFAULT_MANAGED_ROOT)
    tools: tuple[ToolSpec, ...]

    @model_validator(mode="after")
    def unique_tools(self) -> "ToolsManifest":
        ids = [tool.tool_id for tool in self.tools]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate tool_id in tools manifest")
        binaries = [tool.binary for tool in self.tools]
        if len(binaries) != len(set(binaries)):
            raise ValueError("duplicate binary in tools manifest")
        return self

    def by_id(self) -> dict[str, ToolSpec]:
        return {tool.tool_id: tool for tool in self.tools}


class ToolStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    binary: str
    installed: bool
    required: bool
    path: str | None = None
    version: str | None = None
    identity_ok: bool = False
    detail: str = ""


class ToolInstallResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    installed: bool
    updated: bool = False
    skipped: bool = False
    path: str | None = None
    version: str | None = None
    sha256: str | None = None
    source: str | None = None
    detail: str = ""


class ToolInstallPhase(StrEnum):
    CHECKING = "checking"
    INSTALLING = "installing"
    VERIFYING = "verifying"
    COMPLETE = "complete"
    SKIPPED = "skipped"


class ToolInstallProgress(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    index: int = Field(ge=1)
    total: int = Field(ge=1)
    phase: ToolInstallPhase
    detail: str = ""


class ToolsLockEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    binary: str
    strategy: str
    path: str
    version: str | None = None
    sha256: str | None = None
    source: str | None = None
    installed_at: str


class ToolsLock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    platform: PlatformInfo
    entries: tuple[ToolsLockEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class GitHubAsset:
    name: str
    url: str
    size: int
    digest: str | None


@dataclass(frozen=True, slots=True)
class GitHubRelease:
    tag_name: str
    html_url: str
    assets: tuple[GitHubAsset, ...]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def detect_platform() -> PlatformInfo:
    os_release = read_os_release()
    os_id = os_release.get("ID", "").strip().lower()
    pretty_name = os_release.get("PRETTY_NAME", os_id or "unknown")
    version_id = os_release.get("VERSION_ID") or None
    architecture = platform.machine().strip().lower()

    arch_map = {
        "x86_64": ("amd64", "x64"),
        "amd64": ("amd64", "x64"),
        "aarch64": ("arm64", "arm64"),
        "arm64": ("arm64", "arm64"),
    }
    mapped = arch_map.get(architecture)
    if mapped is None:
        goarch = "unsupported"
        asset_arch = "unsupported"
    else:
        goarch, asset_arch = mapped
        architecture = "x86_64" if goarch == "amd64" else "aarch64"

    return PlatformInfo(
        os_id=os_id,
        pretty_name=pretty_name,
        version_id=version_id,
        architecture=architecture,
        goarch=goarch,
        asset_arch=asset_arch,
    )


def assert_supported_platform(info: PlatformInfo | None = None) -> PlatformInfo:
    info = info or detect_platform()
    if info.os_id not in SUPPORTED_OS_IDS:
        raise UnsupportedPlatformError(
            f"Night Scout supports only Debian and Kali Linux; detected {info.pretty_name!r}"
        )
    if info.architecture not in SUPPORTED_ARCHES:
        raise UnsupportedPlatformError(
            "Night Scout supports only x86_64 and aarch64 on Debian/Kali; "
            f"detected {info.architecture!r}"
        )
    return info


def load_tools_manifest(path: str | Path | None = None) -> ToolsManifest:
    manifest_path = Path(path or default_tools_manifest_path()).expanduser().resolve()
    if not manifest_path.is_file():
        raise FileNotFoundError(f"tools manifest not found: {manifest_path}")
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("tools manifest root must be a mapping")
    manifest = ToolsManifest.model_validate(raw)
    return manifest


def managed_root(manifest: ToolsManifest | None = None) -> Path:
    env = os.environ.get("NIGHTSCOUT_TOOL_ROOT", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    manifest = manifest or load_tools_manifest()
    return Path(manifest.managed_root).expanduser().resolve()


def managed_bin_dir(manifest: ToolsManifest | None = None) -> Path:
    return managed_root(manifest) / "bin"


def activate_managed_tool_path(manifest: ToolsManifest | None = None) -> Path:
    bin_dir = managed_bin_dir(manifest)
    current = os.environ.get("PATH", "")
    components = [item for item in current.split(os.pathsep) if item]
    bin_text = str(bin_dir)
    if bin_text not in components:
        os.environ["PATH"] = os.pathsep.join([bin_text, *components])
    return bin_dir


def resolve_binary(binary: str, manifest: ToolsManifest | None = None) -> str | None:
    bin_dir = managed_bin_dir(manifest)
    managed = bin_dir / binary
    if managed.is_file() and os.access(managed, os.X_OK):
        return str(managed)
    return shutil.which(binary)


def format_asset_regex(pattern: str, platform_info: PlatformInfo) -> str:
    return pattern.format(
        goarch=re.escape(platform_info.goarch),
        asset_arch=re.escape(platform_info.asset_arch),
        arch=re.escape(platform_info.architecture),
    )


def probe_tool(spec: ToolSpec, manifest: ToolsManifest | None = None) -> ToolStatus:
    resolved = resolve_binary(spec.binary, manifest)
    required = spec.requirement is ToolRequirement.REQUIRED
    if resolved is None:
        return ToolStatus(
            tool_id=spec.tool_id,
            binary=spec.binary,
            installed=False,
            required=required,
            detail="binary not found",
        )

    try:
        result = subprocess.run(
            [resolved, *spec.version_args],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
            env=_probe_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(
            tool_id=spec.tool_id,
            binary=spec.binary,
            installed=True,
            required=required,
            path=resolved,
            identity_ok=False,
            detail=f"probe failed: {type(exc).__name__}: {exc}",
        )

    output = " ".join((result.stdout + " " + result.stderr).strip().split())
    identity_ok = result.returncode == 0
    if spec.identity_regex:
        identity_ok = identity_ok and re.search(
            spec.identity_regex,
            output,
            flags=re.IGNORECASE,
        ) is not None

    return ToolStatus(
        tool_id=spec.tool_id,
        binary=spec.binary,
        installed=True,
        required=required,
        path=resolved,
        version=output[:500] or None,
        identity_ok=identity_ok,
        detail=(output[:500] if output else f"probe exit={result.returncode}"),
    )


def probe_all_tools(manifest: ToolsManifest | None = None) -> tuple[ToolStatus, ...]:
    manifest = manifest or load_tools_manifest()
    return tuple(probe_tool(spec, manifest) for spec in manifest.tools)


def tool_status_by_worker(
    worker: str,
    manifest: ToolsManifest | None = None,
) -> tuple[ToolStatus, ...]:
    manifest = manifest or load_tools_manifest()
    return tuple(
        probe_tool(spec, manifest)
        for spec in manifest.tools
        if worker in spec.workers
    )


def select_tools(
    manifest: ToolsManifest,
    *,
    requested: Sequence[str] = (),
    include_optional: bool = False,
    all_tools: bool = False,
) -> tuple[ToolSpec, ...]:
    by_id = manifest.by_id()
    if requested:
        unknown = sorted(set(requested) - set(by_id))
        if unknown:
            raise ToolingError(f"unknown tool IDs: {', '.join(unknown)}")
        selected = [by_id[item] for item in requested]
    elif all_tools:
        selected = list(manifest.tools)
    else:
        selected = [
            tool
            for tool in manifest.tools
            if tool.requirement is ToolRequirement.REQUIRED or include_optional
        ]

    deduped: list[ToolSpec] = []
    seen: set[str] = set()
    for tool in selected:
        if tool.tool_id in seen:
            continue
        seen.add(tool.tool_id)
        deduped.append(tool)
    return tuple(deduped)


class _AptSession:
    """One setup/install invocation worth of APT state."""

    def __init__(self) -> None:
        self.updated = False


def _privilege_prefix() -> list[str] | None:
    if os.geteuid() == 0:
        return []
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo]
    return None


def _apt_candidate_available(package: str) -> bool:
    apt_cache = shutil.which("apt-cache")
    if apt_cache is None:
        return False
    # apt-cache emits translated field names.  Parse a stable machine locale so
    # installations running under ru_RU and other non-English locales do not
    # mistake an available package for a missing one.
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"})
    result = subprocess.run(
        [apt_cache, "policy", package],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
        env=env,
    )
    if result.returncode != 0:
        return False
    return re.search(r"(?m)^\s*Candidate:\s*(?!\(none\))\S+", result.stdout) is not None


def _try_install_with_apt(
    spec: ToolSpec,
    manifest: ToolsManifest,
    *,
    platform_info: PlatformInfo,
    apt_session: _AptSession,
) -> ToolInstallResult | None:
    """Install an explicitly allow-listed distro package, or return ``None``.

    APT is deliberately not guessed from ``tool_id``.  This prevents installing
    unrelated packages with colliding names.  If the package is unavailable or
    sudo/root is unavailable, the caller falls back to the upstream strategy.
    """

    apt_spec = spec.apt.get(platform_info.os_id)
    if apt_spec is None:
        return None
    prefix = _privilege_prefix()
    if prefix is None:
        print(
            f"    apt: {apt_spec.package} is allow-listed, but sudo/root is unavailable; "
            "using upstream fallback",
            flush=True,
        )
        return None
    if not _apt_candidate_available(apt_spec.package):
        # Package lists may be stale. Refresh once, then check again.
        if not apt_session.updated:
            print("    apt: refreshing package metadata (apt-get update)...", flush=True)
            try:
                update = subprocess.run(
                    [*prefix, "apt-get", "update"],
                    check=False,
                    timeout=APT_UPDATE_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as exc:
                raise ToolingError(
                    f"apt-get update timed out after {APT_UPDATE_TIMEOUT_SECONDS}s; "
                    "refusing to hide the APT failure behind an upstream fallback"
                ) from exc
            if update.returncode != 0:
                raise ToolingError(
                    f"apt-get update failed with exit code {update.returncode}; "
                    "refusing to hide the APT failure behind an upstream fallback"
                )
            apt_session.updated = True
        if not _apt_candidate_available(apt_spec.package):
            print(
                f"    apt: no candidate for {apt_spec.package} after metadata refresh",
                flush=True,
            )
            return None

    print(f"    apt: installing {apt_spec.package}...", flush=True)
    try:
        install = subprocess.run(
            [*prefix, "apt-get", "install", "-y", "--no-install-recommends", apt_spec.package],
            check=False,
            timeout=APT_INSTALL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolingError(
            f"APT installation of {apt_spec.package} timed out after "
            f"{APT_INSTALL_TIMEOUT_SECONDS}s"
        ) from exc
    if install.returncode != 0:
        raise ToolingError(
            f"APT installation of {apt_spec.package} failed with exit code "
            f"{install.returncode}"
        )

    actual = shutil.which(apt_spec.binary)
    if actual is None:
        return None

    # If the distro intentionally renames the executable, expose a managed
    # compatibility symlink under the binary name expected by Night Scout.
    if apt_spec.binary != spec.binary:
        _atomic_symlink(Path(actual).resolve(), managed_bin_dir(manifest) / spec.binary)

    verified = probe_tool(spec, manifest)
    if not verified.installed or not verified.identity_ok:
        return None

    return ToolInstallResult(
        tool_id=spec.tool_id,
        installed=True,
        path=verified.path,
        version=verified.version,
        source=f"apt:{platform_info.os_id}:{apt_spec.package}",
        detail=f"installed from {platform_info.os_id} APT package {apt_spec.package}",
    )


def install_tools(
    *,
    manifest_path: str | Path | None = None,
    requested: Sequence[str] = (),
    include_optional: bool = False,
    all_tools: bool = False,
    update: bool = False,
    allow_unverified: bool = False,
    install_prerequisites: bool = False,
    progress: Callable[[ToolInstallProgress], None] | None = None,
) -> tuple[ToolInstallResult, ...]:
    platform_info = assert_supported_platform()
    manifest = load_tools_manifest(manifest_path)
    root = managed_root(manifest)
    bin_dir = root / "bin"
    apps_dir = root / "apps"
    downloads_dir = root / "downloads"
    for directory in (root, bin_dir, apps_dir, downloads_dir):
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700 if directory == root else 0o755)

    activate_managed_tool_path(manifest)

    selected = select_tools(
        manifest,
        requested=requested,
        include_optional=include_optional,
        all_tools=all_tools,
    )

    results: list[ToolInstallResult] = []
    apt_session = _AptSession()
    total = len(selected)
    for index, spec in enumerate(selected, start=1):
        _emit_tool_progress(
            progress,
            spec=spec,
            index=index,
            total=total,
            phase=ToolInstallPhase.CHECKING,
            detail="checking existing binary and identity",
        )
        current = probe_tool(spec, manifest)
        if current.installed and current.identity_ok and not update:
            results.append(
                ToolInstallResult(
                    tool_id=spec.tool_id,
                    installed=True,
                    skipped=True,
                    path=current.path,
                    version=current.version,
                    detail="already installed and identity probe passed",
                )
            )
            _emit_tool_progress(
                progress,
                spec=spec,
                index=index,
                total=total,
                phase=ToolInstallPhase.SKIPPED,
                detail="already installed and verified",
            )
            continue

        apt_spec = spec.apt.get(platform_info.os_id)
        apt_note = (
            f"APT-first ({apt_spec.package}); upstream fallback if unavailable/incompatible"
            if apt_spec is not None
            else "no allow-listed distro package; using upstream installer"
        )
        _emit_tool_progress(
            progress,
            spec=spec,
            index=index,
            total=total,
            phase=ToolInstallPhase.INSTALLING,
            detail=apt_note,
        )

        result = _try_install_with_apt(
            spec,
            manifest,
            platform_info=platform_info,
            apt_session=apt_session,
        )
        if result is None:
            if apt_spec is not None:
                print(
                    f"    apt: {apt_spec.package} unavailable/incompatible; using upstream fallback",
                    flush=True,
                )
            if install_prerequisites:
                _install_apt_prerequisites((spec,))
            _ensure_prerequisite_commands(spec)
            if spec.strategy is InstallStrategy.PDTM:
                _ensure_pdtm_available(
                    manifest,
                    platform_info=platform_info,
                    allow_unverified=allow_unverified,
                )
                result = _install_with_pdtm(spec, manifest, update=update)
            elif spec.strategy is InstallStrategy.PIPX:
                result = _install_with_pipx(spec, manifest, update=update)
            elif spec.strategy in {
                InstallStrategy.GITHUB_BINARY,
                InstallStrategy.GITHUB_ARCHIVE_APP,
                InstallStrategy.GITHUB_JAR,
            }:
                result = _install_from_github_release(
                    spec,
                    manifest,
                    platform_info=platform_info,
                    update=update,
                    allow_unverified=allow_unverified,
                )
            else:  # pragma: no cover - enum exhaustiveness
                raise ToolingError(f"unsupported install strategy: {spec.strategy}")

        _emit_tool_progress(
            progress,
            spec=spec,
            index=index,
            total=total,
            phase=ToolInstallPhase.VERIFYING,
            detail="running binary identity/version probe",
        )
        verified = probe_tool(spec, manifest)
        if not verified.installed or not verified.identity_ok:
            raise ToolingError(
                f"{spec.tool_id} installed but verification failed: {verified.detail}"
            )

        completed = result.model_copy(
            update={
                "path": verified.path,
                "version": verified.version,
                "installed": True,
            }
        )
        results.append(completed)
        _emit_tool_progress(
            progress,
            spec=spec,
            index=index,
            total=total,
            phase=ToolInstallPhase.COMPLETE,
            detail=verified.version or "installed and verified",
        )

    _write_tools_lock(manifest, platform_info, install_results=tuple(results))
    return tuple(results)


def _emit_tool_progress(
    callback: Callable[[ToolInstallProgress], None] | None,
    *,
    spec: ToolSpec,
    index: int,
    total: int,
    phase: ToolInstallPhase,
    detail: str,
) -> None:
    if callback is None:
        return
    callback(
        ToolInstallProgress(
            tool_id=spec.tool_id,
            index=index,
            total=total,
            phase=phase,
            detail=detail,
        )
    )


def _install_apt_prerequisites(specs: Sequence[ToolSpec]) -> None:
    # Avoid unnecessary sudo/apt work when all prerequisite commands already
    # exist.  This matters for the one-command `nightscout setup` path.
    packages = sorted(
        {
            package
            for spec in specs
            if any(
                shutil.which(command) is None
                for command in spec.prerequisite_commands
            )
            for package in spec.prerequisite_apt_packages
            if package.strip()
        }
    )
    if not packages:
        return

    prefix = _privilege_prefix()
    if prefix is None:
        raise ToolingError(
            "system prerequisites are missing and sudo is unavailable; install: "
            + " ".join(packages)
        )

    subprocess.run([*prefix, "apt-get", "update"], check=True)
    subprocess.run(
        [*prefix, "apt-get", "install", "-y", "--no-install-recommends", *packages],
        check=True,
    )


def _ensure_prerequisite_commands(spec: ToolSpec) -> None:
    missing = [command for command in spec.prerequisite_commands if shutil.which(command) is None]
    if missing:
        packages = ", ".join(spec.prerequisite_apt_packages) or "the required packages"
        raise ToolingError(
            f"{spec.tool_id} prerequisites missing: {', '.join(missing)}; "
            f"install {packages} or rerun with --install-prerequisites"
        )


def _ensure_pdtm_available(
    manifest: ToolsManifest,
    *,
    platform_info: PlatformInfo,
    allow_unverified: bool,
) -> None:
    status_spec = manifest.by_id().get("pdtm")
    if status_spec is None:
        raise ToolingError("tools manifest does not define PDTM fallback helper")
    status = probe_tool(status_spec, manifest)
    if status.installed and status.identity_ok:
        return

    print(
        "    upstream fallback needs PDTM; installing the small PDTM helper first...",
        flush=True,
    )
    _install_from_github_release(
        status_spec,
        manifest,
        platform_info=platform_info,
        update=False,
        allow_unverified=allow_unverified,
    )
    verified = probe_tool(status_spec, manifest)
    if not verified.installed or not verified.identity_ok:
        raise ToolingError(f"PDTM helper verification failed: {verified.detail}")


def _install_with_pdtm(
    spec: ToolSpec,
    manifest: ToolsManifest,
    *,
    update: bool,
) -> ToolInstallResult:
    pdtm = resolve_binary("pdtm", manifest)
    if pdtm is None:
        raise ToolingError("PDTM is required before installing ProjectDiscovery tools")

    bin_dir = managed_bin_dir(manifest)
    action = "-u" if update else "-i"
    command = [
        pdtm,
        "-bp",
        str(bin_dir),
        action,
        str(spec.project),
        "-duc",
        "-nc",
    ]
    print(f"    upstream: running PDTM for {spec.tool_id} (live output follows)...", flush=True)
    try:
        result = subprocess.run(command, check=False, timeout=PDTM_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ToolingError(
            f"PDTM timed out while installing {spec.tool_id} after "
            f"{PDTM_TIMEOUT_SECONDS}s; check DNS/proxy access to api.pdtm.sh and GitHub"
        ) from exc
    if result.returncode != 0:
        raise ToolingError(f"PDTM failed for {spec.tool_id} with exit code {result.returncode}")

    return ToolInstallResult(
        tool_id=spec.tool_id,
        installed=True,
        updated=update,
        source=f"pdtm:{spec.project}",
        detail="installed with ProjectDiscovery PDTM",
    )


def _install_with_pipx(
    spec: ToolSpec,
    manifest: ToolsManifest,
    *,
    update: bool,
) -> ToolInstallResult:
    pipx = shutil.which("pipx")
    if pipx is None:
        raise ToolingError(
            f"pipx is required for {spec.tool_id}; install package 'pipx' or use --install-prerequisites"
        )

    if update:
        command = [pipx, "upgrade", str(spec.package)]
    else:
        command = [pipx, "install", "--force", str(spec.package)]

    env = os.environ.copy()
    env["PIPX_BIN_DIR"] = str(managed_bin_dir(manifest))
    env["PIPX_HOME"] = str(managed_root(manifest) / "pipx")

    print(f"    upstream: running pipx for {spec.tool_id} (live output follows)...", flush=True)
    result = subprocess.run(command, check=False, timeout=900, env=env)
    if result.returncode != 0:
        raise ToolingError(f"pipx failed for {spec.tool_id} with exit code {result.returncode}")

    return ToolInstallResult(
        tool_id=spec.tool_id,
        installed=True,
        updated=update,
        source=f"pipx:{spec.package}",
        detail="installed in isolated Night Scout pipx home",
    )


def _install_from_github_release(
    spec: ToolSpec,
    manifest: ToolsManifest,
    *,
    platform_info: PlatformInfo,
    update: bool,
    allow_unverified: bool,
) -> ToolInstallResult:
    assert spec.repository is not None
    assert spec.asset_regex is not None

    print(f"    upstream: checking latest release for {spec.repository}...", flush=True)
    release = _github_latest_release(spec.repository)
    asset_pattern = re.compile(format_asset_regex(spec.asset_regex, platform_info), re.IGNORECASE)
    matching = [asset for asset in release.assets if asset_pattern.search(asset.name)]
    if len(matching) != 1:
        raise ToolingError(
            f"{spec.tool_id}: expected exactly one release asset matching {asset_pattern.pattern!r}; "
            f"found {[asset.name for asset in matching]}"
        )
    asset = matching[0]
    if asset.size <= 0 or asset.size > MAX_ASSET_BYTES:
        raise ToolingError(f"{spec.tool_id}: unsafe release asset size {asset.size}")

    root = managed_root(manifest)
    downloads = root / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    download_path = downloads / asset.name
    print(
        f"    upstream: downloading {asset.name} ({asset.size / (1024 * 1024):.1f} MiB)...",
        flush=True,
    )
    _download_file(asset.url, download_path, max_bytes=MAX_ASSET_BYTES, show_progress=True)
    digest = _sha256_file(download_path)

    verified = False
    if asset.digest and asset.digest.lower().startswith("sha256:"):
        expected = asset.digest.split(":", 1)[1].strip().lower()
        if digest != expected:
            raise ToolingError(
                f"{spec.tool_id}: GitHub asset digest mismatch: expected {expected}, got {digest}"
            )
        verified = True

    if not verified and spec.checksum_asset_regex:
        checksum_pattern = re.compile(
            format_asset_regex(spec.checksum_asset_regex, platform_info), re.IGNORECASE
        )
        checksum_assets = [asset for asset in release.assets if checksum_pattern.search(asset.name)]
        if len(checksum_assets) == 1:
            checksum_path = downloads / checksum_assets[0].name
            print(f"    upstream: downloading checksum {checksum_assets[0].name}...", flush=True)
            _download_file(
                checksum_assets[0].url,
                checksum_path,
                max_bytes=16 * 1024 * 1024,
                show_progress=False,
            )
            expected = _checksum_for_asset(checksum_path, asset.name)
            if expected is None:
                raise ToolingError(
                    f"{spec.tool_id}: checksum file did not contain {asset.name}"
                )
            if digest != expected:
                raise ToolingError(
                    f"{spec.tool_id}: checksum mismatch: expected {expected}, got {digest}"
                )
            verified = True

    if not verified and not allow_unverified:
        raise ToolingError(
            f"{spec.tool_id}: upstream release asset has no usable SHA-256 digest/checksum; "
            "refusing install (use --allow-unverified only after manual verification)"
        )

    if spec.strategy is InstallStrategy.GITHUB_BINARY:
        installed_path = _install_single_binary_asset(spec, manifest, download_path)
    elif spec.strategy is InstallStrategy.GITHUB_ARCHIVE_APP:
        installed_path = _install_archive_app(spec, manifest, download_path, release.tag_name)
    elif spec.strategy is InstallStrategy.GITHUB_JAR:
        installed_path = _install_jar(spec, manifest, download_path, release.tag_name)
    else:  # pragma: no cover
        raise ToolingError("invalid GitHub install strategy")

    return ToolInstallResult(
        tool_id=spec.tool_id,
        installed=True,
        updated=update,
        path=str(installed_path),
        sha256=digest,
        source=release.html_url,
        detail=(
            f"installed official GitHub release {release.tag_name}; "
            + ("SHA-256 verified" if verified else "UNVERIFIED BY REQUEST")
        ),
    )


def _install_single_binary_asset(
    spec: ToolSpec,
    manifest: ToolsManifest,
    asset_path: Path,
) -> Path:
    with tempfile.TemporaryDirectory(prefix="nightscout-tool-") as tmp:
        tmp_path = Path(tmp)
        if asset_path.name.endswith(".zip"):
            _safe_extract_zip(asset_path, tmp_path)
        elif asset_path.name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
            _safe_extract_tar(asset_path, tmp_path)
        else:
            candidate = asset_path
            return _atomic_install_executable(candidate, managed_bin_dir(manifest) / spec.binary)

        candidates = [
            path
            for path in tmp_path.rglob(spec.binary)
            if path.is_file() and not path.is_symlink()
        ]
        if len(candidates) != 1:
            raise ToolingError(
                f"{spec.tool_id}: expected one {spec.binary!r} in archive, found {len(candidates)}"
            )
        return _atomic_install_executable(candidates[0], managed_bin_dir(manifest) / spec.binary)


def _install_archive_app(
    spec: ToolSpec,
    manifest: ToolsManifest,
    asset_path: Path,
    release_tag: str,
) -> Path:
    assert spec.entrypoint is not None
    app_root = managed_root(manifest) / "apps" / spec.tool_id / release_tag
    staging = app_root.with_name(app_root.name + ".tmp")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    if asset_path.name.endswith(".zip"):
        _safe_extract_zip(asset_path, staging)
    elif asset_path.name.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar")):
        _safe_extract_tar(asset_path, staging)
    else:
        raise ToolingError(f"{spec.tool_id}: archive app requires zip/tar asset")

    entrypoint = _find_archive_entrypoint(staging, spec.entrypoint)
    if entrypoint is None:
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolingError(f"{spec.tool_id}: entrypoint not found: {spec.entrypoint}")

    if app_root.exists():
        shutil.rmtree(app_root)
    staging.rename(app_root)
    final_entrypoint = _find_archive_entrypoint(app_root, spec.entrypoint)
    assert final_entrypoint is not None
    final_entrypoint.chmod(final_entrypoint.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return _atomic_symlink(final_entrypoint, managed_bin_dir(manifest) / spec.binary)


def _install_jar(
    spec: ToolSpec,
    manifest: ToolsManifest,
    asset_path: Path,
    release_tag: str,
) -> Path:
    app_root = managed_root(manifest) / "apps" / spec.tool_id / release_tag
    app_root.mkdir(parents=True, exist_ok=True)
    jar_path = app_root / asset_path.name
    shutil.copy2(asset_path, jar_path)
    os.chmod(jar_path, 0o644)

    wrapper = managed_bin_dir(manifest) / spec.binary
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "#!/bin/sh\n"
        "set -eu\n"
        f'exec java -jar "{jar_path}" "$@"\n'
    )
    _atomic_write_text(wrapper, content, mode=0o755)
    return wrapper


def _find_archive_entrypoint(root: Path, entrypoint: str) -> Path | None:
    relative = PurePosixPath(entrypoint)
    direct = root.joinpath(*relative.parts)
    if direct.is_file():
        return direct
    matches = [
        path
        for path in root.rglob(relative.name)
        if path.is_file() and path.as_posix().endswith(relative.as_posix())
    ]
    return matches[0] if len(matches) == 1 else None


def _github_latest_release(repository: str) -> GitHubRelease:
    url = f"{GITHUB_API}/repos/{repository}/releases/latest"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "NightScout/0.1 tool-installer",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30.0) as response:
            raw = response.read(MAX_RELEASE_JSON_BYTES + 1)
    except urllib.error.URLError as exc:
        raise ToolingError(f"GitHub release lookup failed for {repository}: {exc}") from exc
    if len(raw) > MAX_RELEASE_JSON_BYTES:
        raise ToolingError(f"GitHub release metadata too large for {repository}")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ToolingError("GitHub release response is not an object")

    assets_raw = payload.get("assets")
    if not isinstance(assets_raw, list):
        assets_raw = []
    assets: list[GitHubAsset] = []
    for item in assets_raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        download_url = item.get("browser_download_url")
        size = item.get("size")
        if not isinstance(name, str) or not isinstance(download_url, str):
            continue
        if not download_url.startswith("https://github.com/"):
            continue
        try:
            size_int = int(size)
        except (TypeError, ValueError):
            size_int = 0
        digest = item.get("digest")
        assets.append(
            GitHubAsset(
                name=name,
                url=download_url,
                size=size_int,
                digest=(str(digest) if digest else None),
            )
        )

    tag_name = str(payload.get("tag_name") or "").strip()
    html_url = str(payload.get("html_url") or "").strip()
    if not tag_name or not html_url.startswith("https://github.com/"):
        raise ToolingError(f"invalid GitHub release metadata for {repository}")
    return GitHubRelease(tag_name=tag_name, html_url=html_url, assets=tuple(assets))


def _download_file(
    url: str,
    destination: Path,
    *,
    max_bytes: int,
    show_progress: bool = False,
) -> None:
    if not url.startswith("https://"):
        raise ToolingError("refusing non-HTTPS download")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".part")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "NightScout/0.1 tool-installer"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=60.0) as response, temp.open("wb") as handle:
            total = 0
            content_length_raw = response.headers.get("Content-Length")
            try:
                expected = int(content_length_raw) if content_length_raw else 0
            except ValueError:
                expected = 0
            last_report = time.monotonic()
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ToolingError(f"download exceeded size limit: {url}")
                handle.write(chunk)
                now = time.monotonic()
                if show_progress and now - last_report >= 2.0:
                    if expected > 0:
                        percent = min(100.0, total * 100.0 / expected)
                        print(
                            f"      downloaded {total / (1024 * 1024):.1f}/"
                            f"{expected / (1024 * 1024):.1f} MiB ({percent:.0f}%)",
                            flush=True,
                        )
                    else:
                        print(
                            f"      downloaded {total / (1024 * 1024):.1f} MiB...",
                            flush=True,
                        )
                    last_report = now
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, destination)
        if show_progress:
            print(f"      download complete: {total / (1024 * 1024):.1f} MiB", flush=True)
    finally:
        temp.unlink(missing_ok=True)


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    total = 0
    with zipfile.ZipFile(archive) as handle:
        infos = handle.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise ToolingError("archive contains too many members")
        for info in infos:
            relative = _safe_archive_path(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ToolingError("archive symlinks are not allowed")
            total += max(0, int(info.file_size))
            if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ToolingError("archive uncompressed size exceeds limit")
            target = destination.joinpath(*relative.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with handle.open(info, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    total = 0
    with tarfile.open(archive, "r:*") as handle:
        members = handle.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ToolingError("archive contains too many members")
        for member in members:
            relative = _safe_archive_path(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ToolingError("archive links/devices are not allowed")
            if member.isdir():
                destination.joinpath(*relative.parts).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            total += max(0, int(member.size))
            if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise ToolingError("archive uncompressed size exceeds limit")
            source = handle.extractfile(member)
            if source is None:
                continue
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _safe_archive_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ToolingError(f"unsafe archive path: {name!r}")
    return path


def _checksum_for_asset(checksum_path: Path, asset_name: str) -> str | None:
    single_hash: str | None = None
    meaningful = 0
    for line in checksum_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        meaningful += 1
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", stripped)
        if match and Path(match.group(2)).name == asset_name:
            return match.group(1).lower()
        if re.fullmatch(r"[0-9a-fA-F]{64}", stripped):
            single_hash = stripped.lower()
    # Some projects publish a per-asset .sha256 file containing only the hash.
    if meaningful == 1:
        return single_hash
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_install_executable(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")
    shutil.copy2(source, temp)
    temp.chmod(0o755)
    os.replace(temp, destination)
    return destination


def _atomic_symlink(target: Path, link: Path) -> Path:
    link.parent.mkdir(parents=True, exist_ok=True)
    temp = link.with_name(link.name + ".tmp-link")
    temp.unlink(missing_ok=True)
    temp.symlink_to(target)
    os.replace(temp, link)
    return link


def _atomic_write_text(path: Path, content: str, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    temp.chmod(mode)
    os.replace(temp, path)


def _probe_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("ALL_PROXY", None)
    env.pop("http_proxy", None)
    env.pop("https_proxy", None)
    env.pop("all_proxy", None)
    return env


def _write_tools_lock(
    manifest: ToolsManifest,
    platform_info: PlatformInfo,
    *,
    install_results: Sequence[ToolInstallResult] = (),
) -> Path:
    entries: list[ToolsLockEntry] = []
    old_lock = read_tools_lock(manifest)
    old_by_id = {entry.tool_id: entry for entry in old_lock.entries} if old_lock else {}
    result_by_id = {result.tool_id: result for result in install_results}

    for spec in manifest.tools:
        status = probe_tool(spec, manifest)
        if not status.installed or not status.identity_ok or not status.path:
            continue
        path = Path(status.path)
        sha256 = _sha256_file(path) if path.is_file() and not path.is_symlink() else None
        old = old_by_id.get(spec.tool_id)
        installed = result_by_id.get(spec.tool_id)
        entries.append(
            ToolsLockEntry(
                tool_id=spec.tool_id,
                binary=spec.binary,
                strategy=spec.strategy.value,
                path=status.path,
                version=status.version,
                sha256=sha256 or (old.sha256 if old else None),
                source=(
                    installed.source
                    if installed is not None and installed.source
                    else (old.source if old else None)
                ),
                installed_at=utc_now().isoformat(),
            )
        )

    lock = ToolsLock(platform=platform_info, entries=tuple(entries))
    path = managed_root(manifest) / "tools.lock.yaml"
    _atomic_write_text(
        path,
        yaml.safe_dump(lock.model_dump(mode="json"), sort_keys=False, allow_unicode=True),
        mode=0o600,
    )
    return path


def read_tools_lock(manifest: ToolsManifest | None = None) -> ToolsLock | None:
    manifest = manifest or load_tools_manifest()
    path = managed_root(manifest) / "tools.lock.yaml"
    if not path.is_file():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None
    try:
        return ToolsLock.model_validate(raw)
    except Exception:
        return None


def tooling_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install/verify Night Scout external tools")
    parser.add_argument("action", choices=("list", "install", "verify"))
    parser.add_argument("tools", nargs="*")
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--all", action="store_true", dest="all_tools")
    parser.add_argument("--optional", action="store_true", dest="include_optional")
    parser.add_argument("--update", action="store_true")
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--install-prerequisites", action="store_true")
    args = parser.parse_args(argv)

    manifest = load_tools_manifest(args.manifest)
    platform_info = assert_supported_platform()

    if args.action == "list":
        print(f"platform: {platform_info.pretty_name} / {platform_info.architecture}")
        print(f"managed bin: {managed_bin_dir(manifest)}")
        for spec in manifest.tools:
            marker = "required" if spec.requirement is ToolRequirement.REQUIRED else "optional"
            apt_spec = spec.apt.get(platform_info.os_id)
            install_path = (
                f"apt:{apt_spec.package} -> fallback:{spec.strategy.value}"
                if apt_spec is not None
                else f"upstream:{spec.strategy.value}"
            )
            print(f"{spec.tool_id:14} {marker:8} {install_path:36} {spec.description}")
        return 0

    if args.action == "verify":
        failed = False
        for status in probe_all_tools(manifest):
            marker = "OK" if status.installed and status.identity_ok else (
                "WARN" if not status.required else "FAIL"
            )
            print(f"[{marker:4}] {status.tool_id}: {status.detail}")
            if status.required and not (status.installed and status.identity_ok):
                failed = True
        return 1 if failed else 0

    results = install_tools(
        manifest_path=args.manifest,
        requested=args.tools,
        include_optional=args.include_optional,
        all_tools=args.all_tools,
        update=args.update,
        allow_unverified=args.allow_unverified,
        install_prerequisites=args.install_prerequisites,
    )
    for result in results:
        marker = "SKIP" if result.skipped else "OK"
        print(f"[{marker:4}] {result.tool_id}: {result.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(tooling_cli())
