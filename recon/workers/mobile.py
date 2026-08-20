"""Offline mobile-artifact analysis for Night Scout.

This worker analyzes *already obtained* APK/IPA files. It never downloads an
application, launches it, logs in, verifies credentials, or makes target/API
requests.

Pipeline
--------

    MOBILE_ARTIFACT (local workspace reference)
        -> safe bounded archive extraction
        -> optional Android decompilation (JADX, Apktool fallback)
        -> local strings/resources/plist inspection
        -> optional offline secret scanners
        -> normalized Events

Outputs can include:

    DNS_NAME
    URL
    API_ENDPOINT
    PARAMETER_NAME
    PROJECT_NAME
    TECHNOLOGY
    VOCAB_TOKEN
    ARTIFACT
    HUMAN_REVIEW
    MOBILE_ARTIFACT (analysis summary)

Credential handling
-------------------
Possible credentials are *detection candidates*, never credentials to use.
Night Scout does not send them to any service for validation.

The worker deliberately does not put a raw secret into Event.value, tags,
metadata, stdout, or ordinary JSONL state. A finding records only safe context:

    detector / rule id
    secret type
    relative source file
    line/column when available
    confidence/severity
    location-derived evidence fingerprint
    optional masked preview (disabled by default)

The original local mobile artifact/decompiled source remains the place a human
reviewer can inspect the value if program policy permits it.

External scanners
-----------------
Gitleaks is run in `dir` mode with a Night Scout-owned config extending the
built-in rules, a Night Scout-owned empty ignore file, JSON reporting, 100%
redaction, bounded target size, and a timeout.

TruffleHog is run only against a bounded local filesystem view with
`--no-verification`; thus detector verification requests are disabled. Raw and
Redacted fields from its JSON output are discarded immediately.

Android decompilation
---------------------
JADX is the primary optional Android decompiler. It is executed with one
thread, isolated config/cache/temp directories, config loading disabled, and
JADX's ZIP security left enabled. Apktool can be used as a local fallback.

Even if neither tool is installed, Night Scout still performs bounded ZIP,
plist, printable-string, URL, vocabulary, technology, and built-in secret
analysis.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import tempfile
import zipfile
from collections import Counter, deque
from collections.abc import Iterable, Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext
from recon.workers.passive_domains import normalize_dns_name

WORKER_NAME = "mobile"
ACTION_ANALYZE = "analyze"


class MobileArtifactKind(StrEnum):
    APK = "APK"
    IPA = "IPA"


class SecretSeverity(StrEnum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MobileArtifactMaterial(BaseModel):
    """Trusted local mobile-artifact reference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    kind: MobileArtifactKind

    sha256: str
    size_bytes: int = Field(ge=0)

    content_ref: str
    source: str = "workspace"

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        normalized = value.strip().lower().replace(":", "")

        if (
            len(normalized) != 64
            or any(character not in "0123456789abcdef" for character in normalized)
        ):
            raise ValueError("sha256 must be a 64-character hexadecimal digest")

        return normalized

    @field_validator("content_ref", "source")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized


class ImportedMobileArtifact(BaseModel):
    """Content-addressed mobile artifact materialized in a workspace."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    artifact_ref: str
    kind: MobileArtifactKind
    sha256: str
    size_bytes: int = Field(ge=0)

    @field_validator("artifact_ref")
    @classmethod
    def artifact_ref_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("artifact_ref must not be blank")
        return normalized

    @field_validator("sha256")
    @classmethod
    def normalize_sha256(cls, value: str) -> str:
        return MobileArtifactMaterial.normalize_sha256(value)


class MobileArtifactProvider(Protocol):
    async def material_for(
        self,
        event: Event,
    ) -> MobileArtifactMaterial | None:
        ...


class InputEventProvider(Protocol):
    async def get_event(
        self,
        event_id: str,
    ) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(
        self,
        event: Event,
    ) -> bool:
        ...


class WorkspaceMobileArtifactProvider:
    """Resolve a relative artifact reference beneath a trusted workspace root."""

    def __init__(
        self,
        root: Path,
        *,
        metadata_keys: tuple[str, ...] = (
            "artifact_ref",
            "content_ref",
        ),
    ) -> None:
        self._root = root.expanduser().resolve()
        self._metadata_keys = tuple(
            key.strip()
            for key in metadata_keys
            if key.strip()
        )

        if not self._metadata_keys:
            raise ValueError("metadata_keys cannot be empty")

    async def material_for(
        self,
        event: Event,
    ) -> MobileArtifactMaterial | None:
        raw_ref: str | None = None

        for key in self._metadata_keys:
            value = event.metadata.get(key)

            if isinstance(value, str) and value.strip():
                raw_ref = value.strip()
                break

        if raw_ref is None:
            return None

        relative = Path(raw_ref)

        if relative.is_absolute():
            return None

        candidate = (self._root / relative).resolve()

        try:
            candidate.relative_to(self._root)
        except ValueError:
            return None

        if not candidate.is_file() or candidate.is_symlink():
            return None

        try:
            kind = mobile_artifact_kind(
                event.metadata.get("mobile_kind")
                or event.metadata.get("artifact_kind")
                or candidate.suffix
            )
        except ValueError:
            return None

        digest, size_bytes = await asyncio.to_thread(
            hash_file,
            candidate,
        )

        expected_digest = event.metadata.get("artifact_sha256")
        if expected_digest is not None:
            try:
                normalized_expected = MobileArtifactMaterial.normalize_sha256(
                    str(expected_digest)
                )
            except ValueError:
                return None
            if digest != normalized_expected:
                return None

        expected_size = event.metadata.get("artifact_size_bytes")
        if expected_size is not None:
            if isinstance(expected_size, bool):
                return None
            try:
                normalized_size = int(expected_size)
            except (TypeError, ValueError):
                return None
            if size_bytes != normalized_size:
                return None

        return MobileArtifactMaterial(
            path=candidate,
            kind=kind,
            sha256=digest,
            size_bytes=size_bytes,
            content_ref=relative.as_posix(),
            source="workspace",
        )


class WorkspaceMobileArtifactStore:
    """Safely import immutable APK/IPA content into one target workspace."""

    def __init__(
        self,
        root: Path,
        *,
        max_artifact_bytes: int,
    ) -> None:
        if max_artifact_bytes < 1:
            raise ValueError("max_artifact_bytes must be positive")
        self._root = root.expanduser().resolve()
        self._max_artifact_bytes = max_artifact_bytes

    @property
    def root(self) -> Path:
        return self._root

    async def import_file(
        self,
        source: Path,
        *,
        kind: MobileArtifactKind | None = None,
    ) -> ImportedMobileArtifact:
        return await asyncio.to_thread(
            self._import_file_sync,
            source,
            kind,
        )

    def _import_file_sync(
        self,
        source: Path,
        kind: MobileArtifactKind | None,
    ) -> ImportedMobileArtifact:
        source = source.expanduser()
        if source.is_symlink():
            raise ValueError("mobile artifact source cannot be a symlink")

        selected_kind = mobile_artifact_kind(kind or source.suffix)
        self._prepare_root()

        source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(source, source_flags)
        except OSError as exc:
            raise ValueError(f"cannot open mobile artifact: {exc}") from exc

        tmp: Path | None = None
        tmp_fd: int | None = None
        digest = hashlib.sha256()
        size_bytes = 0

        try:
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise ValueError("mobile artifact source must be a regular file")
            if source_stat.st_size > self._max_artifact_bytes:
                raise ValueError(
                    "mobile artifact exceeds configured size limit: "
                    f"{source_stat.st_size} > {self._max_artifact_bytes}"
                )

            tmp_fd, tmp_name = tempfile.mkstemp(
                prefix=".mobile-import-",
                suffix=".tmp",
                dir=self._root,
            )
            tmp = Path(tmp_name)
            os.fchmod(tmp_fd, stat.S_IRUSR | stat.S_IWUSR)

            with os.fdopen(source_fd, "rb", closefd=False) as source_handle, os.fdopen(
                tmp_fd,
                "wb",
                closefd=False,
            ) as destination_handle:
                while True:
                    chunk = source_handle.read(1024 * 1024)
                    if not chunk:
                        break
                    size_bytes += len(chunk)
                    if size_bytes > self._max_artifact_bytes:
                        raise ValueError(
                            "mobile artifact exceeded configured size limit while importing: "
                            f"> {self._max_artifact_bytes}"
                        )
                    digest.update(chunk)
                    destination_handle.write(chunk)
                destination_handle.flush()
                os.fsync(destination_handle.fileno())

            sha256 = digest.hexdigest()
            suffix = ".apk" if selected_kind is MobileArtifactKind.APK else ".ipa"
            destination = self._root / f"{sha256}{suffix}"

            try:
                os.link(tmp, destination)
            except FileExistsError:
                self._validate_existing(destination, sha256, size_bytes)
            os.chmod(destination, stat.S_IRUSR)

            return ImportedMobileArtifact(
                path=destination,
                artifact_ref=destination.relative_to(self._root).as_posix(),
                kind=selected_kind,
                sha256=sha256,
                size_bytes=size_bytes,
            )
        finally:
            with contextlib.suppress(OSError):
                os.close(source_fd)
            if tmp_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(tmp_fd)
            if tmp is not None:
                tmp.unlink(missing_ok=True)

    def _prepare_root(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self._root.is_dir() or self._root.is_symlink():
            raise ValueError("mobile artifact root must be a real directory")
        os.chmod(self._root, 0o700)

    @staticmethod
    def _validate_existing(
        destination: Path,
        expected_sha256: str,
        expected_size: int,
    ) -> None:
        if destination.is_symlink() or not destination.is_file():
            raise ValueError("existing mobile artifact destination is unsafe")
        actual_sha256, actual_size = hash_file(destination)
        if actual_sha256 != expected_sha256 or actual_size != expected_size:
            raise ValueError("existing content-addressed mobile artifact is inconsistent")


class MobileAnalysisConfig(BaseModel):
    """Hard bounds for local mobile analysis."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_artifact_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1024,
        le=4 * 1024 * 1024 * 1024,
    )

    max_archive_entries: int = Field(default=100_000, ge=1, le=1_000_000)
    max_archive_member_bytes: int = Field(
        default=64 * 1024 * 1024,
        ge=1024,
        le=512 * 1024 * 1024,
    )
    max_archive_total_uncompressed_bytes: int = Field(
        default=1024 * 1024 * 1024,
        ge=1024,
        le=8 * 1024 * 1024 * 1024,
    )

    max_files_scanned: int = Field(default=100_000, ge=1, le=1_000_000)
    max_file_scan_bytes: int = Field(
        default=8 * 1024 * 1024,
        ge=1024,
        le=128 * 1024 * 1024,
    )
    max_total_scan_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1024,
        le=4 * 1024 * 1024 * 1024,
    )

    min_printable_string_length: int = Field(default=6, ge=4, le=64)

    max_urls: int = Field(default=20_000, ge=1, le=500_000)
    max_dns_names: int = Field(default=20_000, ge=1, le=500_000)
    max_api_endpoints: int = Field(default=20_000, ge=1, le=500_000)
    max_parameters: int = Field(default=20_000, ge=1, le=500_000)
    max_vocabulary_tokens: int = Field(default=50_000, ge=1, le=1_000_000)
    max_projects: int = Field(default=2048, ge=1, le=100_000)
    max_technologies: int = Field(default=2048, ge=1, le=100_000)
    max_deep_links: int = Field(default=4096, ge=1, le=100_000)
    max_secret_findings: int = Field(default=4096, ge=1, le=100_000)

    enable_jadx: bool = True
    enable_apktool_fallback: bool = True
    enable_builtin_secret_scan: bool = True
    enable_gitleaks: bool = True
    enable_trufflehog: bool = True

    decompiler_timeout_seconds: float = Field(default=180.0, gt=0.0)
    secret_scanner_timeout_seconds: float = Field(default=120.0, gt=0.0)

    external_scan_max_file_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=1024,
        le=128 * 1024 * 1024,
    )
    external_scan_max_total_bytes: int = Field(
        default=256 * 1024 * 1024,
        ge=1024,
        le=2 * 1024 * 1024 * 1024,
    )

    include_masked_secret_preview: bool = False

    # Raw secret evidence is never put into Events. When enabled it is written
    # to a separate private evidence store for explicit bug-bounty reporting.
    preserve_raw_secret_evidence: bool = True
    sensitive_evidence_root: Path = Path(".nightscout/sensitive-evidence")

    @model_validator(mode="after")
    def valid_external_scan_bounds(self) -> "MobileAnalysisConfig":
        if self.external_scan_max_file_bytes > self.external_scan_max_total_bytes:
            raise ValueError(
                "external_scan_max_file_bytes cannot exceed total external scan bytes"
            )

        return self


class SecretFinding(BaseModel):
    """Possible-secret evidence with a non-serializing in-memory raw value.

    `raw_secret` is excluded from Pydantic serialization/repr and is never
    copied into Events. It exists only long enough to be persisted into the
    separate protected sensitive-evidence store.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    detector: str
    secret_type: str

    relative_path: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)

    rule_id: str | None = None

    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    severity: SecretSeverity = SecretSeverity.HIGH

    evidence_fingerprint: str
    masked_preview: str | None = None

    raw_secret: SecretStr | None = Field(
        default=None,
        exclude=True,
        repr=False,
    )

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "detector",
        "secret_type",
        "relative_path",
        "evidence_fingerprint",
    )
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError("must not be blank")

        return normalized

    @field_validator("rule_id", "masked_preview")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None


class SensitiveEvidenceRecord(BaseModel):
    """Raw secret record stored outside the normal event graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_fingerprint: str
    raw_secret: SecretStr = Field(repr=False)
    secret_type: str
    detector: str
    source_file: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    artifact_ref: str
    artifact_sha256: str


class SensitiveEvidenceSink(Protocol):
    async def store(
        self,
        record: SensitiveEvidenceRecord,
    ) -> bool:
        ...


class WorkspaceSensitiveEvidenceStore:
    """Private plaintext-at-rest evidence store for manual bug-bounty reports.

    Directory mode is forced to 0700 and each JSON record to 0600. Raw values
    never enter Event metadata. Encryption/keyring support can later implement
    the same sink interface without changing mobile.py.
    """

    def __init__(self, root: Path) -> None:
        self._root = root.expanduser().resolve()
        self._prepare_root()

    @property
    def root(self) -> Path:
        return self._root

    def _prepare_root(self) -> None:
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._root.is_symlink():
            raise ValueError("sensitive evidence root cannot be a symlink")
        os.chmod(self._root, 0o700)

    async def store(
        self,
        record: SensitiveEvidenceRecord,
    ) -> bool:
        return await asyncio.to_thread(self._store_sync, record)

    def _store_sync(self, record: SensitiveEvidenceRecord) -> bool:
        fingerprint = record.evidence_fingerprint.strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{16,128}", fingerprint):
            raise ValueError("invalid sensitive evidence fingerprint")

        self._prepare_root()
        destination = (self._root / f"{fingerprint}.json").resolve()
        destination.relative_to(self._root)

        payload = {
            "evidence_fingerprint": fingerprint,
            "raw_secret": record.raw_secret.get_secret_value(),
            "secret_type": record.secret_type,
            "detector": record.detector,
            "source_file": record.source_file,
            "line": record.line,
            "column": record.column,
            "artifact_ref": record.artifact_ref,
            "artifact_sha256": record.artifact_sha256,
        }

        data = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{fingerprint}.",
            suffix=".tmp",
            dir=self._root,
        )
        tmp = Path(tmp_name)

        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, destination)
            os.chmod(destination, 0o600)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            tmp.unlink(missing_ok=True)
            raise

        return True


class MobileAnalysisResult(BaseModel):
    """Bounded normalized local-analysis result before Event publication."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    urls: tuple[str, ...] = ()
    dns_names: tuple[str, ...] = ()
    api_endpoints: tuple[str, ...] = ()
    parameters: tuple[str, ...] = ()

    project_names: tuple[str, ...] = ()
    technologies: tuple[str, ...] = ()
    vocabulary: tuple[str, ...] = ()
    deep_links: tuple[str, ...] = ()

    secrets: tuple[SecretFinding, ...] = ()

    files_scanned: int = Field(default=0, ge=0)
    bytes_scanned: int = Field(default=0, ge=0)

    package_identifiers: tuple[str, ...] = ()

    tools_used: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class MobileDecompiler(Protocol):
    name: str

    def available(self) -> bool:
        ...

    async def decompile(
        self,
        artifact: MobileArtifactMaterial,
        *,
        output_dir: Path,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> bool:
        ...


class SecretScanner(Protocol):
    name: str

    def available(self) -> bool:
        ...

    async def scan(
        self,
        root: Path,
        *,
        artifact_sha256: str,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> Sequence[SecretFinding]:
        ...


class JadxDecompiler:
    """Local JADX adapter; never executes decompiled application code."""

    name = "jadx"

    def __init__(
        self,
        binary: str = "jadx",
    ) -> None:
        self.binary = binary

    def available(self) -> bool:
        return resolve_executable(self.binary) is not None

    async def decompile(
        self,
        artifact: MobileArtifactMaterial,
        *,
        output_dir: Path,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> bool:
        executable = resolve_executable(self.binary)

        if executable is None:
            return False

        config_dir = work_dir / "jadx-config"
        cache_dir = work_dir / "jadx-cache"
        tmp_dir = work_dir / "jadx-tmp"

        for path in (config_dir, cache_dir, tmp_dir, output_dir):
            path.mkdir(parents=True, exist_ok=True)

        env = safe_subprocess_env(
            {
                "JADX_CONFIG_DIR": str(config_dir),
                "JADX_CACHE_DIR": str(cache_dir),
                "JADX_TMP_DIR": str(tmp_dir),
                "JADX_ZIP_MAX_ENTRIES_COUNT": str(config.max_archive_entries),
            }
        )

        command = (
            executable,
            "-d",
            str(output_dir),
            "--threads-count",
            "1",
            "--log-level",
            "ERROR",
            "--config",
            "none",
            "--deobf-cfg-file-mode",
            "ignore",
            str(artifact.path),
        )

        return await run_bounded_process(
            command,
            timeout_seconds=config.decompiler_timeout_seconds,
            cwd=work_dir,
            env=env,
        )


class ApktoolDecompiler:
    """Local Apktool fallback for Android resources/smali."""

    name = "apktool"

    def __init__(
        self,
        binary: str = "apktool",
    ) -> None:
        self.binary = binary

    def available(self) -> bool:
        return resolve_executable(self.binary) is not None

    async def decompile(
        self,
        artifact: MobileArtifactMaterial,
        *,
        output_dir: Path,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> bool:
        del config

        if artifact.kind is not MobileArtifactKind.APK:
            return False

        executable = resolve_executable(self.binary)

        if executable is None:
            return False

        output_dir.mkdir(parents=True, exist_ok=True)
        frame_dir = work_dir / "apktool-framework"
        frame_dir.mkdir(parents=True, exist_ok=True)

        command = (
            executable,
            "d",
            str(artifact.path),
            "-f",
            "-j",
            "1",
            "-p",
            str(frame_dir),
            "-o",
            str(output_dir),
        )

        return await run_bounded_process(
            command,
            timeout_seconds=180.0,
            cwd=work_dir,
            env=safe_subprocess_env(),
        )


class GitleaksSecretScanner:
    """Offline Gitleaks directory scan with forced redaction/config isolation."""

    name = "gitleaks"

    def __init__(
        self,
        binary: str = "gitleaks",
    ) -> None:
        self.binary = binary

    def available(self) -> bool:
        return resolve_executable(self.binary) is not None

    async def scan(
        self,
        root: Path,
        *,
        artifact_sha256: str,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> Sequence[SecretFinding]:
        executable = resolve_executable(self.binary)

        if executable is None:
            return ()

        scanner_dir = work_dir / "gitleaks"
        scanner_dir.mkdir(parents=True, exist_ok=True)

        report_path = scanner_dir / "report.json"
        fixed_config = scanner_dir / "nightscout-gitleaks.toml"
        ignore_path = scanner_dir / "empty.gitleaksignore"

        fixed_config.write_text(
            "title = \"Night Scout default Gitleaks rules\"\n"
            "[extend]\n"
            "useDefault = true\n",
            encoding="utf-8",
        )
        ignore_path.write_text("", encoding="utf-8")

        # Pre-create the report with private permissions. In evidence-preserving
        # mode Gitleaks is allowed to place the raw matched secret only in this
        # temporary 0600 report, which is parsed and then destroyed with the
        # worker temporary directory.
        report_path.touch(mode=0o600, exist_ok=True)
        os.chmod(report_path, 0o600)

        command_parts = [
            executable,
            "dir",
            str(root),
            "--config",
            str(fixed_config),
            "--gitleaks-ignore-path",
            str(ignore_path),
            "--report-path",
            str(report_path),
            "--report-format",
            "json",
        ]

        if not config.preserve_raw_secret_evidence:
            command_parts.append("--redact=100")

        command_parts.extend(
            (
                "--no-banner",
                "--no-color",
                "--max-archive-depth",
                "0",
                "--max-decode-depth",
                "0",
                "--max-target-megabytes",
                str(
                    max(
                        1,
                        config.external_scan_max_file_bytes // (1024 * 1024),
                    )
                ),
                "--timeout",
                str(max(1, int(config.secret_scanner_timeout_seconds))),
                "--exit-code",
                "0",
            )
        )

        command = tuple(command_parts)

        ok = await run_bounded_process(
            command,
            timeout_seconds=config.secret_scanner_timeout_seconds + 5.0,
            cwd=scanner_dir,
            env=safe_subprocess_env(),
        )

        if not ok or not report_path.is_file():
            return ()

        try:
            payload = json.loads(
                report_path.read_text(
                    encoding="utf-8",
                    errors="replace",
                )
                or "[]"
            )
        except (json.JSONDecodeError, OSError):
            return ()

        if not isinstance(payload, list):
            return ()

        findings: list[SecretFinding] = []

        for item in payload:
            if not isinstance(item, dict):
                continue

            path = safe_scanner_relative_path(
                item.get("File")
                or item.get("file")
                or "unknown"
            )

            rule_id = optional_text(
                item.get("RuleID")
                or item.get("ruleID")
                or item.get("rule_id")
            )

            secret_type = (
                rule_id
                or optional_text(item.get("Description"))
                or "gitleaks-secret"
            )

            line = positive_int(
                item.get("StartLine")
                or item.get("Line")
            )

            column = positive_int(
                item.get("StartColumn")
            )

            fingerprint = secret_location_fingerprint(
                artifact_sha256=artifact_sha256,
                detector=self.name,
                secret_type=secret_type,
                relative_path=path,
                line=line,
                column=column,
                rule_id=rule_id,
            )

            raw_secret = (
                optional_text(
                    item.get("Secret")
                    or item.get("secret")
                )
                if config.preserve_raw_secret_evidence
                else None
            )

            findings.append(
                SecretFinding(
                    detector=self.name,
                    secret_type=secret_type,
                    relative_path=path,
                    line=line,
                    column=column,
                    rule_id=rule_id,
                    confidence=0.86,
                    severity=secret_severity_for_type(secret_type),
                    evidence_fingerprint=fingerprint,
                    raw_secret=(
                        SecretStr(raw_secret)
                        if raw_secret is not None
                        else None
                    ),
                    metadata={
                        "external_scanner": True,
                        "raw_secret_stored": False,
                        "scanner_redaction": (
                            "disabled-for-protected-evidence-store"
                            if config.preserve_raw_secret_evidence
                            else "100%"
                        ),
                        "verification_attempted": False,
                    },
                )
            )

            if len(findings) >= config.max_secret_findings:
                break

        return tuple(findings)


class TruffleHogSecretScanner:
    """Offline TruffleHog filesystem scan with verification disabled."""

    name = "trufflehog"

    def __init__(
        self,
        binary: str = "trufflehog",
    ) -> None:
        self.binary = binary

    def available(self) -> bool:
        return resolve_executable(self.binary) is not None

    async def scan(
        self,
        root: Path,
        *,
        artifact_sha256: str,
        work_dir: Path,
        config: MobileAnalysisConfig,
    ) -> Sequence[SecretFinding]:
        executable = resolve_executable(self.binary)

        if executable is None:
            return ()

        command = (
            executable,
            "filesystem",
            str(root),
            "--json",
            "--no-verification",
            "--results=unverified,unknown",
            "--concurrency=1",
            "--force-skip-archives",
            "--log-level=-1",
        )

        lines = await run_jsonl_process(
            command,
            timeout_seconds=config.secret_scanner_timeout_seconds,
            cwd=work_dir,
            env=safe_subprocess_env(),
            max_lines=config.max_secret_findings * 4,
        )

        findings: list[SecretFinding] = []

        for payload in lines:
            detector_name = (
                optional_text(payload.get("DetectorName"))
                or optional_text(payload.get("DetectorType"))
                or "trufflehog-secret"
            )

            relative_path, line = trufflehog_location(payload)

            fingerprint = secret_location_fingerprint(
                artifact_sha256=artifact_sha256,
                detector=self.name,
                secret_type=detector_name,
                relative_path=relative_path,
                line=line,
                column=None,
                rule_id=None,
            )

            # Raw detector output may be retained only in the protected
            # evidence store. It is never copied to Event.value/metadata.
            raw_secret = (
                optional_text(payload.get("Raw"))
                or optional_text(payload.get("RawV2"))
                if config.preserve_raw_secret_evidence
                else None
            )

            findings.append(
                SecretFinding(
                    detector=self.name,
                    secret_type=detector_name,
                    relative_path=relative_path,
                    line=line,
                    confidence=0.84,
                    severity=secret_severity_for_type(detector_name),
                    evidence_fingerprint=fingerprint,
                    raw_secret=(
                        SecretStr(raw_secret)
                        if raw_secret is not None
                        else None
                    ),
                    metadata={
                        "external_scanner": True,
                        "raw_secret_stored": False,
                        "verification_attempted": False,
                        "trufflehog_no_verification": True,
                    },
                )
            )

            if len(findings) >= config.max_secret_findings:
                break

        return tuple(findings)


class MobileArtifactError(RuntimeError):
    """Unsafe, unsupported or invalid local artifact."""


class MobileWorker:
    """Offline mobile static-analysis worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        artifacts: MobileArtifactProvider,
        config: MobileAnalysisConfig | None = None,
        jadx: MobileDecompiler | None = None,
        apktool: MobileDecompiler | None = None,
        secret_scanners: Sequence[SecretScanner] | None = None,
        sensitive_evidence: SensitiveEvidenceSink | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._artifacts = artifacts
        self._config = config or MobileAnalysisConfig()

        self._jadx = jadx or JadxDecompiler()
        self._apktool = apktool or ApktoolDecompiler()

        self._secret_scanners = tuple(
            secret_scanners
            if secret_scanners is not None
            else (
                GitleaksSecretScanner(),
                TruffleHogSecretScanner(),
            )
        )

        self._sensitive_evidence: SensitiveEvidenceSink | None
        if sensitive_evidence is not None:
            self._sensitive_evidence = sensitive_evidence
        elif self._config.preserve_raw_secret_evidence:
            self._sensitive_evidence = WorkspaceSensitiveEvidenceStore(
                self._config.sensitive_evidence_root
            )
        else:
            self._sensitive_evidence = None

    async def execute(
        self,
        task: Task,
    ) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "mobile worker may only execute claimed RUNNING tasks, "
                    f"got {task.status.value}"
                ),
            )

        if task.worker != self.name:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    f"task worker mismatch: expected {self.name}, "
                    f"got {task.worker}"
                ),
            )

        if task.action != ACTION_ANALYZE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported mobile action: {task.action}",
            )

        input_event = await self._events.get_event(
            task.input_event_id
        )

        if input_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"input event not found: {task.input_event_id}",
            )

        if input_event.type is not EventType.MOBILE_ARTIFACT:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "mobile.analyze requires MOBILE_ARTIFACT input, got "
                    f"{input_event.type.value}"
                ),
            )

        material = await self._artifacts.material_for(
            input_event
        )

        if material is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "mobile artifact has no trusted local material; "
                    "this worker never downloads applications"
                ),
            )

        if material.size_bytes > self._config.max_artifact_bytes:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "mobile artifact exceeds configured size limit: "
                    f"{material.size_bytes} > "
                    f"{self._config.max_artifact_bytes}"
                ),
            )

        try:
            result = await self._analyze_material(
                material
            )
        except MobileArtifactError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )
        except OSError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"mobile local analysis I/O failure: {exc}",
            )

        await self._publish_result(
            input_event=input_event,
            material=material,
            result=result,
        )

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )

    async def _analyze_material(
        self,
        material: MobileArtifactMaterial,
    ) -> MobileAnalysisResult:
        with tempfile.TemporaryDirectory(
            prefix="nightscout-mobile-"
        ) as raw_workdir:
            work_dir = Path(raw_workdir)
            archive_dir = work_dir / "archive"

            await asyncio.to_thread(
                safe_extract_mobile_archive,
                material.path,
                archive_dir,
                self._config,
            )

            roots: list[
                tuple[str, Path]
            ] = [
                (
                    "archive",
                    archive_dir,
                )
            ]

            tools_used = [
                "python-safe-archive"
            ]

            warnings: list[str] = []

            if material.kind is MobileArtifactKind.APK:
                decompiled = False

                if (
                    self._config.enable_jadx
                    and self._jadx.available()
                ):
                    jadx_dir = work_dir / "jadx"

                    decompiled = await self._jadx.decompile(
                        material,
                        output_dir=jadx_dir,
                        work_dir=work_dir,
                        config=self._config,
                    )

                    if decompiled:
                        roots.append(("jadx", jadx_dir))
                        tools_used.append(self._jadx.name)
                    else:
                        warnings.append("jadx failed; continued with local fallback")

                if (
                    not decompiled
                    and self._config.enable_apktool_fallback
                    and self._apktool.available()
                ):
                    apktool_dir = work_dir / "apktool"

                    apktool_ok = await self._apktool.decompile(
                        material,
                        output_dir=apktool_dir,
                        work_dir=work_dir,
                        config=self._config,
                    )

                    if apktool_ok:
                        roots.append(("apktool", apktool_dir))
                        tools_used.append(self._apktool.name)
                    else:
                        warnings.append(
                            "apktool failed; continued with extracted archive"
                        )

            local_result = await asyncio.to_thread(
                scan_mobile_roots,
                roots,
                material,
                self._config,
            )

            secrets = list(
                local_result.secrets
            )

            scanner_view = work_dir / "scanner-view"

            if any(
                (
                    self._config.enable_gitleaks,
                    self._config.enable_trufflehog,
                )
            ):
                await asyncio.to_thread(
                    build_bounded_scanner_view,
                    roots,
                    scanner_view,
                    self._config,
                )

            for scanner in self._secret_scanners:
                if len(secrets) >= self._config.max_secret_findings:
                    break

                if not scanner.available():
                    continue

                if (
                    scanner.name == "gitleaks"
                    and not self._config.enable_gitleaks
                ):
                    continue

                if (
                    scanner.name == "trufflehog"
                    and not self._config.enable_trufflehog
                ):
                    continue

                findings = await scanner.scan(
                    scanner_view,
                    artifact_sha256=material.sha256,
                    work_dir=work_dir,
                    config=self._config,
                )

                if findings:
                    tools_used.append(scanner.name)
                    secrets.extend(findings)

            secrets = list(
                dedupe_secret_findings(
                    secrets
                )
            )[
                : self._config.max_secret_findings
            ]

            return local_result.model_copy(
                update={
                    "secrets": tuple(secrets),
                    "tools_used": tuple(
                        dict.fromkeys(
                            (
                                *local_result.tools_used,
                                *tools_used,
                            )
                        )
                    ),
                    "warnings": tuple(
                        dict.fromkeys(
                            (
                                *local_result.warnings,
                                *warnings,
                            )
                        )
                    ),
                }
            )

    async def _publish_result(
        self,
        *,
        input_event: Event,
        material: MobileArtifactMaterial,
        result: MobileAnalysisResult,
    ) -> None:
        source = (
            "mobile:apk-static"
            if material.kind is MobileArtifactKind.APK
            else "mobile:ipa-static"
        )

        common = {
            "local_static_analysis": True,
            "network_access": False,
            "artifact_kind": material.kind.value,
            "artifact_ref": material.content_ref,
            "artifact_sha256": material.sha256,
            "artifact_size_bytes": material.size_bytes,
        }

        for project in result.project_names:
            await self._publisher.publish(
                Event(
                    type=EventType.PROJECT_NAME,
                    value=project,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.94,
                    novelty=0.84,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "project-name",
                        "target-genome",
                    },
                    metadata={
                        **common,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for technology in result.technologies:
            await self._publisher.publish(
                Event(
                    type=EventType.TECHNOLOGY,
                    value=technology,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.86,
                    novelty=0.55,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "technology",
                        "target-genome",
                    },
                    metadata={
                        **common,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for url in result.urls:
            url_event = Event(
                type=EventType.URL,
                value=url,
                source=source,
                parent_event_id=input_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=0.90,
                novelty=0.92,
                depth=input_event.depth + 1,
                tags={
                    "mobile",
                    "url-reference",
                    "hypothesis",
                    "feeds-vocabulary",
                },
                metadata={
                    **common,
                    "requires_scope_reclassification": True,
                    "requires_live_confirmation": True,
                    "feeds_vocabulary": True,
                },
            )

            accepted = await self._publisher.publish(
                url_event
            )

            child_parent = (
                url_event.event_id
                if accepted
                else input_event.event_id
            )

            parts = urlsplit(url)

            if parts.hostname is not None:
                await self._publisher.publish(
                    Event(
                        type=EventType.DNS_NAME,
                        value=normalize_dns_name(parts.hostname),
                        source=source,
                        parent_event_id=child_parent,
                        scope_state=ScopeState.UNKNOWN,
                        confidence=0.88,
                        novelty=0.90,
                        depth=input_event.depth + 2,
                        tags={
                            "mobile",
                            "dns-candidate",
                            "hypothesis",
                            "feeds-vocabulary",
                        },
                        metadata={
                            **common,
                            "reference_url": url,
                            "requires_scope_reclassification": True,
                            "requires_dns_confirmation": True,
                            "feeds_vocabulary": True,
                        },
                    )
                )

        for hostname in result.dns_names:
            await self._publisher.publish(
                Event(
                    type=EventType.DNS_NAME,
                    value=hostname,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.82,
                    novelty=0.90,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "dns-candidate",
                        "hypothesis",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "requires_scope_reclassification": True,
                        "requires_dns_confirmation": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for endpoint in result.api_endpoints:
            await self._publisher.publish(
                Event(
                    type=EventType.API_ENDPOINT,
                    value=endpoint,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.86,
                    novelty=0.96,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "api-endpoint",
                        "hypothesis",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "requires_scope_reclassification": True,
                        "requires_live_confirmation": True,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for parameter in result.parameters:
            await self._publisher.publish(
                Event(
                    type=EventType.PARAMETER_NAME,
                    value=parameter,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.84,
                    novelty=0.80,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "parameter-name",
                        "feeds-vocabulary",
                    },
                    metadata={
                        **common,
                        "raw_value_stored": False,
                        "feeds_vocabulary": True,
                    },
                )
            )

        for token in result.vocabulary:
            await self._publisher.publish(
                Event(
                    type=EventType.VOCAB_TOKEN,
                    value=token,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.76,
                    novelty=0.87,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "vocabulary",
                        "target-specific",
                        "target-genome",
                    },
                    metadata={
                        **common,
                        "target_specific": True,
                        "raw_sensitive_value_stored": False,
                    },
                )
            )

        for deep_link in result.deep_links:
            await self._publisher.publish(
                Event(
                    type=EventType.ARTIFACT,
                    value=deep_link,
                    source=source,
                    parent_event_id=input_event.event_id,
                    scope_state=ScopeState.UNKNOWN,
                    confidence=0.82,
                    novelty=0.86,
                    depth=input_event.depth + 1,
                    tags={
                        "mobile",
                        "deep-link",
                        "artifact-candidate",
                    },
                    metadata={
                        **common,
                        "artifact_kind": "mobile-deep-link",
                        "network_request_performed": False,
                    },
                )
            )

        for secret in result.secrets:
            raw_secret_stored = False

            if (
                self._sensitive_evidence is not None
                and secret.raw_secret is not None
            ):
                raw_secret_stored = await self._sensitive_evidence.store(
                    SensitiveEvidenceRecord(
                        evidence_fingerprint=secret.evidence_fingerprint,
                        raw_secret=secret.raw_secret,
                        secret_type=secret.secret_type,
                        detector=secret.detector,
                        source_file=secret.relative_path,
                        line=secret.line,
                        column=secret.column,
                        artifact_ref=material.content_ref,
                        artifact_sha256=material.sha256,
                    )
                )

            await self._publish_secret_review(
                input_event=input_event,
                source=source,
                common=common,
                secret=secret,
                raw_secret_stored=raw_secret_stored,
            )

        await self._publisher.publish(
            Event(
                type=EventType.MOBILE_ARTIFACT,
                value=input_event.value,
                source=source,
                parent_event_id=input_event.event_id,
                scope_state=input_event.scope_state,
                confidence=0.99,
                novelty=0.35,
                depth=input_event.depth + 1,
                tags={
                    "mobile",
                    "analysis:complete",
                    "local-static-analysis",
                    material.kind.value.lower(),
                },
                metadata={
                    **common,
                    "files_scanned": result.files_scanned,
                    "bytes_scanned": result.bytes_scanned,
                    "url_count": len(result.urls),
                    "dns_name_count": len(result.dns_names),
                    "api_endpoint_count": len(result.api_endpoints),
                    "parameter_count": len(result.parameters),
                    "project_name_count": len(result.project_names),
                    "technology_count": len(result.technologies),
                    "vocabulary_token_count": len(result.vocabulary),
                    "deep_link_count": len(result.deep_links),
                    "possible_secret_count": len(result.secrets),
                    "package_identifiers": list(result.package_identifiers),
                    "tools_used": list(result.tools_used),
                    "warnings": list(result.warnings),
                    "credential_verification_attempted": False,
                    "credential_use_attempted": False,
                    "raw_secret_stored_in_event": False,
                },
            )
        )

    async def _publish_secret_review(
        self,
        *,
        input_event: Event,
        source: str,
        common: dict[str, Any],
        secret: SecretFinding,
        raw_secret_stored: bool,
    ) -> None:
        location = secret.relative_path

        if secret.line is not None:
            location += f":{secret.line}"

        safe_summary = (
            f"Possible {secret.secret_type} in mobile artifact at {location}; "
            "offline candidate only, not validated or used"
        )

        artifact_value = (
            "possible-secret:"
            + secret.evidence_fingerprint[:24]
        )

        safe_metadata = {
            **common,
            "artifact_kind": "possible-secret",
            "secret_type": secret.secret_type,
            "detector": secret.detector,
            "rule_id": secret.rule_id,
            "source_file": secret.relative_path,
            "line": secret.line,
            "column": secret.column,
            "confidence": secret.confidence,
            "severity": secret.severity.value,
            "evidence_fingerprint": secret.evidence_fingerprint,
            "masked_preview": secret.masked_preview,
            "raw_secret_stored": False,
            "raw_secret_stored_separately": raw_secret_stored,
            "sensitive_evidence_fingerprint": secret.evidence_fingerprint,
            "credential_used": False,
            "verification_attempted": False,
            "scanner_metadata": safe_secret_scanner_metadata(secret.metadata),
        }

        await self._publisher.publish(
            Event(
                type=EventType.ARTIFACT,
                value=artifact_value,
                source=(
                    f"{source}:secret:{secret.detector}"
                ),
                parent_event_id=input_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=secret.confidence,
                novelty=0.98,
                depth=input_event.depth + 1,
                tags={
                    "mobile",
                    "possible-secret",
                    "sensitive-artifact",
                    "human-review",
                },
                metadata=safe_metadata,
            )
        )

        await self._publisher.publish(
            Event(
                type=EventType.HUMAN_REVIEW,
                value=artifact_value,
                source=(
                    f"{source}:review:{secret.detector}"
                ),
                parent_event_id=input_event.event_id,
                scope_state=ScopeState.UNKNOWN,
                confidence=secret.confidence,
                novelty=0.99,
                depth=input_event.depth + 1,
                tags={
                    "mobile",
                    "possible-secret",
                    "human-review",
                },
                metadata={
                    **safe_metadata,
                    "review_category": "POSSIBLE_SECRET",
                    "review_severity": secret.severity.value,
                    "review_summary": safe_summary,
                    "pause_sensitive_followup": True,
                },
            )
        )


def mobile_route_rules(
    *,
    base_priority: float = 7.0,
) -> tuple[RouteRule, ...]:
    """Route only explicitly local, not-yet-analyzed mobile artifacts."""

    return (
        RouteRule(
            rule_id="mobile.analyze.local-artifact",
            accepts=frozenset(
                {
                    EventType.MOBILE_ARTIFACT,
                }
            ),
            worker=WORKER_NAME,
            action=ACTION_ANALYZE,
            reason=(
                "offline static analysis of an already materialized APK/IPA"
            ),
            base_priority=base_priority,
            required_tags=frozenset(
                {
                    "local",
                }
            ),
            excluded_tags=frozenset(
                {
                    "analysis:complete",
                }
            ),
            predicate=_has_local_artifact_reference,
        ),
    )


def _has_local_artifact_reference(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    return bool(
        event.metadata.get("artifact_ref")
        or event.metadata.get("content_ref")
    )


def mobile_artifact_kind(
    value: Any,
) -> MobileArtifactKind:
    raw = str(value).strip().lower()

    if raw.startswith("."):
        raw = raw[1:]

    if raw in {"apk", "android", "android-apk"}:
        return MobileArtifactKind.APK

    if raw in {"ipa", "ios", "ios-ipa"}:
        return MobileArtifactKind.IPA

    raise ValueError(f"unsupported mobile artifact kind: {value!r}")


def safe_extract_mobile_archive(
    artifact_path: Path,
    output_dir: Path,
    config: MobileAnalysisConfig,
) -> None:
    """Extract APK/IPA ZIP contents without traversal, links, or zip bombs."""

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    try:
        archive = zipfile.ZipFile(
            artifact_path,
            "r",
        )
    except (zipfile.BadZipFile, OSError) as exc:
        raise MobileArtifactError(
            f"mobile artifact is not a valid ZIP container: {exc}"
        ) from exc

    with archive:
        infos = archive.infolist()

        if len(infos) > config.max_archive_entries:
            raise MobileArtifactError(
                "mobile archive exceeds entry limit: "
                f"{len(infos)} > {config.max_archive_entries}"
            )

        declared_total = 0

        for info in infos:
            if info.file_size < 0:
                raise MobileArtifactError("negative ZIP member size")

            if info.file_size > config.max_archive_member_bytes:
                raise MobileArtifactError(
                    "mobile archive member exceeds size limit: "
                    f"{info.filename}"
                )

            declared_total += info.file_size

            if declared_total > config.max_archive_total_uncompressed_bytes:
                raise MobileArtifactError(
                    "mobile archive exceeds total uncompressed size limit"
                )

            relative = safe_zip_member_path(
                info.filename
            )

            if relative is None:
                raise MobileArtifactError(
                    f"unsafe mobile archive path: {info.filename!r}"
                )

            if zip_info_is_symlink(info):
                raise MobileArtifactError(
                    f"mobile archive symlink is not allowed: {info.filename!r}"
                )

            target = output_dir.joinpath(
                *relative.parts
            )

            resolved = target.resolve()

            try:
                resolved.relative_to(
                    output_dir.resolve()
                )
            except ValueError as exc:
                raise MobileArtifactError(
                    f"mobile archive member escapes extraction root: {info.filename!r}"
                ) from exc

            if info.is_dir():
                resolved.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                continue

            resolved.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            written = 0

            with archive.open(info, "r") as source, resolved.open("xb") as sink:
                while True:
                    chunk = source.read(
                        min(
                            1024 * 1024,
                            config.max_archive_member_bytes - written + 1,
                        )
                    )

                    if not chunk:
                        break

                    written += len(chunk)

                    if written > config.max_archive_member_bytes:
                        raise MobileArtifactError(
                            f"extracted member exceeded size limit: {info.filename!r}"
                        )

                    sink.write(chunk)

            try:
                os.chmod(
                    resolved,
                    stat.S_IRUSR | stat.S_IWUSR,
                )
            except OSError:
                pass


def safe_zip_member_path(
    value: str,
) -> PurePosixPath | None:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)

    if path.is_absolute():
        return None

    parts = tuple(
        part
        for part in path.parts
        if part not in {"", "."}
    )

    if not parts:
        return PurePosixPath(".")

    if any(part == ".." for part in parts):
        return None

    if ":" in parts[0]:
        return None

    return PurePosixPath(
        *parts
    )


def zip_info_is_symlink(
    info: zipfile.ZipInfo,
) -> bool:
    unix_mode = (
        info.external_attr
        >> 16
    )

    return stat.S_ISLNK(
        unix_mode
    )


def scan_mobile_roots(
    roots: Sequence[tuple[str, Path]],
    material: MobileArtifactMaterial,
    config: MobileAnalysisConfig,
) -> MobileAnalysisResult:
    accumulator = _MobileAccumulator(
        material=material,
        config=config,
    )

    for root_name, root in roots:
        accumulator.scan_root(
            root_name,
            root,
        )

    return accumulator.result()


class _MobileAccumulator:
    def __init__(
        self,
        *,
        material: MobileArtifactMaterial,
        config: MobileAnalysisConfig,
    ) -> None:
        self.material = material
        self.config = config

        self.urls: set[str] = set()
        self.dns_names: set[str] = set()
        self.api_endpoints: set[str] = set()
        self.parameters: set[str] = set()
        self.project_names: set[str] = set()
        self.technologies: set[str] = set()
        self.vocabulary_counter: Counter[str] = Counter()
        self.deep_links: set[str] = set()
        self.package_identifiers: set[str] = set()
        self.secrets: list[SecretFinding] = []

        self.files_scanned = 0
        self.bytes_scanned = 0

        self._seen_files: set[
            tuple[str, int, int]
        ] = set()

    def scan_root(
        self,
        root_name: str,
        root: Path,
    ) -> None:
        if not root.is_dir():
            return

        for path in sorted(
            root.rglob("*")
        ):
            if (
                self.files_scanned
                >= self.config.max_files_scanned
                or self.bytes_scanned
                >= self.config.max_total_scan_bytes
            ):
                break

            if path.is_symlink() or not path.is_file():
                continue

            try:
                stat_result = path.stat()
            except OSError:
                continue

            identity = (
                str(path.resolve()),
                stat_result.st_size,
                stat_result.st_mtime_ns,
            )

            if identity in self._seen_files:
                continue

            self._seen_files.add(
                identity
            )

            remaining = (
                self.config.max_total_scan_bytes
                - self.bytes_scanned
            )

            read_limit = min(
                self.config.max_file_scan_bytes,
                remaining,
            )

            if read_limit <= 0:
                break

            try:
                with path.open("rb") as handle:
                    data = handle.read(
                        read_limit
                    )
            except OSError:
                continue

            self.files_scanned += 1
            self.bytes_scanned += len(data)

            relative = (
                Path(root_name)
                / path.relative_to(root)
            ).as_posix()

            self.scan_file(
                relative,
                path,
                data,
            )

    def scan_file(
        self,
        relative_path: str,
        path: Path,
        data: bytes,
    ) -> None:
        suffix = path.suffix.lower()

        if suffix == ".plist":
            self.scan_plist(
                relative_path,
                data,
            )

        text = decode_maybe_text(
            data
        )

        if text is not None:
            self.scan_text(
                relative_path,
                text,
            )

        # Printable binary strings recover useful values from classes.dex,
        # Mach-O binaries, native libraries and compiled resource blobs.
        for binary_string in printable_strings(
            data,
            min_length=self.config.min_printable_string_length,
        ):
            self.scan_text_fragment(
                relative_path,
                binary_string,
                line=None,
            )

    def scan_plist(
        self,
        relative_path: str,
        data: bytes,
    ) -> None:
        try:
            payload = plistlib.loads(
                data
            )
        except Exception:
            return

        for key, value in walk_plist(
            payload
        ):
            if key in {
                "CFBundleIdentifier",
                "CFBundleName",
                "CFBundleDisplayName",
                "CFBundleExecutable",
            } and isinstance(value, str):
                self.add_project(
                    value
                )

                if key == "CFBundleIdentifier":
                    self.package_identifiers.add(
                        value.strip()
                    )

            if isinstance(value, str):
                self.scan_text_fragment(
                    relative_path,
                    value,
                    line=None,
                )

            if isinstance(key, str):
                self.add_vocabulary_from_text(
                    key
                )

    def scan_text(
        self,
        relative_path: str,
        text: str,
    ) -> None:
        self.extract_mobile_identity(
            text
        )
        self.detect_technologies(
            text
        )

        for line_number, line in enumerate(
            text.splitlines(),
            start=1,
        ):
            self.scan_text_fragment(
                relative_path,
                line,
                line=line_number,
            )

            if (
                self.config.enable_builtin_secret_scan
                and len(self.secrets)
                < self.config.max_secret_findings
            ):
                self.secrets.extend(
                    builtin_secret_findings(
                        line,
                        relative_path=relative_path,
                        line_number=line_number,
                        artifact_sha256=self.material.sha256,
                        include_masked_preview=(
                            self.config.include_masked_secret_preview
                        ),
                        remaining=(
                            self.config.max_secret_findings
                            - len(self.secrets)
                        ),
                    )
                )

    def scan_text_fragment(
        self,
        relative_path: str,
        text: str,
        *,
        line: int | None,
    ) -> None:
        del relative_path, line

        for raw_url in URL_RE.findall(
            text
        ):
            url = normalize_mobile_url(
                trim_url_punctuation(
                    raw_url
                )
            )

            if url is None:
                continue

            if (
                url in self.urls
                or len(self.urls) < self.config.max_urls
            ):
                self.urls.add(
                    url
                )

            parts = urlsplit(
                url
            )

            if parts.hostname is not None:
                try:
                    normalized_host = normalize_dns_name(
                        parts.hostname
                    )
                    if (
                        normalized_host in self.dns_names
                        or len(self.dns_names) < self.config.max_dns_names
                    ):
                        self.dns_names.add(
                            normalized_host
                        )
                except ValueError:
                    pass

            if looks_like_api_url(
                url
            ):
                endpoint = api_endpoint_identity(
                    url
                )
                if (
                    endpoint in self.api_endpoints
                    or len(self.api_endpoints) < self.config.max_api_endpoints
                ):
                    self.api_endpoints.add(
                        endpoint
                    )

            for parameter in query_parameter_names(
                url
            ):
                if (
                    parameter in self.parameters
                    or len(self.parameters) < self.config.max_parameters
                ):
                    self.parameters.add(
                        parameter
                    )

            self.add_vocabulary_from_url(
                url
            )

        for deep_link in DEEP_LINK_RE.findall(
            text
        ):
            value = trim_url_punctuation(
                deep_link
            )

            scheme = value.split(
                ":",
                1,
            )[0].lower()

            if scheme in {
                "http",
                "https",
                "javascript",
                "data",
                "file",
            }:
                continue

            if (
                len(value) <= 2048
                and (
                    value in self.deep_links
                    or len(self.deep_links) < self.config.max_deep_links
                )
            ):
                self.deep_links.add(
                    value
                )

                self.add_vocabulary_from_text(
                    value
                )

        for host in ANDROID_HOST_RE.findall(
            text
        ):
            host = host.strip()

            if not host or host.startswith("@"):
                continue

            try:
                normalized = normalize_dns_name(
                    host
                )
            except ValueError:
                continue

            if (
                normalized in self.dns_names
                or len(self.dns_names) < self.config.max_dns_names
            ):
                self.dns_names.add(
                    normalized
                )
            self.add_vocabulary_from_hostname(
                normalized
            )

        self.add_vocabulary_from_text(
            text
        )

    def extract_mobile_identity(
        self,
        text: str,
    ) -> None:
        for package in ANDROID_PACKAGE_RE.findall(
            text
        ):
            package = package.strip()

            if not package:
                continue

            if (
                package in self.package_identifiers
                or len(self.package_identifiers) < self.config.max_projects
            ):
                self.package_identifiers.add(
                    package
                )
            self.add_project(
                package
            )

        for application_id in GRADLE_APPLICATION_ID_RE.findall(
            text
        ):
            application_id = application_id.strip()

            if application_id:
                if (
                    application_id in self.package_identifiers
                    or len(self.package_identifiers) < self.config.max_projects
                ):
                    self.package_identifiers.add(
                        application_id
                    )
                self.add_project(
                    application_id
                )

    def add_project(
        self,
        value: str,
    ) -> None:
        normalized = value.strip()

        if (
            not normalized
            or len(normalized) > 255
        ):
            return

        if (
            len(self.project_names)
            < self.config.max_projects
        ):
            self.project_names.add(
                normalized
            )

        self.add_vocabulary_from_text(
            normalized
        )

    def detect_technologies(
        self,
        text: str,
    ) -> None:
        lowered = text.lower()

        for marker, technology in TECHNOLOGY_MARKERS:
            if marker in lowered:
                if (
                    len(self.technologies)
                    < self.config.max_technologies
                ):
                    self.technologies.add(
                        technology
                    )

    def add_vocabulary_from_url(
        self,
        url: str,
    ) -> None:
        parts = urlsplit(
            url
        )

        if parts.hostname is not None:
            self.add_vocabulary_from_hostname(
                parts.hostname
            )

        for segment in parts.path.split(
            "/"
        ):
            self.add_vocabulary_from_text(
                segment
            )

        for parameter in query_parameter_names(
            url
        ):
            self.add_vocabulary_from_text(
                parameter
            )

    def add_vocabulary_from_hostname(
        self,
        hostname: str,
    ) -> None:
        for label in hostname.split(
            "."
        ):
            self.add_vocabulary_from_text(
                label
            )

    def add_vocabulary_from_text(
        self,
        value: str,
    ) -> None:
        if len(value) > 4096:
            return

        vocabulary_cap = (
            self.config.max_vocabulary_tokens
            * 4
        )

        for token in tokenize_mobile_text(
            value
        ):
            if (
                token not in self.vocabulary_counter
                and len(self.vocabulary_counter) >= vocabulary_cap
            ):
                continue

            self.vocabulary_counter[
                token
            ] += 1

    def result(
        self,
    ) -> MobileAnalysisResult:
        vocabulary = tuple(
            token
            for token, _count in sorted(
                self.vocabulary_counter.items(),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )[
                : self.config.max_vocabulary_tokens
            ]
        )

        return MobileAnalysisResult(
            urls=tuple(
                sorted(self.urls)
                [: self.config.max_urls]
            ),
            dns_names=tuple(
                sorted(self.dns_names)
                [: self.config.max_dns_names]
            ),
            api_endpoints=tuple(
                sorted(self.api_endpoints)
                [: self.config.max_api_endpoints]
            ),
            parameters=tuple(
                sorted(self.parameters)
                [: self.config.max_parameters]
            ),
            project_names=tuple(
                sorted(self.project_names)
                [: self.config.max_projects]
            ),
            technologies=tuple(
                sorted(self.technologies)
                [: self.config.max_technologies]
            ),
            vocabulary=vocabulary,
            deep_links=tuple(
                sorted(self.deep_links)
                [: self.config.max_deep_links]
            ),
            secrets=tuple(
                dedupe_secret_findings(
                    self.secrets
                )
            )[
                : self.config.max_secret_findings
            ],
            files_scanned=self.files_scanned,
            bytes_scanned=self.bytes_scanned,
            package_identifiers=tuple(
                sorted(self.package_identifiers)
            ),
            tools_used=(
                "builtin-static-scanner",
            ),
        )


def build_bounded_scanner_view(
    roots: Sequence[tuple[str, Path]],
    destination: Path,
    config: MobileAnalysisConfig,
) -> None:
    """Copy only bounded regular files into an isolated external-scanner view."""

    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    total = 0
    files = 0

    for root_name, root in roots:
        if not root.is_dir():
            continue

        for source in sorted(
            root.rglob("*")
        ):
            if (
                files
                >= config.max_files_scanned
                or total
                >= config.external_scan_max_total_bytes
            ):
                return

            if source.is_symlink() or not source.is_file():
                continue

            try:
                size = source.stat().st_size
            except OSError:
                continue

            if (
                size > config.external_scan_max_file_bytes
                or total + size > config.external_scan_max_total_bytes
            ):
                continue

            relative = (
                Path(root_name)
                / source.relative_to(root)
            )

            # Prevent target-controlled scanner configuration/ignore files from
            # changing detector behavior in the isolated view.
            if relative.name.lower() in {
                ".gitleaks.toml",
                ".gitleaksignore",
                "gitleaks.toml",
            }:
                continue

            target = destination / relative
            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copyfile(
                source,
                target,
            )

            try:
                os.chmod(
                    target,
                    stat.S_IRUSR | stat.S_IWUSR,
                )
            except OSError:
                pass

            total += size
            files += 1


def builtin_secret_findings(
    line: str,
    *,
    relative_path: str,
    line_number: int,
    artifact_sha256: str,
    include_masked_preview: bool,
    remaining: int,
) -> tuple[SecretFinding, ...]:
    if remaining <= 0:
        return ()

    findings: list[SecretFinding] = []

    for rule in BUILTIN_SECRET_RULES:
        for match in rule.pattern.finditer(
            line
        ):
            secret = (
                match.groupdict().get("secret")
                or match.group(0)
            )

            if not secret or is_placeholder_secret(
                secret
            ):
                continue

            column = match.start() + 1

            fingerprint = secret_location_fingerprint(
                artifact_sha256=artifact_sha256,
                detector="builtin",
                secret_type=rule.secret_type,
                relative_path=relative_path,
                line=line_number,
                column=column,
                rule_id=rule.rule_id,
            )

            findings.append(
                SecretFinding(
                    detector="builtin",
                    secret_type=rule.secret_type,
                    relative_path=relative_path,
                    line=line_number,
                    column=column,
                    rule_id=rule.rule_id,
                    confidence=rule.confidence,
                    severity=rule.severity,
                    evidence_fingerprint=fingerprint,
                    masked_preview=(
                        mask_secret(secret)
                        if include_masked_preview
                        else None
                    ),
                    raw_secret=SecretStr(secret),
                    metadata={
                        "external_scanner": False,
                        "raw_secret_stored": False,
                        "verification_attempted": False,
                    },
                )
            )

            if len(findings) >= remaining:
                return tuple(findings)

    return tuple(findings)


class _BuiltinSecretRule(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        arbitrary_types_allowed=True,
    )

    rule_id: str
    secret_type: str
    pattern: re.Pattern[str]
    confidence: float = Field(ge=0.0, le=1.0)
    severity: SecretSeverity


BUILTIN_SECRET_RULES: tuple[_BuiltinSecretRule, ...] = (
    _BuiltinSecretRule(
        rule_id="private-key-header",
        secret_type="private-key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        confidence=0.99,
        severity=SecretSeverity.CRITICAL,
    ),
    _BuiltinSecretRule(
        rule_id="aws-access-key-id",
        secret_type="aws-access-key-id",
        pattern=re.compile(
            r"(?P<secret>AKIA[0-9A-Z]{16})"
        ),
        confidence=0.98,
        severity=SecretSeverity.HIGH,
    ),
    _BuiltinSecretRule(
        rule_id="google-api-key",
        secret_type="google-api-key",
        pattern=re.compile(
            r"(?P<secret>AIza[0-9A-Za-z_-]{35})"
        ),
        confidence=0.96,
        severity=SecretSeverity.HIGH,
    ),
    _BuiltinSecretRule(
        rule_id="github-token",
        secret_type="github-token",
        pattern=re.compile(
            r"(?P<secret>gh(?:p|o|u|s|r)_[0-9A-Za-z]{20,255})"
        ),
        confidence=0.96,
        severity=SecretSeverity.HIGH,
    ),
    _BuiltinSecretRule(
        rule_id="stripe-live-secret",
        secret_type="stripe-live-secret-key",
        pattern=re.compile(
            r"(?P<secret>sk_live_[0-9A-Za-z]{16,128})"
        ),
        confidence=0.98,
        severity=SecretSeverity.CRITICAL,
    ),
    _BuiltinSecretRule(
        rule_id="slack-token",
        secret_type="slack-token",
        pattern=re.compile(
            r"(?P<secret>xox[baprs]-[0-9A-Za-z-]{10,200})"
        ),
        confidence=0.94,
        severity=SecretSeverity.HIGH,
    ),
    _BuiltinSecretRule(
        rule_id="jwt-like",
        secret_type="jwt-like-token",
        pattern=re.compile(
            r"(?P<secret>eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,})"
        ),
        confidence=0.82,
        severity=SecretSeverity.HIGH,
    ),
    _BuiltinSecretRule(
        rule_id="generic-secret-assignment",
        secret_type="generic-hardcoded-secret",
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"bearer[_-]?token|password|passwd|secret)\s*[=:]\s*[\"']?"
            r"(?P<secret>[A-Za-z0-9+/=_\-.:]{10,256})"
        ),
        confidence=0.72,
        severity=SecretSeverity.MEDIUM,
    ),
)


URL_RE = re.compile(
    r"https?://[^\s\"'<>\\]{3,4096}",
    re.IGNORECASE,
)

DEEP_LINK_RE = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,30}://[^\s\"'<>\\]{1,2048}"
)

ANDROID_HOST_RE = re.compile(
    r"android:host\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

ANDROID_PACKAGE_RE = re.compile(
    r"<manifest\b[^>]*\bpackage\s*=\s*[\"']([A-Za-z0-9_.-]{3,255})[\"']",
    re.IGNORECASE,
)

GRADLE_APPLICATION_ID_RE = re.compile(
    r"\bapplicationId\s*[=( ]+\s*[\"']([A-Za-z0-9_.-]{3,255})[\"']",
    re.IGNORECASE,
)

API_TOKEN_SPLIT_RE = re.compile(
    r"[-_.]+"
)

CAMEL_BOUNDARY_RE = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])"
)

TOKEN_SPLIT_RE = re.compile(
    r"[^A-Za-z0-9]+"
)

PRINTABLE_RE_CACHE: dict[int, re.Pattern[bytes]] = {}

TECHNOLOGY_MARKERS: tuple[tuple[str, str], ...] = (
    ("okhttp3", "OkHttp"),
    ("retrofit2", "Retrofit"),
    ("com.google.firebase", "Firebase"),
    ("firebaseapp.com", "Firebase"),
    ("reactnative", "React Native"),
    ("react-native", "React Native"),
    ("libflutter", "Flutter"),
    ("flutterassets", "Flutter"),
    ("capacitor", "Capacitor"),
    ("cordova", "Apache Cordova"),
    ("alamofire", "Alamofire"),
    ("afnetworking", "AFNetworking"),
    ("apollo", "Apollo GraphQL"),
    ("graphql", "GraphQL"),
    ("realm", "Realm"),
    ("sentry", "Sentry"),
)

VOCAB_STOPWORDS = frozenset(
    {
        "android",
        "java",
        "kotlin",
        "string",
        "value",
        "values",
        "resource",
        "resources",
        "layout",
        "drawable",
        "manifest",
        "application",
        "activity",
        "fragment",
        "context",
        "intent",
        "bundle",
        "class",
        "public",
        "private",
        "static",
        "final",
        "return",
        "true",
        "false",
        "null",
        "object",
        "function",
        "window",
        "document",
    }
)


def normalize_mobile_url(
    value: str,
) -> str | None:
    raw = value.strip()

    if not raw or len(raw) > 16_384:
        return None

    try:
        parts = urlsplit(
            raw
        )
    except ValueError:
        return None

    scheme = parts.scheme.lower()

    if scheme not in {
        "http",
        "https",
    }:
        return None

    # Userinfo may itself be a credential. Do not normalize/publish it as an
    # ordinary URL where it could leak into logs.
    if (
        parts.username is not None
        or parts.password is not None
    ):
        return None

    if parts.hostname is None:
        return None

    try:
        hostname = normalize_dns_name(
            parts.hostname
        )
        port = parts.port
    except ValueError:
        return None

    default_port = (
        443
        if scheme == "https"
        else 80
    )

    netloc = (
        hostname
        if port is None or port == default_port
        else f"{hostname}:{port}"
    )

    return urlunsplit(
        (
            scheme,
            netloc,
            parts.path or "/",
            parts.query,
            "",
        )
    )


def trim_url_punctuation(
    value: str,
) -> str:
    return value.rstrip(
        ".,;:!?)]}"
    )


def looks_like_api_url(
    url: str,
) -> bool:
    parts = urlsplit(
        url
    )

    path = parts.path.lower()

    if re.search(
        r"/(?:api|rest)(?:/[^/?#]+)*/v[0-9]+(?:/|$)",
        path,
        flags=re.IGNORECASE,
    ):
        return True

    for segment in path.split(
        "/"
    ):
        tokens = {
            token
            for token in API_TOKEN_SPLIT_RE.split(
                segment
            )
            if token
        }

        if {
            "api",
            "rest",
            "graphql",
            "graphiql",
            "swagger",
            "openapi",
        } & tokens:
            return True

    return False


def api_endpoint_identity(
    url: str,
) -> str:
    parts = urlsplit(
        url
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path or "/",
            "",
            "",
        )
    )


def query_parameter_names(
    url: str,
) -> tuple[str, ...]:
    query = urlsplit(
        url
    ).query

    if not query:
        return ()

    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=4096,
        )
    except ValueError:
        return ()

    return tuple(
        sorted(
            {
                name.strip()
                for name, _value in pairs
                if name.strip()
                and len(name.strip()) <= 256
            }
        )
    )


def tokenize_mobile_text(
    value: str,
) -> tuple[str, ...]:
    result: list[str] = []

    for coarse in TOKEN_SPLIT_RE.split(
        value
    ):
        if not coarse:
            continue

        for part in CAMEL_BOUNDARY_RE.split(
            coarse
        ):
            normalized = part.strip().lower()

            if (
                len(normalized) < 2
                or len(normalized) > 64
                or normalized in VOCAB_STOPWORDS
                or normalized.isdigit()
            ):
                continue

            if (
                len(normalized) >= 24
                and looks_hash_like(
                    normalized
                )
            ):
                continue

            if not any(
                character.isalpha()
                for character in normalized
            ):
                continue

            if normalized not in result:
                result.append(
                    normalized
                )

    return tuple(
        result
    )


def looks_hash_like(
    value: str,
) -> bool:
    if not value:
        return False

    hex_fraction = (
        sum(
            character in "0123456789abcdef"
            for character in value.lower()
        )
        / len(value)
    )

    return hex_fraction >= 0.90


def decode_maybe_text(
    data: bytes,
) -> str | None:
    if not data:
        return None

    nul_fraction = (
        data.count(b"\x00")
        / len(data)
    )

    if nul_fraction > 0.15:
        return None

    text = data.decode(
        "utf-8",
        errors="replace",
    )

    replacement_fraction = (
        text.count("\ufffd")
        / max(
            1,
            len(text),
        )
    )

    if replacement_fraction > 0.15:
        return None

    return text


def printable_strings(
    data: bytes,
    *,
    min_length: int,
) -> Iterable[str]:
    pattern = PRINTABLE_RE_CACHE.get(
        min_length
    )

    if pattern is None:
        pattern = re.compile(
            rb"[\x20-\x7e]{" + str(min_length).encode("ascii") + rb",}"
        )
        PRINTABLE_RE_CACHE[
            min_length
        ] = pattern

    for match in pattern.finditer(
        data
    ):
        yield match.group(0).decode(
            "ascii",
            errors="ignore",
        )


def walk_plist(
    payload: Any,
    *,
    parent_key: str = "",
) -> Iterable[tuple[str, Any]]:
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_text = str(
                key
            )
            yield key_text, value
            yield from walk_plist(
                value,
                parent_key=key_text,
            )

    elif isinstance(
        payload,
        (list, tuple),
    ):
        for value in payload:
            yield parent_key, value
            yield from walk_plist(
                value,
                parent_key=parent_key,
            )


def secret_location_fingerprint(
    *,
    artifact_sha256: str,
    detector: str,
    secret_type: str,
    relative_path: str,
    line: int | None,
    column: int | None,
    rule_id: str | None,
) -> str:
    """Stable fingerprint without hashing the secret itself.

    Location + immutable artifact digest changes when the application changes,
    while avoiding an offline password/API-key dictionary oracle.
    """

    material = "|".join(
        (
            artifact_sha256,
            detector.strip().lower(),
            secret_type.strip().lower(),
            relative_path.strip(),
            str(line or 0),
            str(column or 0),
            (rule_id or "").strip().lower(),
        )
    )

    return hashlib.sha256(
        material.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def mask_secret(
    value: str,
) -> str:
    length = len(
        value
    )

    if length <= 4:
        return f"<redacted:{length}>"

    if length <= 10:
        return (
            value[:1]
            + "*" * min(
                8,
                length - 2,
            )
            + value[-1:]
            + f" (len={length})"
        )

    return (
        value[:2]
        + "*" * 8
        + value[-2:]
        + f" (len={length})"
    )


def is_placeholder_secret(
    value: str,
) -> bool:
    lowered = value.strip().lower()

    if not lowered:
        return True

    placeholder_tokens = {
        "changeme",
        "password",
        "password123",
        "example",
        "example123",
        "your_api_key",
        "your-api-key",
        "api_key_here",
        "token_here",
        "secret_here",
        "xxxxxxxxxx",
        "0000000000",
    }

    if lowered in placeholder_tokens:
        return True

    return bool(
        re.fullmatch(
            r"(?:x+|0+|1+|a+|test(?:ing)?|dummy|sample|placeholder)",
            lowered,
        )
    )


def safe_secret_scanner_metadata(
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Whitelist scanner diagnostics that are safe to copy into Events."""

    allowed = (
        "external_scanner",
        "scanner_redaction",
        "verification_attempted",
        "trufflehog_no_verification",
    )

    return {
        key: metadata[key]
        for key in allowed
        if key in metadata
        and isinstance(
            metadata[key],
            (str, int, float, bool, type(None)),
        )
    }


def secret_severity_for_type(
    secret_type: str,
) -> SecretSeverity:
    lowered = secret_type.lower()

    if any(
        token in lowered
        for token in (
            "private-key",
            "private key",
            "stripe",
            "secret-access-key",
        )
    ):
        return SecretSeverity.CRITICAL

    if any(
        token in lowered
        for token in (
            "token",
            "api-key",
            "api key",
            "credential",
            "client-secret",
            "password",
            "aws",
            "github",
            "slack",
        )
    ):
        return SecretSeverity.HIGH

    return SecretSeverity.MEDIUM


def dedupe_secret_findings(
    findings: Sequence[SecretFinding],
) -> tuple[SecretFinding, ...]:
    best: dict[
        tuple[str, str, int, int],
        SecretFinding,
    ] = {}

    for finding in findings:
        key = (
            finding.relative_path,
            normalize_secret_type_family(
                finding.secret_type
            ),
            finding.line or 0,
            finding.column or 0,
        )

        existing = best.get(
            key
        )

        if existing is None:
            best[key] = finding
            continue

        finding_rank = (
            finding.confidence,
            secret_severity_rank(finding.severity),
        )
        existing_rank = (
            existing.confidence,
            secret_severity_rank(existing.severity),
        )

        if finding_rank > existing_rank:
            selected = finding
            fallback = existing
        else:
            selected = existing
            fallback = finding

        # Preserve an exact raw value when either detector captured one, while
        # retaining the stronger detector's classification/provenance.
        if selected.raw_secret is None and fallback.raw_secret is not None:
            selected = selected.model_copy(
                update={
                    "raw_secret": fallback.raw_secret,
                }
            )

        best[key] = selected

    return tuple(
        sorted(
            best.values(),
            key=lambda finding: (
                -secret_severity_rank(
                    finding.severity
                ),
                -finding.confidence,
                finding.relative_path,
                finding.line or 0,
                finding.secret_type,
            ),
        )
    )


def normalize_secret_type_family(
    value: str,
) -> str:
    lowered = value.strip().lower()

    if "aws" in lowered:
        return "aws"
    if "github" in lowered:
        return "github"
    if "slack" in lowered:
        return "slack"
    if "stripe" in lowered:
        return "stripe"
    if "private" in lowered and "key" in lowered:
        return "private-key"
    if "jwt" in lowered:
        return "jwt"
    if "password" in lowered or "passwd" in lowered:
        return "password"
    if "token" in lowered:
        return "token"
    if "api" in lowered and "key" in lowered:
        return "api-key"

    return lowered


def secret_severity_rank(
    value: SecretSeverity,
) -> int:
    return {
        SecretSeverity.MEDIUM: 20,
        SecretSeverity.HIGH: 30,
        SecretSeverity.CRITICAL: 40,
    }[
        value
    ]


def trufflehog_location(
    payload: dict[str, Any],
) -> tuple[str, int | None]:
    source_metadata = payload.get(
        "SourceMetadata"
    )

    candidates: list[
        dict[str, Any]
    ] = []

    if isinstance(
        source_metadata,
        dict,
    ):
        data = source_metadata.get(
            "Data"
        )

        if isinstance(
            data,
            dict,
        ):
            for value in data.values():
                if isinstance(
                    value,
                    dict,
                ):
                    candidates.append(
                        value
                    )

    candidates.append(
        payload
    )

    for item in candidates:
        raw_path = (
            item.get("file")
            or item.get("File")
            or item.get("path")
            or item.get("Path")
        )

        if raw_path is not None:
            path = safe_scanner_relative_path(
                raw_path
            )
            line = positive_int(
                item.get("line")
                or item.get("Line")
            )
            return path, line

    return "unknown", None


def safe_scanner_relative_path(
    value: Any,
) -> str:
    raw = str(value).strip().replace(
        "\\",
        "/",
    )

    if not raw:
        return "unknown"

    parts = [
        part
        for part in raw.split(
            "/"
        )
        if part
        and part not in {
            ".",
            "..",
        }
    ]

    if not parts:
        return "unknown"

    # Scanner view contains archive/... or jadx/... paths. Keep only bounded
    # tail components and never expose the temporary absolute prefix.
    return "/".join(
        parts[-12:]
    )[
        :1024
    ]


def optional_text(
    value: Any,
) -> str | None:
    if value is None:
        return None

    normalized = str(
        value
    ).strip()

    return normalized or None


def positive_int(
    value: Any,
) -> int | None:
    try:
        parsed = int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    return parsed if parsed > 0 else None


def hash_file(
    path: Path,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0

    with path.open(
        "rb"
    ) as handle:
        while True:
            chunk = handle.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )
            size += len(
                chunk
            )

    return digest.hexdigest(), size


def resolve_executable(
    binary: str,
) -> str | None:
    candidate = Path(
        binary
    ).expanduser()

    if (
        candidate.parent != Path(".")
        or candidate.is_absolute()
    ):
        if (
            candidate.exists()
            and candidate.is_file()
            and os.access(
                candidate,
                os.X_OK,
            )
        ):
            return str(
                candidate.resolve()
            )

        return None

    return shutil.which(
        binary
    )


def safe_subprocess_env(
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Minimal environment to avoid leaking ambient cloud/app credentials."""

    allowed = (
        "PATH",
        "JAVA_HOME",
        "LANG",
        "LC_ALL",
        "SYSTEMROOT",
        "WINDIR",
        "TMPDIR",
        "TEMP",
        "TMP",
    )

    env = {
        key: os.environ[key]
        for key in allowed
        if key in os.environ
    }

    env.setdefault(
        "LANG",
        "C.UTF-8",
    )

    if extra:
        env.update(
            extra
        )

    # Explicitly ensure target-controlled Gitleaks settings are not inherited.
    for key in (
        "GITLEAKS_CONFIG",
        "GITLEAKS_CONFIG_TOML",
    ):
        env.pop(
            key,
            None,
        )

    return env


async def run_bounded_process(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: Path,
    env: dict[str, str],
) -> bool:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=1024 * 1024,
    )

    assert process.stdout is not None
    assert process.stderr is not None

    stdout_tail: deque[bytes] = deque(
        maxlen=64
    )
    stderr_tail: deque[bytes] = deque(
        maxlen=64
    )

    async def drain(
        stream: asyncio.StreamReader,
        tail: deque[bytes],
    ) -> None:
        while True:
            line = await stream.readline()

            if not line:
                return

            tail.append(
                line[:4096]
            )

    stdout_task = asyncio.create_task(
        drain(
            process.stdout,
            stdout_tail,
        )
    )
    stderr_task = asyncio.create_task(
        drain(
            process.stderr,
            stderr_tail,
        )
    )

    try:
        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            await terminate_process(
                process
            )
            return False
    finally:
        await asyncio.gather(
            stdout_task,
            stderr_task,
            return_exceptions=True,
        )

    return process.returncode == 0


async def run_jsonl_process(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: Path,
    env: dict[str, str],
    max_lines: int,
) -> tuple[dict[str, Any], ...]:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(cwd),
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=2 * 1024 * 1024,
    )

    assert process.stdout is not None
    assert process.stderr is not None

    results: list[
        dict[str, Any]
    ] = []

    stderr_task = asyncio.create_task(
        drain_stream(
            process.stderr
        )
    )

    try:
        try:
            async with asyncio.timeout(
                timeout_seconds
            ):
                while True:
                    raw = await process.stdout.readline()

                    if not raw:
                        break

                    if len(results) >= max_lines:
                        await terminate_process(
                            process
                        )
                        break

                    try:
                        payload = json.loads(
                            raw.decode(
                                "utf-8",
                                errors="replace",
                            )
                        )
                    except json.JSONDecodeError:
                        continue

                    if isinstance(
                        payload,
                        dict,
                    ):
                        results.append(
                            payload
                        )

                if process.returncode is None:
                    await process.wait()

        except TimeoutError:
            await terminate_process(
                process
            )
            return tuple(
                results
            )

    finally:
        await asyncio.gather(
            stderr_task,
            return_exceptions=True,
        )

    if process.returncode not in {
        0,
        None,
    }:
        return ()

    return tuple(
        results
    )


async def drain_stream(
    stream: asyncio.StreamReader,
) -> None:
    while True:
        raw = await stream.readline()

        if not raw:
            return


async def terminate_process(
    process: asyncio.subprocess.Process,
) -> None:
    if process.returncode is not None:
        return

    process.terminate()

    try:
        await asyncio.wait_for(
            process.wait(),
            timeout=2.0,
        )
    except TimeoutError:
        process.kill()
        await process.wait()
