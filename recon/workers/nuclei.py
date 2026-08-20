"""Controlled Nuclei validation for Night Scout CVE candidates.

This worker is deliberately NOT a generic ``nuclei -u target`` wrapper.

It consumes a ``VULNERABILITY_CANDIDATE`` event produced by
``recon.intelligence.vulnerabilities`` and will run at most one locally audited,
hash-pinned HTTP template selected for that CVE.

Safety boundary
---------------
Automatic execution is limited to templates which pass all of these checks:

* explicitly listed in an audited local manifest;
* template file is inside the configured templates root;
* exact SHA-256 matches the manifest pin;
* HTTP protocol only;
* GET / HEAD / OPTIONS only;
* bounded request count;
* no raw requests, request bodies, payloads, fuzzing, race conditions, unsafe
  HTTP, workflow/flow, code, JavaScript, headless, network, DNS, SSL, file,
  websocket, whois or OAST/interactsh;
* no Authorization/Cookie/Host/client-certificate style overrides;
* every request path is rooted at ``{{BaseURL}}`` or ``{{RootURL}}``;
* redirects disabled;
* no authenticated target scan, proxy, cloud upload, template update, local
  file access or environment-variable expansion.

The subprocess also receives a conservative Nuclei CLI configuration and runs
under an exclusive shared-host RateLimiter lease, just like other opaque
multi-request workers.

A Nuclei match is recorded as an automated target match requiring manual
validation.  It does not mean exploitation occurred and it does not override
scope, program restrictions, budgets, review policy or human judgment.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import shutil
import tempfile
from collections import deque
from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import WorkerExecutionResult, WorkerOutcome
from recon.core.queue import Task, TaskStatus
from recon.core.router import RouteRule, RoutingContext
from recon.policy.rate_limit import (
    RateLimitContext,
    RateLimitDemand,
    RateLimitOutcome,
    RateLimitPlan,
    RateLimiter,
)
from recon.policy.scope import (
    ScopeAssetKind,
    ScopeDecision,
    ScopeEngine,
    ScopeSubject,
)
from recon.workers.passive_domains import normalize_dns_name


WORKER_NAME = "nuclei"
ACTION_VALIDATE_CVE = "validate_cve"

_ALLOWED_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_ALLOWED_ROOT_VARIABLES = ("{{BaseURL}}", "{{RootURL}}")

# Top-level protocols/features which are never allowed in the automatic lane.
_DENIED_TOP_LEVEL_KEYS = frozenset(
    {
        "workflows",
        "workflow",
        "flow",
        "code",
        "javascript",
        "headless",
        "network",
        "tcp",
        "dns",
        "ssl",
        "file",
        "websocket",
        "whois",
    }
)

# Features which can multiply requests, mutate request semantics or cross the
# recon-only boundary. Checked recursively, not just on one YAML level.
_DENIED_RECURSIVE_KEYS = frozenset(
    {
        "raw",
        "body",
        "payloads",
        "payload",
        "attack",
        "fuzzing",
        "race",
        "race_count",
        "race-count",
        "unsafe",
        "threads",
        "pipeline",
        "iterate-all",
        "iterate_all",
        "cookie-reuse",
        "cookie_reuse",
        "host-redirects",
        "host_redirects",
        "redirects",
        "max-redirects",
        "max_redirects",
        "req-condition",
        "req_condition",
        "pre-condition",
        "pre_condition",
        "analyzer",
    }
)

_DENIED_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "content-length",
        "transfer-encoding",
        "x-http-method-override",
        "x-method-override",
        "x-original-method",
    }
)

_DENIED_TEMPLATE_MARKERS = (
    "{{interactsh-url}}",
    "interactsh_protocol",
    "interactsh_request",
    "interactsh_response",
    "{{file(",
    "{{read_file(",
    "{{env(",
)

_CLOUD_ENV_PREFIXES = (
    "PDCP_",
    "PROJECTDISCOVERY_",
)

_SENSITIVE_ENV_NAMES = frozenset(
    {
        "NUCLEI_SIGNATURE_PRIVATE_KEY",
        "NUCLEI_USER_PRIVATE_KEY",
        "NUCLEI_USER_CERTIFICATE",
        "NUCLEI_USER_CERTIFICATE_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)


class NucleiTemplateManifestEntry(BaseModel):
    """One human-reviewed, hash-pinned template authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: str
    template_id: str
    path: str
    sha256: str

    audited: bool = True
    audit_note: str | None = None

    # Human audit may choose a lower ceiling than the global worker ceiling.
    max_requests: int = Field(default=3, ge=1, le=32)

    # By default automatic templates must also pass Nuclei signature checks.
    require_signed: bool = True

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized.startswith("CVE-"):
            raise ValueError("manifest cve_id must start with CVE-")
        return normalized

    @field_validator("template_id", "path")
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("sha256")
    @classmethod
    def valid_sha256(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(
            char not in "0123456789abcdef" for char in normalized
        ):
            raise ValueError("sha256 must be a 64-character hex digest")
        return normalized

    @field_validator("audit_note")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


class NucleiTemplateManifest(BaseModel):
    """Audited template manifest loaded by the runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    templates: tuple[NucleiTemplateManifestEntry, ...] = ()

    @model_validator(mode="after")
    def unique_entries(self) -> "NucleiTemplateManifest":
        seen_paths: set[str] = set()
        seen_pairs: set[tuple[str, str]] = set()

        for entry in self.templates:
            if entry.path in seen_paths:
                raise ValueError(f"duplicate template manifest path: {entry.path}")
            seen_paths.add(entry.path)

            pair = (entry.cve_id, entry.template_id)
            if pair in seen_pairs:
                raise ValueError(
                    "duplicate CVE/template manifest pair: "
                    f"{entry.cve_id}/{entry.template_id}"
                )
            seen_pairs.add(pair)

        return self


class NucleiTemplateAudit(BaseModel):
    """Explainable static audit result for one pinned template."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    template_id: str | None = None
    template_name: str | None = None
    severity: str | None = None

    request_count: int = Field(default=0, ge=0)
    methods: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()

    sha256: str
    reasons: tuple[str, ...] = ()


class AuditedNucleiTemplate(BaseModel):
    """Runtime-ready local template after manifest + static audit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: str
    template_id: str
    path: Path
    sha256: str

    request_count: int = Field(ge=1)
    request_paths: tuple[str, ...] = ()
    severity: str | None = None
    require_signed: bool = True
    audit_note: str | None = None


class NucleiCandidate(BaseModel):
    """Normalized execution target extracted from a CVE candidate Event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: str
    target_url: str
    hostname: str

    matched_cpe: str | None = None
    cpe_score: float = Field(default=0.0, ge=0.0, le=1.0)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    known_exploited: bool = False

    product: str | None = None
    version: str | None = None


class NucleiResult(BaseModel):
    """Safe subset of one Nuclei JSONL finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: str
    template_path: str | None = None
    template_url: str | None = None

    name: str | None = None
    severity: str | None = None
    matcher_name: str | None = None
    finding_type: str | None = None

    host: str | None = None
    matched_at: str | None = None
    ip: str | None = None
    timestamp: str | None = None

    curl_command_stored: bool = False
    raw_request_response_stored: bool = False


class NucleiBackendConfig(BaseModel):
    """CLI guardrails for the Nuclei subprocess."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    binary: str = "nuclei"

    timeout_seconds: int = Field(default=10, ge=1, le=60)
    process_timeout_seconds: int = Field(default=60, ge=5, le=600)

    max_response_read_bytes: int = Field(
        default=1024 * 1024,
        ge=1024,
        le=8 * 1024 * 1024,
    )
    max_response_save_bytes: int = Field(
        default=1024,
        ge=0,
        le=1024 * 1024,
    )

    stderr_tail_lines: int = Field(default=100, ge=10, le=1000)
    stream_limit_bytes: int = Field(default=2 * 1024 * 1024, ge=65536)

    # Deliberately narrow. Arbitrary extra_args would be able to re-enable
    # auth, proxies, OAST, fuzzing, headless, redirects, code, cloud upload, etc.
    extra_args: tuple[str, ...] = ()

    @field_validator("binary")
    @classmethod
    def binary_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("binary must not be blank")
        return normalized

    @field_validator("extra_args")
    @classmethod
    def validate_extra_args(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        forbidden = {
            "-H",
            "-header",
            "-sf",
            "-secret-file",
            "-ps",
            "-prefetch-secrets",
            "-p",
            "-proxy",
            "-pi",
            "-proxy-internal",
            "-fr",
            "-follow-redirects",
            "-fhr",
            "-follow-host-redirects",
            "-headless",
            "-code",
            "-fuzz",
            "-dast",
            "-itags",
            "-include-tags",
            "-it",
            "-include-templates",
            "-lfa",
            "-allow-local-file-access",
            "-ev",
            "-env-vars",
            "-cc",
            "-client-cert",
            "-ck",
            "-client-key",
            "-ca",
            "-client-ca",
            "-sni",
            "-tlsi",
            "-tls-impersonate",
            "-pd",
            "-dashboard",
            "-cup",
            "-cloud-upload",
            "-uc",
            "-uncover",
            "-debug",
            "-dreq",
            "-debug-req",
            "-dresp",
            "-debug-resp",
            "-irr",
            "-include-rr",
            "-sresp",
            "-store-resp",
            "-srd",
            "-store-resp-dir",
            "-config",
            "-profile",
            "-tp",
            "-r",
            "-resolvers",
            "-sr",
            "-system-resolvers",
            "-up",
            "-update",
            "-ut",
            "-update-templates",
            "-reset",
            "-file",
            "-esc",
            "-enable-self-contained",
            "-egm",
            "-enable-global-matchers",
        }

        normalized: list[str] = []
        for raw in values:
            value = raw.strip()
            if not value:
                continue

            flag = value.split("=", 1)[0]
            if flag in forbidden:
                raise ValueError(f"unsafe Nuclei extra arg is forbidden: {flag}")

            # Extra flags may not override fields Night Scout sets itself.
            if flag in {
                "-u",
                "-target",
                "-t",
                "-templates",
                "-rl",
                "-rate-limit",
                "-rld",
                "-rate-limit-duration",
                "-c",
                "-concurrency",
                "-bs",
                "-bulk-size",
                "-pc",
                "-payload-concurrency",
                "-timeout",
                "-retries",
                "-rsr",
                "-response-size-read",
                "-rss",
                "-response-size-save",
                "-pt",
                "-type",
                "-dut",
                "-disable-unsigned-templates",
                "-ni",
                "-no-interactsh",
                "-dr",
                "-disable-redirects",
                "-j",
                "-jsonl",
                "-or",
                "-omit-raw",
                "-ot",
                "-omit-template",
            }:
                raise ValueError(
                    f"Nuclei extra arg may not override worker guardrail: {flag}"
                )

            normalized.append(value)

        return tuple(normalized)


class NucleiWorkerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_requests_per_template: int = Field(default=3, ge=1, le=16)

    lease_margin_seconds: int = Field(default=30, ge=1, le=600)
    default_retry_after_seconds: float = Field(default=10.0, ge=0.0)

    minimum_cpe_score: float = Field(default=0.60, ge=0.0, le=1.0)

    finding_confidence_floor: float = Field(default=0.72, ge=0.0, le=1.0)
    finding_confidence_ceiling: float = Field(default=0.95, ge=0.0, le=1.0)

    require_signed_templates: bool = True

    @model_validator(mode="after")
    def confidence_bounds(self) -> "NucleiWorkerConfig":
        if self.finding_confidence_floor > self.finding_confidence_ceiling:
            raise ValueError("finding confidence floor cannot exceed ceiling")
        return self


class InputEventProvider(Protocol):
    async def get_event(self, event_id: str) -> Event | None:
        ...


class EventPublisher(Protocol):
    async def publish(self, event: Event) -> bool:
        ...


class NucleiRequestScopeProvider(Protocol):
    """Classify every concrete URL a template may contact."""

    async def classify_url(self, url: str) -> ScopeDecision:
        ...


class ScopeEngineNucleiRequestScopeProvider:
    """Adapt ScopeEngine to per-template-request URL authorization."""

    def __init__(self, engine: ScopeEngine) -> None:
        self._engine = engine

    async def classify_url(self, url: str) -> ScopeDecision:
        return self._engine.evaluate(
            ScopeSubject(
                kind=ScopeAssetKind.URL,
                value=url,
            )
        )


class NucleiTemplateCatalog(Protocol):
    async def template_for(
        self,
        *,
        cve_id: str,
        max_requests: int,
        require_signed: bool,
    ) -> AuditedNucleiTemplate | None:
        ...


class LocalAuditedTemplateCatalog:
    """Manifest-backed local template resolver with hash pinning."""

    def __init__(
        self,
        *,
        manifest_path: str | Path,
        templates_root: str | Path,
        max_template_bytes: int = 1024 * 1024,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.templates_root = Path(templates_root)
        self.max_template_bytes = max_template_bytes

        if max_template_bytes < 1024:
            raise ValueError("max_template_bytes must be at least 1024")

        self._manifest: NucleiTemplateManifest | None = None
        self._manifest_mtime_ns: int | None = None
        self._lock = asyncio.Lock()

    async def template_for(
        self,
        *,
        cve_id: str,
        max_requests: int,
        require_signed: bool,
    ) -> AuditedNucleiTemplate | None:
        manifest = await self._load_manifest()
        normalized_cve = cve_id.strip().upper()

        for entry in manifest.templates:
            if entry.cve_id != normalized_cve or not entry.audited:
                continue

            if require_signed and not entry.require_signed:
                continue

            path = resolve_template_path(
                templates_root=self.templates_root,
                relative_path=entry.path,
            )

            if path is None:
                continue

            audit = audit_nuclei_template(
                path,
                entry=entry,
                max_template_bytes=self.max_template_bytes,
                max_requests=min(
                    max_requests,
                    entry.max_requests,
                ),
            )

            if not audit.allowed:
                continue

            assert audit.template_id is not None
            assert audit.request_count >= 1

            return AuditedNucleiTemplate(
                cve_id=entry.cve_id,
                template_id=audit.template_id,
                path=path,
                sha256=audit.sha256,
                request_count=audit.request_count,
                request_paths=audit.paths,
                severity=audit.severity,
                require_signed=entry.require_signed,
                audit_note=entry.audit_note,
            )

        return None

    async def _load_manifest(self) -> NucleiTemplateManifest:
        async with self._lock:
            stat = await asyncio.to_thread(
                self.manifest_path.stat
            )

            if (
                self._manifest is not None
                and self._manifest_mtime_ns == stat.st_mtime_ns
            ):
                return self._manifest

            raw = await asyncio.to_thread(
                self.manifest_path.read_text,
                encoding="utf-8",
            )

            loaded = yaml.safe_load(raw)
            if not isinstance(loaded, dict):
                raise ValueError("Nuclei template manifest must be a YAML object")

            manifest = NucleiTemplateManifest.model_validate(loaded)
            self._manifest = manifest
            self._manifest_mtime_ns = stat.st_mtime_ns
            return manifest


class NucleiBackendUnavailable(RuntimeError):
    pass


class NucleiBackendError(RuntimeError):
    pass


class NucleiBackendTimeout(NucleiBackendError):
    pass


class NucleiBackend:
    """One-target/one-template Nuclei JSONL adapter."""

    name = "nuclei"

    def __init__(
        self,
        config: NucleiBackendConfig | None = None,
    ) -> None:
        self.config = config or NucleiBackendConfig()

    def ensure_available(self) -> None:
        if shutil.which(self.config.binary) is None:
            raise NucleiBackendUnavailable(
                f"Nuclei binary not found: {self.config.binary}"
            )

    def command_for(
        self,
        *,
        target_url: str,
        template: AuditedNucleiTemplate,
        pacing: "NucleiPacing",
        isolated_config: Path,
    ) -> tuple[str, ...]:
        args = [
            self.config.binary,
            "-u",
            target_url,
            "-t",
            str(template.path),
            "-pt",
            "http",
            "-j",
            "-silent",
            "-nc",
            "-duc",
            "-ni",
            "-dr",
            "-retries",
            "0",
            "-timeout",
            str(self.config.timeout_seconds),
            "-c",
            "1",
            "-bs",
            "1",
            "-pc",
            "1",
            "-prc",
            "1",
            "-rsr",
            str(self.config.max_response_read_bytes),
            "-rss",
            str(self.config.max_response_save_bytes),
            "-or",
            "-ot",
            "-no-stdin",
            "-nh",
            "-config",
            str(isolated_config),
        ]

        if template.require_signed:
            args.append("-dut")

        args.extend(
            (
                "-rl",
                str(pacing.requests),
                "-rld",
                pacing.duration,
            )
        )

        args.extend(self.config.extra_args)
        return tuple(args)

    async def run(
        self,
        *,
        target_url: str,
        template: AuditedNucleiTemplate,
        pacing: "NucleiPacing",
    ) -> AsyncIterator[NucleiResult]:
        normalized_target = normalize_target_url(target_url)
        self.ensure_available()

        with tempfile.TemporaryDirectory(prefix="nightscout-nuclei-") as temp_dir:
            temp_root = Path(temp_dir)
            home = temp_root / "home"
            config_home = temp_root / "config"
            cache_home = temp_root / "cache"

            for path in (home, config_home, cache_home):
                path.mkdir(mode=0o700, parents=True, exist_ok=True)

            # Passing an explicit empty config and isolated HOME/XDG dirs keeps
            # user-level Nuclei auth/headers/proxy/cloud configuration out of
            # an automated Night Scout validation run.
            config_file = temp_root / "nuclei-empty-config.yaml"
            config_file.write_text("{}\n", encoding="utf-8")
            os.chmod(config_file, 0o600)

            env = sanitized_nuclei_environment(
                home=home,
                config_home=config_home,
                cache_home=cache_home,
            )

            process = await asyncio.create_subprocess_exec(
                *self.command_for(
                    target_url=normalized_target,
                    template=template,
                    pacing=pacing,
                    isolated_config=config_file,
                ),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=self.config.stream_limit_bytes,
                env=env,
            )

            if process.stdout is None or process.stderr is None:
                await terminate_process(process)
                raise NucleiBackendError("Nuclei subprocess pipes were not created")

            stderr_tail: deque[str] = deque(
                maxlen=self.config.stderr_tail_lines
            )

            stderr_task = asyncio.create_task(
                drain_stderr(
                    process.stderr,
                    stderr_tail,
                )
            )

            try:
                try:
                    async with asyncio.timeout(
                        self.config.process_timeout_seconds
                    ):
                        while True:
                            raw_line = await process.stdout.readline()
                            if not raw_line:
                                break

                            line = raw_line.decode(
                                "utf-8",
                                errors="replace",
                            ).strip()

                            if not line:
                                continue

                            result = parse_nuclei_jsonl(line)
                            if result is not None:
                                yield result

                        returncode = await process.wait()

                except TimeoutError as exc:
                    await terminate_process(process)
                    raise NucleiBackendTimeout(
                        "Nuclei exceeded process timeout "
                        f"({self.config.process_timeout_seconds}s)"
                    ) from exc

                if returncode != 0:
                    detail = " | ".join(stderr_tail)
                    raise NucleiBackendError(
                        "Nuclei exited unsuccessfully "
                        f"(returncode={returncode})"
                        + (f"; stderr_tail={detail}" if detail else "")
                    )

            finally:
                if process.returncode is None:
                    await terminate_process(process)

                try:
                    await stderr_task
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass


class NucleiPacing(BaseModel):
    """Nuclei's rate-limit quantity per duration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requests: int = Field(ge=1)
    duration: str

    @field_validator("duration")
    @classmethod
    def valid_duration(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("duration must not be blank")
        return normalized


class NucleiWorker:
    """Audited, bounded CVE detection worker."""

    name = WORKER_NAME

    def __init__(
        self,
        *,
        events: InputEventProvider,
        publisher: EventPublisher,
        rate_limiter: RateLimiter,
        templates: NucleiTemplateCatalog,
        request_scope: NucleiRequestScopeProvider,
        backend: NucleiBackend | None = None,
        config: NucleiWorkerConfig | None = None,
    ) -> None:
        self._events = events
        self._publisher = publisher
        self._rate_limiter = rate_limiter
        self._templates = templates
        self._request_scope = request_scope
        self._backend = backend or NucleiBackend()
        self._config = config or NucleiWorkerConfig()

    async def execute(self, task: Task) -> WorkerExecutionResult:
        if task.status is not TaskStatus.RUNNING:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    "nuclei worker may only execute claimed RUNNING tasks, "
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

        if task.action != ACTION_VALIDATE_CVE:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"unsupported nuclei action: {task.action}",
            )

        input_event = await self._events.get_event(task.input_event_id)
        if input_event is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"input event not found: {task.input_event_id}",
            )

        try:
            candidate = candidate_from_event(input_event)
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        if candidate.cpe_score < self._config.minimum_cpe_score:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.SUCCEEDED,
            )

        try:
            template = await self._templates.template_for(
                cve_id=candidate.cve_id,
                max_requests=self._config.max_requests_per_template,
                require_signed=self._config.require_signed_templates,
            )
        except (OSError, ValueError, yaml.YAMLError) as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"Nuclei template catalog error: {exc}",
            )

        if template is None:
            # No audited automatic validator is a normal state. Candidate stays
            # available for manual validation/review.
            return WorkerExecutionResult(
                outcome=WorkerOutcome.SUCCEEDED,
            )

        try:
            request_urls = template_request_urls(
                template,
                target_url=candidate.target_url,
            )
        except ValueError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"Nuclei template request expansion failed: {exc}",
            )

        request_scope_rule_ids: list[str] = []

        for request_url in request_urls:
            scope_decision = await self._request_scope.classify_url(request_url)

            if scope_decision.state is not ScopeState.IN_SCOPE:
                # Preserve the CVE candidate for manual validation; automatic
                # execution simply stops before any target traffic.
                return WorkerExecutionResult(
                    outcome=WorkerOutcome.SUCCEEDED,
                )

            if scope_decision.matched_rule_id is not None:
                request_scope_rule_ids.append(scope_decision.matched_rule_id)

        try:
            self._backend.ensure_available()
        except NucleiBackendUnavailable as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=str(exc),
            )

        context = RateLimitContext(
            resource_keys=frozenset(
                {
                    f"host:{candidate.hostname}",
                }
            )
        )

        plan = self._rate_limiter.plan(
            task,
            context=context,
        )

        rate_error = validate_opaque_nuclei_plan(plan)
        if rate_error is not None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=rate_error,
            )

        assert plan.aggregate_rps_ceiling is not None
        assert plan.max_concurrency_hint is not None

        pacing = nuclei_pacing_from_plan(plan)

        decision = await self._rate_limiter.acquire(
            task,
            context=context,
            demand=RateLimitDemand(
                requests=0.0,
                concurrency=plan.max_concurrency_hint,
            ),
            lease_for=timedelta(
                seconds=(
                    self._backend.config.process_timeout_seconds
                    + self._config.lease_margin_seconds
                )
            ),
        )

        if decision.outcome is RateLimitOutcome.DEFER:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=(
                    decision.reason
                    or "nuclei could not acquire exclusive host rate lease"
                ),
                retry_after_seconds=(
                    decision.retry_after_seconds
                    if decision.retry_after_seconds is not None
                    else self._config.default_retry_after_seconds
                ),
            )

        if decision.outcome is RateLimitOutcome.DENY:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=(
                    decision.reason
                    or "nuclei shared rate policy denied execution"
                ),
            )

        lease_id = (
            decision.lease.lease_id
            if decision.lease is not None
            else None
        )

        try:
            async for result in self._backend.run(
                target_url=candidate.target_url,
                template=template,
                pacing=pacing,
            ):
                if not result_matches_execution(
                    result,
                    candidate=candidate,
                    template=template,
                ):
                    continue

                finding_event = nuclei_finding_event(
                    input_event=input_event,
                    candidate=candidate,
                    template=template,
                    result=result,
                    config=self._config,
                    request_scope_rule_ids=tuple(sorted(set(request_scope_rule_ids))),
                )

                await self._publisher.publish(finding_event)
                await self._publisher.publish(
                    nuclei_review_event(
                        finding_event=finding_event,
                        candidate=candidate,
                        template=template,
                    )
                )

        except NucleiBackendTimeout as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.default_retry_after_seconds,
            )
        except NucleiBackendError as exc:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.RETRY,
                error=str(exc),
                retry_after_seconds=self._config.default_retry_after_seconds,
            )
        finally:
            if lease_id is not None:
                await self._rate_limiter.release(lease_id)

        return WorkerExecutionResult(
            outcome=WorkerOutcome.SUCCEEDED,
        )


def nuclei_route_rules(
    *,
    base_priority: float = 9.0,
) -> tuple[RouteRule, ...]:
    """Route only explicit unvalidated CVE candidates into Nuclei."""

    return (
        RouteRule(
            rule_id="nuclei.validate-cve.audited",
            accepts=frozenset(
                {
                    EventType.VULNERABILITY_CANDIDATE,
                }
            ),
            worker=WORKER_NAME,
            action=ACTION_VALIDATE_CVE,
            reason=(
                "run one audited hash-pinned read-only Nuclei HTTP template "
                "for an unvalidated CVE candidate"
            ),
            base_priority=base_priority,
            required_tags=frozenset(
                {
                    "cve-candidate",
                    "unvalidated",
                    "nuclei-eligible",
                }
            ),
            excluded_tags=frozenset(
                {
                    "validated",
                    "nuclei-match",
                    "policy-blocked",
                }
            ),
            predicate=_candidate_route_predicate,
        ),
    )


def candidate_from_event(event: Event) -> NucleiCandidate:
    if event.type is not EventType.VULNERABILITY_CANDIDATE:
        raise ValueError(
            "nuclei input must be a VULNERABILITY_CANDIDATE event"
        )

    tags = {tag.strip().lower() for tag in event.tags}
    if "unvalidated" not in tags or "cve-candidate" not in tags:
        raise ValueError("nuclei input is not an unvalidated CVE candidate")

    if event.scope_state is not ScopeState.IN_SCOPE:
        # Defense in depth. Lifecycle ScopeGate remains authoritative.
        raise ValueError("nuclei active validation requires IN_SCOPE input")

    cve_id = required_metadata_text(
        event.metadata,
        "cve_id",
    ).upper()

    target_url = normalize_target_url(
        required_metadata_text(
            event.metadata,
            "target_url",
        )
    )

    parts = urlsplit(target_url)
    assert parts.hostname is not None

    cpe_score = safe_float(
        event.metadata.get("cpe_score")
    )

    cvss_score = safe_float(
        event.metadata.get("cvss_score")
    )

    return NucleiCandidate(
        cve_id=cve_id,
        target_url=target_url,
        hostname=normalize_dns_name(parts.hostname),
        matched_cpe=optional_metadata_text(
            event.metadata,
            "matched_cpe",
        ),
        cpe_score=(
            min(1.0, max(0.0, cpe_score))
            if cpe_score is not None
            else 0.0
        ),
        cvss_score=(
            cvss_score
            if (
                cvss_score is not None
                and 0.0 <= cvss_score <= 10.0
            )
            else None
        ),
        known_exploited=bool(
            event.metadata.get("known_exploited", False)
        ),
        product=optional_metadata_text(
            event.metadata,
            "product",
        ),
        version=optional_metadata_text(
            event.metadata,
            "version",
        ),
    )


def audit_nuclei_template(
    path: Path,
    *,
    entry: NucleiTemplateManifestEntry,
    max_template_bytes: int,
    max_requests: int,
) -> NucleiTemplateAudit:
    reasons: list[str] = []

    try:
        stat = path.lstat()
    except OSError as exc:
        return NucleiTemplateAudit(
            allowed=False,
            sha256=entry.sha256,
            reasons=(f"template unavailable: {exc}",),
        )

    if path.is_symlink():
        reasons.append("template path is a symbolic link")

    if not path.is_file():
        reasons.append("template path is not a regular file")

    if stat.st_size > max_template_bytes:
        reasons.append(
            "template exceeds configured size limit "
            f"({stat.st_size}>{max_template_bytes})"
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        return NucleiTemplateAudit(
            allowed=False,
            sha256=entry.sha256,
            reasons=tuple(reasons + [f"template read failed: {exc}"]),
        )

    digest = hashlib.sha256(data).hexdigest()

    if digest != entry.sha256:
        reasons.append("template SHA-256 does not match audited manifest pin")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return NucleiTemplateAudit(
            allowed=False,
            sha256=digest,
            reasons=tuple(reasons + ["template is not UTF-8 YAML"]),
        )

    lower_text = text.lower()
    for marker in _DENIED_TEMPLATE_MARKERS:
        if marker.lower() in lower_text:
            reasons.append(f"template contains forbidden marker: {marker}")

    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return NucleiTemplateAudit(
            allowed=False,
            sha256=digest,
            reasons=tuple(reasons + [f"invalid YAML: {exc}"]),
        )

    if not isinstance(loaded, dict):
        return NucleiTemplateAudit(
            allowed=False,
            sha256=digest,
            reasons=tuple(reasons + ["template must be a YAML object"]),
        )

    template_id = loaded.get("id")
    if not isinstance(template_id, str) or not template_id.strip():
        reasons.append("template has no valid id")
        normalized_template_id = None
    else:
        normalized_template_id = template_id.strip()
        if normalized_template_id != entry.template_id:
            reasons.append("template id does not match audited manifest entry")

    for key in _DENIED_TOP_LEVEL_KEYS:
        if key in loaded:
            reasons.append(f"forbidden top-level Nuclei protocol/feature: {key}")

    recursive_hits = recursive_denied_keys(loaded)
    for hit in sorted(recursive_hits):
        reasons.append(f"forbidden Nuclei request feature: {hit}")

    info = loaded.get("info")
    template_name: str | None = None
    severity: str | None = None

    if isinstance(info, Mapping):
        raw_name = info.get("name")
        if isinstance(raw_name, str):
            template_name = raw_name.strip() or None

        raw_severity = info.get("severity")
        if isinstance(raw_severity, str):
            severity = raw_severity.strip().lower() or None

    http_requests = loaded.get("http")
    if not isinstance(http_requests, list) or not http_requests:
        reasons.append("automatic Nuclei lane requires at least one HTTP request")
        http_requests = []

    methods: list[str] = []
    paths: list[str] = []
    request_count = 0

    for index, request in enumerate(http_requests):
        if not isinstance(request, Mapping):
            reasons.append(f"http[{index}] must be an object")
            continue

        method_raw = request.get("method", "GET")
        if not isinstance(method_raw, str):
            reasons.append(f"http[{index}] method is not a string")
            continue

        method = method_raw.strip().upper()
        methods.append(method)

        if method not in _ALLOWED_HTTP_METHODS:
            reasons.append(
                f"http[{index}] method {method!r} is not allowed automatically"
            )

        headers = request.get("headers")
        if headers is not None:
            if not isinstance(headers, Mapping):
                reasons.append(f"http[{index}] headers must be a map")
            else:
                for raw_name, raw_value in headers.items():
                    name = str(raw_name).strip().lower()
                    if name in _DENIED_HEADER_NAMES:
                        reasons.append(
                            f"http[{index}] forbidden header override: {name}"
                        )

                    value_text = str(raw_value).lower()
                    if any(
                        marker.lower() in value_text
                        for marker in _DENIED_TEMPLATE_MARKERS
                    ):
                        reasons.append(
                            f"http[{index}] header contains forbidden dynamic marker"
                        )

        request_paths = request.get("path")
        if not isinstance(request_paths, list) or not request_paths:
            reasons.append(f"http[{index}] requires a non-empty path list")
            continue

        for raw_path in request_paths:
            if not isinstance(raw_path, str):
                reasons.append(f"http[{index}] path entry must be a string")
                continue

            normalized_path = raw_path.strip()
            paths.append(normalized_path)
            request_count += 1

            if not normalized_path.startswith(_ALLOWED_ROOT_VARIABLES):
                reasons.append(
                    f"http[{index}] path must start with {{BaseURL}} or {{RootURL}}"
                )

            if any(
                marker.lower() in normalized_path.lower()
                for marker in _DENIED_TEMPLATE_MARKERS
            ):
                reasons.append(
                    f"http[{index}] path contains forbidden dynamic marker"
                )

            # Absolute literal URLs could escape the input target. The only
            # allowed URL roots are the Nuclei target variables above.
            scrubbed = normalized_path
            for prefix in _ALLOWED_ROOT_VARIABLES:
                if scrubbed.startswith(prefix):
                    scrubbed = scrubbed[len(prefix):]
                    break

            if "{{" in scrubbed or "}}" in scrubbed:
                reasons.append(
                    f"http[{index}] path contains non-root dynamic variables"
                )

            if scrubbed and not scrubbed.startswith(("/", "?")):
                reasons.append(
                    f"http[{index}] path suffix must begin with '/' or '?'"
                )

            if "#" in scrubbed:
                reasons.append(
                    f"http[{index}] path must not contain a URL fragment"
                )

            if "http://" in scrubbed.lower() or "https://" in scrubbed.lower():
                reasons.append(
                    f"http[{index}] path embeds an absolute external URL"
                )

    if request_count <= 0:
        reasons.append("template has no bounded model-based HTTP requests")

    effective_limit = min(
        max_requests,
        entry.max_requests,
    )

    if request_count > effective_limit:
        reasons.append(
            "template request count exceeds audited ceiling "
            f"({request_count}>{effective_limit})"
        )

    metadata_max = None
    if isinstance(info, Mapping):
        metadata = info.get("metadata")
        if isinstance(metadata, Mapping):
            metadata_max = safe_int(metadata.get("max-requests"))
            if metadata_max is None:
                metadata_max = safe_int(metadata.get("max_requests"))

    if metadata_max is not None and metadata_max > effective_limit:
        reasons.append(
            "template info.metadata max-requests exceeds audited ceiling "
            f"({metadata_max}>{effective_limit})"
        )

    return NucleiTemplateAudit(
        allowed=not reasons,
        template_id=normalized_template_id,
        template_name=template_name,
        severity=severity,
        request_count=request_count,
        methods=tuple(methods),
        paths=tuple(paths),
        sha256=digest,
        reasons=tuple(reasons),
    )


def recursive_denied_keys(value: Any) -> frozenset[str]:
    hits: set[str] = set()

    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).strip().lower()
            if key in _DENIED_RECURSIVE_KEYS:
                # False values are harmless for boolean switches. Fields such
                # as redirects:false are allowed; true/non-empty are denied.
                if child not in (False, None, 0, "", [], {}):
                    hits.add(key)
            hits.update(recursive_denied_keys(child))

    elif isinstance(value, list):
        for child in value:
            hits.update(recursive_denied_keys(child))

    return frozenset(hits)


def resolve_template_path(
    *,
    templates_root: Path,
    relative_path: str,
) -> Path | None:
    raw = Path(relative_path)
    if raw.is_absolute():
        return None

    root = templates_root.resolve()
    candidate = (root / raw).resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        return None

    return candidate


def validate_opaque_nuclei_plan(plan: RateLimitPlan) -> str | None:
    if not plan.matched:
        return (
            "nuclei has no matching shared rate-limit rule; "
            "opaque multi-request subprocess fails closed"
        )

    if plan.aggregate_rps_ceiling is None or plan.aggregate_rps_ceiling <= 0.0:
        return (
            "nuclei requires an explicit requests_per_second ceiling in its "
            "matching shared rate-limit rule"
        )

    if plan.max_concurrency_hint is None or plan.max_concurrency_hint < 1:
        return (
            "nuclei requires max_concurrency in its matching shared rate-limit "
            "rule so it can acquire an exclusive host lease"
        )

    return None


def nuclei_pacing_from_plan(plan: RateLimitPlan) -> NucleiPacing:
    if plan.aggregate_rps_ceiling is None or plan.aggregate_rps_ceiling <= 0.0:
        raise ValueError("rate plan has no positive aggregate RPS ceiling")

    rps = plan.aggregate_rps_ceiling

    if rps >= 1.0:
        return NucleiPacing(
            requests=max(1, math.floor(rps)),
            duration="1s",
        )

    # Newer Nuclei versions support -rate-limit-duration. One request every
    # ceil(1/rps) seconds is equal to or slower than the shared ceiling.
    return NucleiPacing(
        requests=1,
        duration=f"{math.ceil(1.0 / rps)}s",
    )


def parse_nuclei_jsonl(line: str) -> NucleiResult | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    template_id = payload.get("template-id") or payload.get("template_id")
    if not isinstance(template_id, str) or not template_id.strip():
        return None

    info = payload.get("info")
    if not isinstance(info, Mapping):
        info = {}

    return NucleiResult(
        template_id=template_id.strip(),
        template_path=optional_text(
            payload.get("template-path") or payload.get("template_path")
        ),
        template_url=optional_text(
            payload.get("template-url") or payload.get("template_url")
        ),
        name=optional_text(
            info.get("name") or payload.get("name")
        ),
        severity=optional_text(
            info.get("severity") or payload.get("severity")
        ),
        matcher_name=optional_text(
            payload.get("matcher-name") or payload.get("matcher_name")
        ),
        finding_type=optional_text(payload.get("type")),
        host=optional_text(payload.get("host")),
        matched_at=optional_text(
            payload.get("matched-at") or payload.get("matched_at")
        ),
        ip=optional_text(payload.get("ip")),
        timestamp=optional_text(payload.get("timestamp")),
        # Raw/curl fields are deliberately not copied into the model.
        curl_command_stored=False,
        raw_request_response_stored=False,
    )


def result_matches_execution(
    result: NucleiResult,
    *,
    candidate: NucleiCandidate,
    template: AuditedNucleiTemplate,
) -> bool:
    if result.template_id != template.template_id:
        return False

    for candidate_url in (
        result.matched_at,
        result.host,
    ):
        if candidate_url is None:
            continue

        if not result_target_matches(
            candidate_url,
            target_url=candidate.target_url,
        ):
            return False

    return True


def result_target_matches(
    value: str,
    *,
    target_url: str,
) -> bool:
    target = urlsplit(normalize_target_url(target_url))

    raw = value.strip()
    if not raw:
        return True

    if "://" not in raw:
        raw = f"{target.scheme}://{raw}"

    try:
        observed = urlsplit(raw)
    except ValueError:
        return False

    if observed.hostname is None or target.hostname is None:
        return False

    try:
        observed_host = normalize_dns_name(observed.hostname)
        target_host = normalize_dns_name(target.hostname)
    except ValueError:
        return False

    if observed_host != target_host:
        return False

    return effective_port(observed) == effective_port(target)


def nuclei_finding_event(
    *,
    input_event: Event,
    candidate: NucleiCandidate,
    template: AuditedNucleiTemplate,
    result: NucleiResult,
    config: NucleiWorkerConfig,
    request_scope_rule_ids: tuple[str, ...] = (),
) -> Event:
    confidence = min(
        config.finding_confidence_ceiling,
        max(
            config.finding_confidence_floor,
            (
                input_event.confidence * 0.35
                + candidate.cpe_score * 0.20
                + 0.45
            ),
        ),
    )

    value = (
        f"{candidate.cve_id}@{candidate.target_url}"
        f"#{template.template_id}"
    )

    return Event(
        type=EventType.VULNERABILITY_FINDING,
        value=value,
        source="nuclei:audited-http-template",
        parent_event_id=input_event.event_id,
        scope_state=input_event.scope_state,
        confidence=confidence,
        novelty=max(input_event.novelty, 0.80),
        depth=input_event.depth + 1,
        tags={
            "vulnerability",
            "cve",
            "nuclei",
            "nuclei-match",
            "automated-match",
            "requires-manual-validation",
            "not-exploited",
        },
        metadata={
            "cve_id": candidate.cve_id,
            "target_url": candidate.target_url,
            "hostname": candidate.hostname,
            "matched_cpe": candidate.matched_cpe,
            "cpe_score": candidate.cpe_score,
            "cvss_score": candidate.cvss_score,
            "known_exploited": candidate.known_exploited,
            "product": candidate.product,
            "version": candidate.version,
            "template_id": template.template_id,
            "template_sha256": template.sha256,
            "template_severity": template.severity,
            "template_request_ceiling": template.request_count,
            "template_request_paths": list(template.request_paths),
            "template_scope_rule_ids": list(request_scope_rule_ids),
            "template_audit_note": template.audit_note,
            "nuclei_name": result.name,
            "nuclei_severity": result.severity,
            "nuclei_matcher_name": result.matcher_name,
            "nuclei_type": result.finding_type,
            "matched_at": result.matched_at,
            "observed_ip": result.ip,
            "nuclei_timestamp": result.timestamp,
            "automated_match_on_target": True,
            "manual_validation_required": True,
            "validated_exploitability": False,
            "exploitation_attempted": False,
            "credentials_used": False,
            "oast_used": False,
            "redirects_followed": False,
            "raw_request_response_stored": False,
            "curl_command_stored": False,
            "scope_inference": False,
            "severity_inference_from_cvss": False,
        },
    )


def nuclei_review_event(
    *,
    finding_event: Event,
    candidate: NucleiCandidate,
    template: AuditedNucleiTemplate,
) -> Event:
    """Create a safe manual-validation queue event for an automated match."""

    return Event(
        type=EventType.HUMAN_REVIEW,
        value=(
            f"review:{candidate.cve_id}@{candidate.target_url}"
            f"#{template.template_id}"
        ),
        source="nuclei:manual-validation",
        parent_event_id=finding_event.event_id,
        scope_state=finding_event.scope_state,
        confidence=finding_event.confidence,
        novelty=finding_event.novelty,
        depth=finding_event.depth + 1,
        tags={
            "human-review",
            "vulnerability",
            "cve",
            "nuclei-match",
            "manual-validation-required",
        },
        metadata={
            "review_category": "AUTOMATED_VULNERABILITY_MATCH",
            "cve_id": candidate.cve_id,
            "target_url": candidate.target_url,
            "template_id": template.template_id,
            "finding_event_id": finding_event.event_id,
            "raw_request_response_stored": False,
            "credentials_used": False,
            "exploitation_attempted": False,
            "manual_validation_required": True,
        },
    )


def template_request_urls(
    template: AuditedNucleiTemplate,
    *,
    target_url: str,
) -> tuple[str, ...]:
    """Expand already-audited static paths into concrete scope subjects."""

    target = urlsplit(normalize_target_url(target_url))
    origin = urlunsplit((target.scheme, target.netloc, "", "", ""))

    result: list[str] = []

    for raw_path in template.request_paths:
        path = raw_path.strip()
        prefix = next(
            (candidate for candidate in _ALLOWED_ROOT_VARIABLES if path.startswith(candidate)),
            None,
        )

        if prefix is None:
            raise ValueError("audited template path lost its target root variable")

        suffix = path[len(prefix):]

        if "{{" in suffix or "}}" in suffix:
            raise ValueError("template request path contains unresolved variables")

        if not suffix:
            concrete = f"{origin}/"
        elif suffix.startswith("/"):
            concrete = f"{origin}{suffix}"
        elif suffix.startswith("?"):
            concrete = f"{origin}/{suffix}"
        else:
            raise ValueError("template request suffix is not root-relative")

        parsed = urlsplit(concrete)
        if parsed.fragment:
            raise ValueError("template request URL contains a fragment")

        if parsed.hostname != target.hostname or effective_port(parsed) != effective_port(target):
            raise ValueError("template request escaped the candidate origin")

        result.append(concrete)

    if not result:
        raise ValueError("audited template has no concrete request URLs")

    return tuple(result)


def normalize_target_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("Nuclei target URL must not be blank")

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError("Nuclei automatic target must use HTTP or HTTPS")

    if parts.username is not None or parts.password is not None:
        raise ValueError("Nuclei target URL must not contain userinfo")

    if parts.hostname is None:
        raise ValueError("Nuclei target URL requires a hostname")

    hostname = normalize_dns_name(parts.hostname)

    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid Nuclei target URL port") from exc

    default_port = 443 if scheme == "https" else 80
    netloc = hostname if port in (None, default_port) else f"{hostname}:{port}"

    # Validation is anchored to the discovered service root. Candidate CVEs are
    # service-version intelligence, not arbitrary user-supplied deep URLs.
    return urlunsplit(
        (
            scheme,
            netloc,
            "/",
            "",
            "",
        )
    )


def sanitized_nuclei_environment(
    *,
    home: Path,
    config_home: Path,
    cache_home: Path,
) -> dict[str, str]:
    env: dict[str, str] = {}

    for key, value in os.environ.items():
        if key in _SENSITIVE_ENV_NAMES:
            continue

        if any(key.upper().startswith(prefix) for prefix in _CLOUD_ENV_PREFIXES):
            continue

        env[key] = value

    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["XDG_CACHE_HOME"] = str(cache_home)

    return env


def _candidate_route_predicate(
    event: Event,
    context: RoutingContext,
) -> bool:
    del context

    if event.scope_state is not ScopeState.IN_SCOPE:
        return False

    try:
        candidate = candidate_from_event(event)
    except ValueError:
        return False

    return candidate.cve_id.startswith("CVE-")


def required_metadata_text(
    metadata: Mapping[str, Any],
    key: str,
) -> str:
    value = metadata.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"nuclei candidate metadata missing {key!r}")
    return value.strip()


def optional_metadata_text(
    metadata: Mapping[str, Any],
    key: str,
) -> str | None:
    return optional_text(metadata.get(key))


def optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def safe_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(parsed):
        return None

    return parsed


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def effective_port(parts: Any) -> int:
    if parts.port is not None:
        return parts.port
    return 443 if parts.scheme.lower() == "https" else 80


async def drain_stderr(
    stream: asyncio.StreamReader,
    tail: deque[str],
) -> None:
    while True:
        raw_line = await stream.readline()
        if not raw_line:
            return

        line = raw_line.decode(
            "utf-8",
            errors="replace",
        ).strip()

        if line:
            tail.append(line)


async def terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return

    process.terminate()

    try:
        async with asyncio.timeout(2.0):
            await process.wait()
            return
    except TimeoutError:
        pass

    if process.returncode is None:
        process.kill()
        await process.wait()
