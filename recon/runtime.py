"""Night Scout runtime bootstrap.

This module is the composition root for the project.  Core, policy, storage,
intelligence, and worker modules remain independently testable; runtime.py is
where they are wired into one persistent recursive application.

Runtime flow
------------

    seed Event
        -> RuntimeEventBus.publish()
        -> SQLite EventRepository
        -> provenance / snapshots
        -> vocabulary + cached CVE enrichment
        -> Router.expand()
        -> durable TaskQueue
        -> Scheduler
        -> scope -> restrictions -> review -> budget
        -> WorkerRegistryExecutor
        -> worker publishes more Events
        -> loop

The runtime never treats scheduler/confidence/novelty/yield as authorization.
All active work still passes the lifecycle gates and worker-local shared rate
limiter.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import hashlib
import json
import os
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select

from recon.core.budgets import (
    BudgetContext,
    BudgetDemand,
    BudgetLane,
    BudgetManager,
    BudgetProfile,
)
from recon.core.events import Event, EventType, ScopeState
from recon.core.lifecycle import (
    BudgetPlan,
    GateDecision,
    GateOutcome,
    Lifecycle,
    LifecycleOutcome,
    LifecycleResult,
    LifecycleReviewCoordinator,
    WorkerExecutionResult,
    WorkerOutcome,
)
from recon.core.queue import TERMINAL_TASK_STATUSES, Task, TaskQueue, TaskStatus, utc_now
from recon.core.redaction import sanitize_event_for_storage
from recon.core.router import Router, RouteRule, RoutingContext
from recon.core.scheduler import (
    ScheduleDecision,
    Scheduler,
    SchedulerConfig,
    SchedulingSignals,
)
from recon.exporters.csv import CsvExportOptions, export_csv_bundle
from recon.exporters.jsonl import (
    ExportMode,
    JsonlExportOptions,
    WorkspaceSensitiveEvidenceProvider,
    export_jsonl,
)
from recon.exporters.text import TextExportOptions, export_text_bundle
from recon.intelligence.confidence import ConfidenceModel, ConfidenceModelConfig
from recon.intelligence.convergence import (
    BranchBudgetInspector,
    ConvergenceConfig,
    ConvergenceController,
    SearchTier,
)
from recon.intelligence.genome import TargetGenomeBuilder, TargetGenomeConfig
from recon.intelligence.novelty import NoveltyModel, NoveltyModelConfig
from recon.intelligence.patterns import PatternEngine, PatternEngineConfig
from recon.intelligence.vocabulary import VocabularyProjector, VocabularyProjectorConfig
from recon.intelligence.vulnerabilities import (
    NvdApiError,
    NvdClientConfig,
    NvdVulnerabilityIntelligence,
    SQLiteNvdCache,
    cve_candidate_events,
)
from recon.intelligence.wordlists import (
    ManifestGlobalCorpus,
    StaticGlobalCorpus,
    WordlistCorpus,
    WordlistCorpusConfig,
)
from recon.intelligence.yield_model import (
    PatternYieldFeedbackAdapter,
    WordlistYieldFeedbackAdapter,
    YieldExecutionOutcome,
    YieldModel,
    YieldModelConfig,
    target_key_for_event,
    yield_observation_from_task,
)
from recon.policy.rate_limit import RateLimiter, RateLimitProfile
from recon.policy.request_identity import (
    TARGET_HTTP_IDENTITY_WORKERS,
    RequestIdentityPolicy,
)
from recon.policy.restrictions import (
    RestrictionDecision,
    RestrictionEngine,
    RestrictionRule,
    RestrictionsGate,
    StaticActionDescriptorProvider,
    default_recon_descriptor_rules,
)
from recon.policy.review_gate import (
    ReviewCase,
    ReviewCaseState,
    ReviewCategory,
    ReviewDecisionRecorder,
    ReviewEvaluation,
    ReviewGate,
    ReviewPolicy,
    ReviewSeverity,
    ReviewSignal,
)
from recon.policy.scope import (
    ScopeAssetKind,
    ScopeDecision,
    ScopeEngine,
    ScopeGate,
    ScopeRule,
    ScopeSubject,
    StaticWorkerActivityProvider,
    WorkerActivity,
)
from recon.policy.seeds import (
    DomainSeedPlan,
    DomainSeedSpec,
    effective_scope_rules,
    plan_domain_seeds,
)
from recon.resources import bundled_resource_root, is_standalone_bundle
from recon.storage.database import (
    BranchRepository,
    Database,
    DatabaseConfig,
    DecisionRepository,
    EventRepository,
    RunRepository,
    SQLiteBudgetStore,
    SQLiteRateLimitStore,
    SQLiteReviewCaseStore,
    SQLiteTaskStore,
    TaskAttemptRepository,
)
from recon.storage.intelligence import SQLiteIntelligenceStores
from recon.storage.models import (
    AssetRecord,
    EventObservationRecord,
    ReconRunRecord,
    ReviewCaseRecord,
    SchedulerDecisionRecord,
    TaskAttemptRecord,
    TaskRecord,
)
from recon.storage.provenance import ProvenanceRepository
from recon.storage.schema import upgrade_database
from recon.storage.snapshots import SnapshotKind, SnapshotRepository, SurfaceState
from recon.storage.workspace import (
    WorkspaceBinding,
    WorkspaceRepository,
    recorded_workspace_target_ids,
    workspace_directory_name,
)
from recon.tooling import (
    ToolRequirement,
    activate_managed_tool_path,
    assert_supported_platform,
    detect_platform,
    load_tools_manifest,
    probe_tool,
)
from recon.userenv import user_paths
from recon.workers.archives import (
    ArchivesWorker,
    ArchivesWorkerConfig,
    URLFinderConfig,
    URLFinderSource,
    archive_route_rules,
)
from recon.workers.asn import (
    AsnmapBackend,
    AsnmapConfig,
    ASNWorker,
    ASNWorkerConfig,
    asn_route_rules,
)
from recon.workers.content import (
    ContentWorker,
    ContentWorkerConfig,
    HttpxContentBackend,
    HttpxContentConfig,
    WorkspaceContentStore,
    content_route_rules,
)
from recon.workers.crawler import (
    CrawlerWorker,
    CrawlerWorkerConfig,
    KatanaBackend,
    KatanaConfig,
    crawler_route_rules,
)
from recon.workers.dns import DNSWorker, DNSWorkerConfig, DnsxBackend, DnsxConfig, dns_route_rules
from recon.workers.fingerprints import (
    FingerprintWorker,
    FingerprintWorkerConfig,
    fingerprint_route_rules,
)
from recon.workers.http import (
    HTTPWorker,
    HTTPWorkerConfig,
    HttpxBackend,
    HttpxConfig,
    http_route_rules,
)
from recon.workers.javascript import (
    FileJavaScriptContentProvider,
    JavaScriptAnalysisConfig,
    JavaScriptWorker,
    javascript_route_rules,
)
from recon.workers.mobile import (
    ApktoolDecompiler,
    GitleaksSecretScanner,
    ImportedMobileArtifact,
    JadxDecompiler,
    MobileAnalysisConfig,
    MobileArtifactKind,
    MobileWorker,
    TruffleHogSecretScanner,
    WorkspaceMobileArtifactProvider,
    WorkspaceMobileArtifactStore,
    WorkspaceSensitiveEvidenceStore,
    mobile_route_rules,
)
from recon.workers.nuclei import (
    LocalAuditedTemplateCatalog,
    NucleiBackend,
    NucleiBackendConfig,
    NucleiWorker,
    NucleiWorkerConfig,
    ScopeEngineNucleiRequestScopeProvider,
    nuclei_route_rules,
)
from recon.workers.parameters import (
    ArjunBackend,
    ArjunConfig,
    ParameterDiscoveryConfig,
    ParametersWorker,
    parameter_route_rules,
)
from recon.workers.parameters import (
    InMemoryExplorationCursorStore as ParameterExplorationCursorStore,
)
from recon.workers.passive_domains import (
    PassiveDomainsConfig,
    PassiveDomainsWorker,
    SubfinderConfig,
    SubfinderSource,
    normalize_dns_name,
    passive_domain_route_rules,
)
from recon.workers.permutations import (
    InMemoryExplorationCursorStore as PermutationExplorationCursorStore,
)
from recon.workers.permutations import (
    PermutationsConfig,
    PermutationsWorker,
    permutation_route_rules,
)
from recon.workers.tls import TLSWorker, TLSWorkerConfig, TlsxBackend, TlsxConfig, tls_route_rules
from recon.workers.vhost import (
    HttpxVHostBackend,
    HttpxVHostConfig,
    ScopeEngineVHostCandidateScopeProvider,
    VHostWorker,
    VHostWorkerConfig,
    WordlistVHostCandidateProvider,
    vhost_route_rules,
)


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """PyYAML loader that rejects duplicate keys instead of silently overwriting."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    loaded = yaml.load(raw, Loader=_UniqueKeyLoader)
    if not isinstance(loaded, dict):
        raise ValueError(f"YAML root must be an object: {path}")
    return loaded


def discover_project_root(path: Path) -> Path:
    """Find the source/config root in checkout or standalone distribution."""
    candidate = path.expanduser().resolve()
    if candidate.is_file():
        candidate = candidate.parent

    for parent in (candidate, *candidate.parents):
        if (parent / "pyproject.toml").is_file():
            return parent

    bundled = bundled_resource_root()
    if (bundled / "configs").is_dir():
        # User configuration may live under ~/.config/nightscout while runtime
        # resources still live in the installed/PyInstaller bundle.  Relative
        # resource paths therefore resolve against the bundle, not the config
        # directory.  NIGHTSCOUT_PROJECT_ROOT remains the explicit override.
        return bundled
    return candidate


def resolve_project_path(project_root: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (project_root / path).resolve()


class ScopeGateDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_unknown_passive: bool = False


class ScopeDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1)
    target_id: str
    display_name: str | None = None
    gate: ScopeGateDocument = Field(default_factory=ScopeGateDocument)
    rules: tuple[ScopeRule, ...]

    @field_validator("target_id")
    @classmethod
    def target_id_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("target_id must not be blank")
        return normalized


class RuntimeLoopConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_steps: int = Field(default=10_000, ge=1)
    task_lease_seconds: int = Field(default=300, ge=30)
    heartbeat_interval_seconds: int = Field(default=60, ge=5)
    recover_retry_delay_seconds: int = Field(default=0, ge=0)
    resume_frontier: bool = True
    max_deferred_wait_seconds: float = Field(default=60.0, ge=0.0, le=3600.0)

    project_vocabulary: bool = True
    vulnerability_enrichment: bool = True
    snapshot_capture: bool = True
    snapshot_diff_on_write: bool = True
    build_genome_on_finish: bool = True

    novel_asset_threshold: float = Field(default=0.70, ge=0.0, le=1.0)


class RestrictionsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    rules: tuple[RestrictionRule, ...] = ()


class PipelineDocument(BaseModel):
    """Typed top-level pipeline document; subsystem sections validate natively."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1)
    profile_id: str
    display_name: str | None = None
    scope_file: str | None = None

    runtime: RuntimeLoopConfig = Field(default_factory=RuntimeLoopConfig)
    storage: dict[str, Any]
    scheduler: dict[str, Any]
    budgets: dict[str, Any]
    rate_limit: dict[str, Any]
    routing: dict[str, Any]
    exploration: dict[str, Any] = Field(default_factory=dict)
    restrictions: RestrictionsDocument = Field(default_factory=RestrictionsDocument)
    workers: dict[str, dict[str, Any]]
    intelligence: dict[str, Any]
    snapshots: dict[str, Any] = Field(default_factory=dict)
    exports: dict[str, Any] = Field(default_factory=dict)

    @field_validator("profile_id")
    @classmethod
    def profile_id_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("profile_id must not be blank")
        return normalized


class LoadedRuntimeConfiguration(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid", frozen=True)

    project_root: Path
    workspace_root: Path
    pipeline_path: Path
    scope_path: Path
    pipeline: PipelineDocument
    scope: ScopeDocument
    config_hash: str

    def resolve_resource(self, value: str | Path) -> Path:
        return resolve_project_path(self.project_root, value)

    def resolve_workspace(self, value: str | Path) -> Path:
        path = Path(value).expanduser()
        if path.is_absolute():
            return path.resolve()
        return (self.workspace_root / path).resolve()

    # Backward-compatible alias: persisted/mutable runtime paths should use
    # workspace semantics. Resource paths call resolve_resource explicitly.
    def resolve(self, value: str | Path) -> Path:
        return self.resolve_workspace(value)

    def worker(self, name: str) -> dict[str, Any]:
        return dict(self.pipeline.workers.get(name, {}))

    def worker_enabled(self, name: str) -> bool:
        return bool(self.pipeline.workers.get(name, {}).get("enabled", False))


class RuntimeRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    status: str
    seed_event_id: str
    target: str
    scope_state: ScopeState

    steps: int
    outcomes: dict[str, int]
    stopped_idle: bool
    max_steps_reached: bool
    paused_deferred: bool = False
    next_resume_at: datetime | None = None

    task_counts: dict[str, int]
    attempt_counts: dict[str, int]
    event_count: int
    asset_count: int
    open_review_cases: int

    genome_fingerprint: str | None = None
    warnings: tuple[str, ...] = ()


class RuntimeSeedSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_event_id: str
    target: str
    scope_state: ScopeState
    mode: str
    matched_rule_id: str | None = None
    source_rule_ids: tuple[str, ...] = ()
    genome_fingerprint: str | None = None
    artifact_ref: str | None = None
    artifact_kind: str | None = None
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = Field(default=None, ge=0)


class RuntimeProgramRunSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    status: str
    seeds: tuple[RuntimeSeedSummary, ...]

    steps: int
    outcomes: dict[str, int]
    stopped_idle: bool
    max_steps_reached: bool
    paused_deferred: bool = False
    next_resume_at: datetime | None = None

    task_counts: dict[str, int]
    attempt_counts: dict[str, int]
    event_count: int
    asset_count: int
    open_review_cases: int

    warnings: tuple[str, ...] = ()


class RuntimeMobileArtifactInput(BaseModel):
    """One local mobile artifact supplied as an additional program seed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_path: Path
    app_id: str
    source_url: str | None = None
    kind: MobileArtifactKind | None = None

    @field_validator("app_id")
    @classmethod
    def app_id_required(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("app_id must not be blank")
        return normalized

    @field_validator("source_url")
    @classmethod
    def normalize_source_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None


@dataclass(frozen=True, slots=True)
class _PreparedMobileIngress:
    input: RuntimeMobileArtifactInput
    subject: ScopeSubject
    decision: ScopeDecision
    store: WorkspaceMobileArtifactStore


@dataclass(frozen=True, slots=True)
class _RuntimeFrontierResult:
    run_id: str
    status: str
    steps: int
    outcomes: dict[str, int]
    stopped_idle: bool
    max_steps_reached: bool
    paused_deferred: bool
    next_resume_at: datetime | None
    status_snapshot: RuntimeStatus


class RuntimeProgress(BaseModel):
    """One live, non-persistent progress update for a running CLI/API client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    phase: Literal[
        "STARTED",
        "EXECUTING",
        "STEP",
        "WAITING",
        "FINISHED",
        "FAILED",
    ]
    step: int = Field(default=0, ge=0)
    max_steps: int = Field(ge=1)
    outcome: LifecycleOutcome | None = None
    task_id: str | None = None
    worker: str | None = None
    action: str | None = None
    reason: str | None = None
    queue_status: TaskStatus | None = None
    wait_seconds: float | None = Field(default=None, ge=0.0)
    next_resume_at: datetime | None = None
    run_status: str | None = None


RuntimeProgressCallback = Callable[[RuntimeProgress], None]


class RuntimeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str
    workspace_root: str
    database_path: str
    event_count: int
    asset_count: int
    task_counts: dict[str, int]
    attempt_counts: dict[str, int]
    open_review_cases: int
    run_counts: dict[str, int]
    warnings: tuple[str, ...] = ()


class DoctorCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    ok: bool
    required: bool = True
    detail: str


class DoctorReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pipeline_path: str
    scope_path: str | None
    checks: tuple[DoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.ok or not check.required for check in self.checks)


@dataclass(slots=True)
class PublicationMetrics:
    new_assets: int = 0
    novel_assets: int = 0
    new_domains: int = 0
    new_urls: int = 0
    new_endpoints: int = 0
    new_vocabulary_tokens: int = 0
    new_patterns: int = 0
    observations: int = 0
    source_ids: set[str] = field(default_factory=set)


class RuntimeEventLog:
    """Append-only safe Event JSONL audit log.

    Raw mobile secrets never enter Event objects, therefore this log intentionally
    stores the complete normalized Event payload.
    """

    def __init__(self, path: Path, *, enabled: bool) -> None:
        self.path = path
        self.enabled = enabled
        self._lock = asyncio.Lock()

    async def append(self, event: Event) -> None:
        if not self.enabled:
            return
        payload = (
            json.dumps(
                event.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        async with self._lock:
            await asyncio.to_thread(self._append_sync, payload)

    def _append_sync(self, payload: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        fd = os.open(self.path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as handle:
                handle.write(payload)
                handle.flush()
        finally:
            os.close(fd)


class RuntimeScopeSubjectProvider:
    """Resolve concrete execution targets from task input Events + lineage."""

    def __init__(self, events: EventRepository, *, max_parent_depth: int = 24) -> None:
        self._events = events
        self._max_parent_depth = max_parent_depth

    async def subject_for(self, task: Task) -> ScopeSubject | None:
        event = await self._events.get_event(task.input_event_id)
        seen: set[str] = set()

        for _ in range(self._max_parent_depth):
            if event is None or event.event_id in seen:
                return None
            seen.add(event.event_id)

            direct = scope_subject_from_event(event)
            if direct is not None:
                return direct

            if event.parent_event_id is None:
                return None
            event = await self._events.get_event(event.parent_event_id)

        return None


class ScopeDecisionAuditRecorder:
    def __init__(self, decisions: DecisionRepository) -> None:
        self._decisions = decisions

    async def record(
        self,
        *,
        task: Task,
        decision: ScopeDecision,
        activity: WorkerActivity,
    ) -> None:
        await self._decisions.record_policy(
            task_id=task.task_id,
            gate="scope",
            outcome=decision.state.value,
            reason=decision.reason,
            details={
                "activity": activity.value,
                "subject": decision.subject.model_dump(mode="json"),
                "matched_rule_id": decision.matched_rule_id,
                "matched_rule_ids": list(decision.matched_rule_ids),
                "tier": decision.tier,
            },
        )


class RestrictionDecisionAuditRecorder:
    def __init__(self, decisions: DecisionRepository) -> None:
        self._decisions = decisions

    async def record(self, *, task: Task, decision: RestrictionDecision) -> None:
        await self._decisions.record_policy(
            task_id=task.task_id,
            gate="restrictions",
            outcome=decision.outcome.value,
            reason=decision.reason,
            details={
                "source": decision.source.value,
                "matched_rule_id": decision.matched_rule_id,
                "matched_rule_ids": list(decision.matched_rule_ids),
                "descriptor": (
                    decision.descriptor.model_dump(mode="json")
                    if decision.descriptor is not None
                    else None
                ),
            },
        )


class ReviewDecisionAuditRecorder(ReviewDecisionRecorder):
    def __init__(self, decisions: DecisionRepository) -> None:
        self._decisions = decisions

    async def record(self, *, task: Task, evaluation: ReviewEvaluation) -> None:
        await self._decisions.record_policy(
            task_id=task.task_id,
            gate="review",
            outcome=evaluation.outcome.value,
            reason=evaluation.reason,
            details={
                "case_id": evaluation.case_id,
                "triggering": [
                    signal.model_dump(mode="json") for signal in evaluation.triggering_signals
                ],
                "ignored": [
                    signal.model_dump(mode="json") for signal in evaluation.ignored_signals
                ],
            },
        )


class RuntimeRestrictionReviewBridge:
    def __init__(self, cases: SQLiteReviewCaseStore) -> None:
        self._cases = cases

    async def approved_for_task(
        self,
        *,
        task: Task,
        decision: RestrictionDecision,
    ) -> bool:
        signal = _restriction_review_signal(task, decision)
        approved = await self._cases.approved_for_task(
            task.task_id,
            signal_fingerprints=(signal.stable_fingerprint,),
        )
        return approved is not None

    async def open_case(
        self,
        *,
        task: Task,
        decision: RestrictionDecision,
    ) -> str:
        signal = _restriction_review_signal(task, decision)
        review_case = await self._cases.open_or_get(
            task=task,
            signals=(signal,),
        )
        return review_case.case_id


def _restriction_review_signal(
    task: Task,
    decision: RestrictionDecision,
) -> ReviewSignal:
    rule = decision.matched_rule_id or decision.source.value
    return ReviewSignal(
        category=ReviewCategory.POLICY_AMBIGUITY,
        severity=ReviewSeverity.HIGH,
        confidence=1.0,
        summary=f"program restriction {rule}: {decision.reason}",
        source_event_id=task.input_event_id,
        evidence_fingerprint=hashlib.sha256(
            f"restriction|{task.task_id}|{rule}".encode()
        ).hexdigest(),
        tags=frozenset({"program-restriction", rule.lower()}),
    )


class RuntimeLifecycleReviewCoordinator(LifecycleReviewCoordinator):
    """Persist review decisions from gates without their own case bridge."""

    def __init__(self, cases: SQLiteReviewCaseStore) -> None:
        self._cases = cases

    @staticmethod
    def _signal(*, task: Task, gate_name: str, reason: str) -> ReviewSignal:
        normalized_gate = gate_name.strip() or "ExecutionGate"
        category = (
            ReviewCategory.SCOPE_AMBIGUITY
            if "scope" in normalized_gate.lower()
            else ReviewCategory.POLICY_AMBIGUITY
        )
        return ReviewSignal(
            category=category,
            severity=ReviewSeverity.HIGH,
            confidence=1.0,
            summary=f"execution gate {normalized_gate} requires manual review",
            source_event_id=task.input_event_id,
            evidence_fingerprint=hashlib.sha256(
                f"lifecycle|{task.task_id}|{normalized_gate}|{reason}".encode()
            ).hexdigest(),
            tags=frozenset({"lifecycle-review", normalized_gate.lower()}),
        )

    async def approved_for(
        self,
        *,
        task: Task,
        gate_name: str,
        reason: str,
    ) -> bool:
        signal = self._signal(task=task, gate_name=gate_name, reason=reason)
        approved = await self._cases.approved_for_task(
            task.task_id,
            signal_fingerprints=(signal.stable_fingerprint,),
        )
        return approved is not None

    async def open_case(
        self,
        *,
        task: Task,
        gate_name: str,
        reason: str,
    ) -> str:
        signal = self._signal(task=task, gate_name=gate_name, reason=reason)
        review_case = await self._cases.open_or_get(task=task, signals=(signal,))
        return review_case.case_id


class RuntimeLifecycleAttemptObserver:
    """Bind lifecycle selections to the currently active persistent run."""

    def __init__(self, attempts: TaskAttemptRepository) -> None:
        self._attempts = attempts
        self._run_id: str | None = None

    def set_run_id(self, run_id: str | None) -> None:
        self._run_id = run_id

    async def start(self, task: Task, schedule: ScheduleDecision) -> str | None:
        del schedule
        if self._run_id is None:
            return None
        return await self._attempts.start(run_id=self._run_id, task=task)

    async def finish(
        self,
        attempt_id: str,
        result: LifecycleResult,
    ) -> None:
        await self._attempts.finish(
            attempt_id,
            outcome=result.outcome.value,
            queue_status=(result.queue_status.value if result.queue_status is not None else None),
            reason=result.reason,
            reservation_id=result.reservation_id,
            claimed=result.claimed,
            execution_attempt=result.execution_attempt,
        )


class RuntimeReviewSignalProvider:
    """Small fail-safe classifier for explicitly tagged sensitive follow-ups."""

    def __init__(self, events: EventRepository) -> None:
        self._events = events

    async def signals_for(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> tuple[ReviewSignal, ...]:
        del schedule
        event = await self._events.get_event(task.input_event_id)
        if event is None:
            return ()

        tags = {tag.strip().lower() for tag in event.tags}
        signals: list[ReviewSignal] = []

        if any("secret" in tag or "credential" in tag for tag in tags):
            signals.append(
                ReviewSignal(
                    category=ReviewCategory.POSSIBLE_SECRET,
                    severity=ReviewSeverity.HIGH,
                    confidence=max(event.confidence, 0.75),
                    summary="input event contains a redacted possible-secret signal",
                    source_event_id=event.event_id,
                    evidence_fingerprint=_safe_evidence_fingerprint(event),
                    tags=frozenset({"runtime", "redacted"}),
                )
            )

        if event.metadata.get("private_data") is True:
            signals.append(
                ReviewSignal(
                    category=ReviewCategory.PRIVATE_DATA,
                    severity=ReviewSeverity.HIGH,
                    confidence=max(event.confidence, 0.75),
                    summary="input event indicates possible private-data exposure",
                    source_event_id=event.event_id,
                    evidence_fingerprint=_safe_evidence_fingerprint(event),
                    tags=frozenset({"runtime", "redacted"}),
                )
            )

        if event.metadata.get("auth_boundary") is True:
            signals.append(
                ReviewSignal(
                    category=ReviewCategory.AUTH_BOUNDARY,
                    severity=ReviewSeverity.HIGH,
                    confidence=max(event.confidence, 0.70),
                    summary="input event indicates an authentication-boundary follow-up",
                    source_event_id=event.event_id,
                    evidence_fingerprint=_safe_evidence_fingerprint(event),
                    tags=frozenset({"runtime"}),
                )
            )

        if event.metadata.get("review_required") is True:
            signals.append(
                ReviewSignal(
                    category=ReviewCategory.UNKNOWN_SENSITIVE_CONTENT,
                    severity=ReviewSeverity.MEDIUM,
                    confidence=max(event.confidence, 0.60),
                    summary="upstream event explicitly requested human review before follow-up",
                    source_event_id=event.event_id,
                    evidence_fingerprint=_safe_evidence_fingerprint(event),
                    tags=frozenset({"runtime"}),
                )
            )

        return tuple(signals)


class CompositeSchedulingSignalProvider:
    """Dynamic confidence + novelty + historical yield scheduler signals."""

    def __init__(
        self,
        *,
        events: EventRepository,
        confidence: ConfidenceModel,
        novelty: NoveltyModel,
        yield_model: YieldModel,
    ) -> None:
        self._events = events
        self._confidence = confidence
        self._novelty = novelty
        self._yield = yield_model

    async def signals_for(self, task: Task) -> SchedulingSignals:
        event = await self._events.get_event(task.input_event_id)
        if event is None:
            return SchedulingSignals()

        confidence_task = asyncio.create_task(self._confidence.assess(event))
        novelty_task = asyncio.create_task(self._novelty.assess(event))
        yield_task = asyncio.create_task(self._yield.task_estimate(task, input_event=event))

        confidence, novelty, yield_estimate = await asyncio.gather(
            confidence_task,
            novelty_task,
            yield_task,
        )

        return SchedulingSignals(
            confidence=confidence.confidence,
            novelty=novelty.novelty,
            expected_yield=yield_estimate.expected_yield,
            information_gain=yield_estimate.information_gain,
            estimated_cost=yield_estimate.estimated_cost,
        )


class RecordingScheduler(Scheduler):
    """Scheduler that persists each bounded ranking in one transaction."""

    def __init__(self, *args: Any, decisions: DecisionRepository, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._decisions = decisions

    async def select_next(self) -> ScheduleDecision | None:
        ranked = await self.rank_ready()
        if ranked:
            await self._decisions.record_schedules(
                ranked,
                selected_task_id=ranked[0].task_id,
            )
        return ranked[0] if ranked else None


class RuntimeConvergenceGate:
    """Enforce persisted branch convergence before budget reservation/claim."""

    def __init__(self, *, events: EventRepository, state_store: Any) -> None:
        self._events = events
        self._state_store = state_store

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        del schedule
        if task.branch_id is None:
            return GateDecision(outcome=GateOutcome.ALLOW)

        seed = await self._events.get_event(task.branch_id)
        if seed is None:
            return GateDecision(outcome=GateOutcome.ALLOW)

        state = await self._state_store.get(
            target_key=target_key_for_event(seed),
            branch_id=task.branch_id,
            lane=task_budget_lane(task),
        )
        if state is None:
            return GateDecision(outcome=GateOutcome.ALLOW)
        if state.closed:
            return GateDecision(
                outcome=GateOutcome.BLOCK,
                reason="convergence closed this branch",
            )
        if state.cooldown_until is not None:
            remaining = (state.cooldown_until - utc_now()).total_seconds()
            if remaining > 0:
                return GateDecision(
                    outcome=GateOutcome.DEFER,
                    reason="convergence cooldown is active for this branch",
                    retry_after_seconds=remaining,
                )
        return GateDecision(outcome=GateOutcome.ALLOW)


class RuntimeExplorationGate:
    """Block exploration tasks when the pipeline disables that subsystem."""

    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        del schedule
        if not self._enabled and task_budget_lane(task) is BudgetLane.EXPLORATION:
            return GateDecision(
                outcome=GateOutcome.BLOCK,
                reason="exploration is disabled by pipeline configuration",
            )
        return GateDecision(outcome=GateOutcome.ALLOW)


class RuntimeBudgetPlanner:
    """Translate worker envelopes into shared BudgetManager demand."""

    def __init__(
        self,
        *,
        events: EventRepository,
        scope_subjects: RuntimeScopeSubjectProvider,
        convergence_store: Any,
        configuration: LoadedRuntimeConfiguration,
    ) -> None:
        self._events = events
        self._scope_subjects = scope_subjects
        self._convergence_store = convergence_store
        self._configuration = configuration

    async def plan(self, task: Task, schedule: ScheduleDecision) -> BudgetPlan:
        input_event = await self._events.get_event(task.input_event_id)
        depth = input_event.depth if input_event is not None else 0
        lane = task_budget_lane(task)
        resources = await self._resource_keys(task)
        multiplier = 1.0

        if task.branch_id is not None and input_event is not None:
            seed = await self._events.get_event(task.branch_id)
            target_event = seed or input_event
            state = await self._convergence_store.get(
                target_key=target_key_for_event(target_event),
                branch_id=task.branch_id,
                lane=lane,
            )
            if state is not None:
                multiplier = state.branch_soft_multiplier

        requests, candidates, runtime_seconds = self._estimate_worker_demand(task)

        return BudgetPlan(
            demand=BudgetDemand(
                tasks=1.0,
                cost=schedule.signals.estimated_cost,
                requests=requests,
                candidates=candidates,
                runtime_seconds=runtime_seconds,
                concurrent_tasks=1.0,
            ),
            context=BudgetContext(
                branch_depth=depth,
                resource_keys=frozenset(resources),
                lane=lane,
                branch_soft_multiplier=multiplier,
            ),
        )

    async def _resource_keys(self, task: Task) -> set[str]:
        subject = await self._scope_subjects.subject_for(task)
        if subject is None:
            return set()

        if subject.kind is ScopeAssetKind.URL:
            host = urlsplit(subject.value).hostname
            return {f"host:{host}"} if host else set()

        if subject.kind is ScopeAssetKind.DOMAIN:
            return {f"host:{subject.value}"}

        if subject.kind is ScopeAssetKind.IP_ADDRESS:
            return {f"ip:{subject.value}"}

        return set()

    def _estimate_worker_demand(self, task: Task) -> tuple[float, float, float]:
        section = self._configuration.worker(task.worker)
        config = section.get("config", {}) if isinstance(section, dict) else {}
        backend = section.get("backend", {}) if isinstance(section, dict) else {}

        requests = 0.0
        candidates = 0.0
        runtime_seconds = 0.0

        if task.worker == "dns":
            requests = float(len(config.get("record_types", ["A", "AAAA", "CNAME"])))
            runtime_seconds = float(backend.get("process_timeout_seconds", 15))
        elif task.worker == "http":
            requests = float(len(backend.get("schemes", ["https", "http"])))
            runtime_seconds = float(backend.get("process_timeout_seconds", 20))
        elif task.worker == "tls":
            requests = 1.0
            runtime_seconds = float(backend.get("process_timeout_seconds", 12))
        elif task.worker == "crawler":
            requests = float(backend.get("max_domain_pages", 250))
            candidates = requests
            runtime_seconds = float(backend.get("process_timeout_seconds", 90))
        elif task.worker == "content":
            requests = 1.0
            runtime_seconds = float(backend.get("process_timeout_seconds", 20))
        elif task.worker == "parameters":
            if "exploration" in task.action:
                candidates = float(config.get("exploration_candidates", 150))
            else:
                candidates = float(config.get("targeted_candidates", 300))
            requests = candidates
            runtime_seconds = float(config.get("process_timeout_seconds", 300))
        elif task.worker == "vhost":
            if "exploration" in task.action:
                candidates = float(config.get("exploration_limit", 100))
            else:
                candidates = float(config.get("targeted_limit", 250))
            requests = candidates + 8.0
            runtime_seconds = float(backend.get("process_timeout_seconds", 20)) * max(
                1.0, candidates
            )
        elif task.worker == "nuclei":
            requests = float(config.get("max_requests_per_template", 3))
            candidates = 1.0
            runtime_seconds = float(backend.get("process_timeout_seconds", 60))
        elif task.worker == "permutations":
            candidates = float(config.get("max_candidates") or 2_000)
        elif task.worker in {"passive_domains", "archives", "asn"}:
            runtime_seconds = float(backend.get("process_timeout_seconds", 60))
        elif task.worker == "mobile":
            runtime_seconds = float(config.get("decompiler_timeout_seconds", 180))
        elif task.worker in {"javascript", "fingerprints"}:
            runtime_seconds = 1.0

        return requests, candidates, runtime_seconds


class RuntimeEventBus:
    """Durable event ingest -> enrichment -> routing bus."""

    def __init__(
        self,
        *,
        events: EventRepository,
        branches: BranchRepository,
        provenance: ProvenanceRepository,
        snapshots: SnapshotRepository,
        router: Router,
        queue: TaskQueue,
        scope_engine: ScopeEngine,
        confidence: ConfidenceModel,
        novelty: NoveltyModel,
        vocabulary: VocabularyProjector,
        vulnerabilities: NvdVulnerabilityIntelligence | None,
        event_log: RuntimeEventLog,
        configuration: LoadedRuntimeConfiguration,
        effective_disabled_workers: frozenset[str],
        warnings: list[str],
    ) -> None:
        self._events = events
        self._branches = branches
        self._provenance = provenance
        self._snapshots = snapshots
        self._router = router
        self._queue = queue
        self._scope_engine = scope_engine
        self._confidence = confidence
        self._novelty = novelty
        self._vocabulary = vocabulary
        self._vulnerabilities = vulnerabilities
        self._event_log = event_log
        self._configuration = configuration
        self._disabled_workers = effective_disabled_workers
        self._warnings = warnings

        self._run_id: str | None = None
        self._task_var: contextvars.ContextVar[Task | None] = contextvars.ContextVar(
            "nightscout_runtime_task",
            default=None,
        )
        self._branch_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "nightscout_runtime_branch",
            default=None,
        )
        self._metrics_var: contextvars.ContextVar[PublicationMetrics | None] = (
            contextvars.ContextVar(
                "nightscout_runtime_metrics",
                default=None,
            )
        )

    @property
    def run_id(self) -> str | None:
        return self._run_id

    def set_run_id(self, run_id: str | None) -> None:
        self._run_id = run_id

    @contextlib.contextmanager
    def bind_task(self, task: Task, metrics: PublicationMetrics) -> Any:
        branch = task.branch_id or self._branch_var.get()
        token_task = self._task_var.set(task)
        token_branch = self._branch_var.set(branch)
        token_metrics = self._metrics_var.set(metrics)
        try:
            yield
        finally:
            self._metrics_var.reset(token_metrics)
            self._branch_var.reset(token_branch)
            self._task_var.reset(token_task)

    @contextlib.contextmanager
    def bind_branch(self, branch_id: str) -> Any:
        token = self._branch_var.set(branch_id)
        try:
            yield
        finally:
            self._branch_var.reset(token)

    async def publish(self, event: Event) -> bool:
        normalized = await self._prepare_event(event)
        write = await self._events.ingest(normalized, run_id=self._run_id)

        if not write.observation_created:
            return False

        await self._event_log.append(normalized)

        if normalized.parent_event_id is not None:
            try:
                await self._provenance.capture_primary_parent(normalized.event_id)
            except (KeyError, ValueError) as exc:
                self._warnings.append(f"provenance edge skipped for {normalized.event_id}: {exc}")

        self._capture_metrics(normalized, asset_created=write.asset_created)
        await self._capture_snapshot(normalized, asset_id=write.asset_id)
        await self._route(normalized)

        runtime_cfg = self._configuration.pipeline.runtime

        if runtime_cfg.project_vocabulary and normalized.type is not EventType.VOCAB_TOKEN:
            for token_event in self._vocabulary.token_events(normalized):
                await self.publish(token_event)

        if (
            runtime_cfg.vulnerability_enrichment
            and self._vulnerabilities is not None
            and normalized.type is EventType.TECHNOLOGY
        ):
            await self._enrich_vulnerabilities(normalized)

        return True

    async def _prepare_event(self, event: Event) -> Event:
        event = sanitize_event_for_storage(event)
        direct_subject = scope_subject_from_event(event)
        prepared = event

        if direct_subject is not None:
            decision = self._scope_engine.evaluate(direct_subject)
            prepared = prepared.model_copy(
                update={"scope_state": decision.state},
                deep=True,
            )

        if "seed" in {tag.lower() for tag in prepared.tags}:
            return prepared

        prepared = await self._confidence.apply(prepared)
        prepared = await self._novelty.scored_event(prepared)
        return prepared

    async def _route(self, event: Event) -> None:
        branch_id = self._branch_var.get()

        if branch_id is not None:
            # Tasks have a real FK to branches. Ensure the durable branch row
            # exists after the root Event has been persisted and before any
            # routed Task references it. Child events defensively repeat this
            # idempotent ensure, which also repairs missing run provenance from
            # older/interrupted runs.
            root_event = await self._events.get_event(branch_id)
            await self._branches.ensure(
                branch_id,
                run_id=self._run_id,
                root_event_id=(root_event.event_id if root_event is not None else None),
                depth=(root_event.depth if root_event is not None else 0),
            )

        context = RoutingContext(
            branch_id=branch_id,
            disabled_workers=self._disabled_workers,
        )
        tasks = self._router.expand(event, context=context)
        await self._queue.enqueue_many(tasks)

    def _capture_metrics(self, event: Event, *, asset_created: bool) -> None:
        metrics = self._metrics_var.get()
        if metrics is None:
            return

        metrics.observations += 1
        metrics.source_ids.add(event.source)

        if not asset_created:
            return

        metrics.new_assets += 1
        if event.novelty >= self._configuration.pipeline.runtime.novel_asset_threshold:
            metrics.novel_assets += 1
        if event.type is EventType.DNS_NAME:
            metrics.new_domains += 1
        elif event.type is EventType.URL:
            metrics.new_urls += 1
        elif event.type is EventType.API_ENDPOINT:
            metrics.new_endpoints += 1
        elif event.type is EventType.VOCAB_TOKEN:
            metrics.new_vocabulary_tokens += 1
        elif event.type is EventType.NAMING_PATTERN:
            metrics.new_patterns += 1

    async def _capture_snapshot(self, event: Event, *, asset_id: str) -> None:
        if self._run_id is None or not self._configuration.pipeline.runtime.snapshot_capture:
            return

        raw_kind = event.metadata.get("snapshot_kind")
        raw_state = event.metadata.get("surface_state")

        if not isinstance(raw_kind, str) or not isinstance(raw_state, dict):
            return

        try:
            kind = SnapshotKind(raw_kind.strip().upper())
        except ValueError:
            self._warnings.append(f"unknown snapshot kind on event {event.event_id}: {raw_kind!r}")
            return

        state_payload = dict(raw_state)
        state_payload["scope_state"] = event.scope_state.value

        try:
            state = SurfaceState.model_validate(state_payload)
            captured = await self._snapshots.capture(
                run_id=self._run_id,
                asset_id=asset_id,
                kind=kind,
                state=state,
                observed_at=event.last_seen,
            )
            if self._configuration.pipeline.runtime.snapshot_diff_on_write:
                await self._snapshots.diff_and_record(captured.snapshot.snapshot_id)
        except (ValueError, KeyError) as exc:
            self._warnings.append(f"snapshot skipped for {event.event_id}: {exc}")

    async def _enrich_vulnerabilities(self, event: Event) -> None:
        assert self._vulnerabilities is not None
        try:
            lookup = await self._vulnerabilities.lookup_event(event)
        except NvdApiError as exc:
            self._warnings.append(f"NVD enrichment failed for {event.value}: {exc}")
            return
        except Exception as exc:
            self._warnings.append(
                f"NVD enrichment exception for {event.value}: {type(exc).__name__}: {exc}"
            )
            return

        if lookup is None:
            return

        nuclei_section = self._configuration.worker("nuclei")
        nuclei_config = nuclei_section.get("config", {}) if nuclei_section else {}
        minimum_cpe = float(nuclei_config.get("minimum_cpe_score", 0.60))

        for candidate_event in cve_candidate_events(
            lookup,
            source_event=event,
            minimum_nuclei_cpe_score=minimum_cpe,
        ):
            await self.publish(candidate_event)


class RuntimeWorkerExecutor:
    """Worker registry + yield/convergence instrumentation."""

    def __init__(
        self,
        *,
        workers: Mapping[str, Any],
        event_bus: RuntimeEventBus,
        events: EventRepository,
        yield_model: YieldModel,
        convergence: ConvergenceController,
        convergence_store: Any,
        initial_tier: SearchTier,
        run_id_getter: Any,
        warnings: list[str],
    ) -> None:
        self._workers = dict(workers)
        self._bus = event_bus
        self._events = events
        self._yield = yield_model
        self._convergence = convergence
        self._convergence_store = convergence_store
        self._initial_tier = initial_tier
        self._run_id_getter = run_id_getter
        self._warnings = warnings

    async def execute(self, task: Task) -> WorkerExecutionResult:
        worker = self._workers.get(task.worker)
        if worker is None:
            return WorkerExecutionResult(
                outcome=WorkerOutcome.FAILED,
                error=f"worker is not registered/enabled: {task.worker}",
            )

        input_event = await self._events.get_event(task.input_event_id)
        execution_task = await self._with_search_tier(task, worker=worker)
        metrics = PublicationMetrics()
        started = time.monotonic()

        try:
            with self._bus.bind_task(task, metrics):
                result = WorkerExecutionResult.model_validate(
                    await worker.execute(execution_task)
                )
        except Exception:
            await self._record_yield(
                task,
                input_event=input_event,
                metrics=metrics,
                runtime_seconds=time.monotonic() - started,
                outcome=YieldExecutionOutcome.FAILED,
            )
            raise

        execution_outcome = {
            WorkerOutcome.SUCCEEDED: YieldExecutionOutcome.SUCCEEDED,
            WorkerOutcome.RETRY: YieldExecutionOutcome.RETRY,
            WorkerOutcome.FAILED: YieldExecutionOutcome.FAILED,
        }[result.outcome]

        await self._record_yield(
            task,
            input_event=input_event,
            metrics=metrics,
            runtime_seconds=time.monotonic() - started,
            outcome=execution_outcome,
        )

        await self._update_convergence(task, input_event=input_event)
        return result

    async def _with_search_tier(self, task: Task, *, worker: Any) -> Task:
        tier = self._initial_tier
        if task.branch_id is not None:
            seed = await self._events.get_event(task.branch_id)
            if seed is not None:
                state = await self._convergence_store.get(
                    target_key=target_key_for_event(seed),
                    branch_id=task.branch_id,
                    lane=task_budget_lane(task),
                )
                if state is not None:
                    tier = state.tier

        limit_resolver = getattr(worker, "candidate_limit_for_tier", None)
        candidate_limit = int(limit_resolver(tier.value)) if callable(limit_resolver) else None
        return task.model_copy(
            update={
                "search_tier": tier.value,
                "candidate_limit_hint": candidate_limit,
            }
        )

    async def _record_yield(
        self,
        task: Task,
        *,
        input_event: Event | None,
        metrics: PublicationMetrics,
        runtime_seconds: float,
        outcome: YieldExecutionOutcome,
    ) -> None:
        observation = yield_observation_from_task(
            task,
            input_event=input_event,
            execution_outcome=outcome,
            attempted_units=1,
            successful_hits=(1 if metrics.new_assets > 0 else 0),
            new_assets=metrics.new_assets,
            novel_assets=metrics.novel_assets,
            new_domains=metrics.new_domains,
            new_urls=metrics.new_urls,
            new_endpoints=metrics.new_endpoints,
            new_vocabulary_tokens=metrics.new_vocabulary_tokens,
            new_patterns=metrics.new_patterns,
            runtime_seconds=max(runtime_seconds, 0.0),
            cost_units=1.0,
            source_ids=tuple(sorted(metrics.source_ids)),
            run_id=self._run_id_getter(),
            metadata={
                "published_observations": metrics.observations,
                "runtime_instrumentation": True,
                "request_count_exact": False,
            },
        )
        await self._yield.store.append(observation)

    async def _update_convergence(
        self,
        task: Task,
        *,
        input_event: Event | None,
    ) -> None:
        if task.branch_id is None or input_event is None:
            return

        seed = await self._events.get_event(task.branch_id)
        if seed is None:
            return

        try:
            lane = task_budget_lane(task)
            state = await self._convergence_store.get(
                target_key=target_key_for_event(seed),
                branch_id=task.branch_id,
                lane=lane,
            )
            await self._convergence.evaluate(
                seed_event=seed,
                branch_id=task.branch_id,
                lane=lane,
                current_tier=(state.tier if state is not None else self._initial_tier),
            )
        except Exception as exc:
            self._warnings.append(
                f"convergence update failed for branch {task.branch_id}: "
                f"{type(exc).__name__}: {exc}"
            )


class NightScoutRuntime:
    """Fully wired Night Scout application instance."""

    def __init__(self) -> None:
        self.configuration: LoadedRuntimeConfiguration
        self.database: Database
        self.events: EventRepository
        self.branches: BranchRepository
        self.provenance: ProvenanceRepository
        self.snapshots: SnapshotRepository
        self.task_store: SQLiteTaskStore
        self.queue: TaskQueue
        self.review_store: SQLiteReviewCaseStore
        self.runs: RunRepository
        self.task_attempts: TaskAttemptRepository
        self.attempt_observer: RuntimeLifecycleAttemptObserver
        self.decisions: DecisionRepository
        self.router: Router
        self.scheduler: RecordingScheduler
        self.lifecycle: Lifecycle
        self.scope_engine: ScopeEngine
        self.rate_limiter: RateLimiter
        self.yield_model: YieldModel
        self.genome_builder: TargetGenomeBuilder
        self.intelligence: SQLiteIntelligenceStores
        self.event_bus: RuntimeEventBus
        self.workers: dict[str, Any]
        self.warnings: list[str] = []
        self._run_id: str | None = None
        self._artifact_root: Path
        self._sensitive_root: Path
        self._nvd_cache: SQLiteNvdCache | None = None
        self.workspace: WorkspaceRepository
        self.workspace_binding: WorkspaceBinding
        self.request_identity: RequestIdentityPolicy

    @classmethod
    async def build(
        cls,
        *,
        pipeline_path: str | Path,
        scope_path: str | Path | None = None,
        request_identity: RequestIdentityPolicy | None = None,
    ) -> "NightScoutRuntime":
        self = cls()
        self.configuration = load_runtime_configuration(
            pipeline_path=pipeline_path,
            scope_path=scope_path,
        )

        cfg = self.configuration
        pipeline = cfg.pipeline
        self.request_identity = request_identity or RequestIdentityPolicy()

        storage = pipeline.storage
        database_config = runtime_database_config(cfg)

        # Migrate before the async engine opens pooled connections. Legacy
        # pre-Alembic Night Scout workspaces are adopted only after an exact
        # table/column compatibility check; incompatible databases fail closed.
        migration_result = await asyncio.to_thread(
            upgrade_database,
            database_config.path,
        )

        self.database = Database(database_config)
        self.workspace = WorkspaceRepository(self.database)
        try:
            self.workspace_binding = await self.workspace.bind_or_validate(cfg.scope.target_id)
        except Exception:
            await self.database.dispose()
            raise
        self.warnings.append(
            "schema: "
            f"{migration_result.action.value.lower()} "
            f"revision={migration_result.current_revision or 'none'}"
        )
        if self.workspace_binding.created:
            action = (
                "adopted from run history"
                if self.workspace_binding.adopted_from_history
                else "created"
            )
            self.warnings.append(f"workspace: {action} target={self.workspace_binding.target_id}")

        self.events = EventRepository(self.database)
        self.branches = BranchRepository(self.database)
        self.provenance = ProvenanceRepository(self.database)
        self.snapshots = SnapshotRepository(self.database)
        self.task_store = SQLiteTaskStore(
            self.database,
            resume_frontier=pipeline.runtime.resume_frontier,
        )
        self.queue = TaskQueue(self.task_store)
        self.review_store = SQLiteReviewCaseStore(self.database)
        self.runs = RunRepository(self.database)
        self.task_attempts = TaskAttemptRepository(self.database)
        self.attempt_observer = RuntimeLifecycleAttemptObserver(self.task_attempts)
        self.decisions = DecisionRepository(self.database)

        budget_store = SQLiteBudgetStore(self.database)
        rate_store = SQLiteRateLimitStore(self.database)
        budget_profile = BudgetProfile.model_validate(pipeline.budgets)
        rate_profile = RateLimitProfile.model_validate(pipeline.rate_limit)

        budget_manager = BudgetManager(budget_store, profile=budget_profile)
        self.rate_limiter = RateLimiter(rate_store, profile=rate_profile)

        self.intelligence = SQLiteIntelligenceStores(
            self.database,
            max_target_events=int(
                pipeline.intelligence.get("wordlists", {}).get(
                    "max_target_events",
                    250_000,
                )
            ),
        )

        yield_config = YieldModelConfig.model_validate(pipeline.intelligence.get("yield_model", {}))
        self.yield_model = YieldModel(
            self.intelligence.yield_store,
            config=yield_config,
        )

        confidence = ConfidenceModel(
            provider=self.intelligence.confidence,
            config=ConfidenceModelConfig.model_validate(
                pipeline.intelligence.get("confidence", {})
            ),
        )
        novelty = NoveltyModel(
            provider=self.intelligence.novelty,
            config=NoveltyModelConfig.model_validate(pipeline.intelligence.get("novelty", {})),
        )
        vocabulary = VocabularyProjector(
            VocabularyProjectorConfig.model_validate(pipeline.intelligence.get("vocabulary", {}))
        )

        wordlists_raw = dict(pipeline.intelligence.get("wordlists", {}))
        manifest_value = wordlists_raw.pop("manifest", "wordlists/manifest.yaml")
        corpus_root_value = wordlists_raw.pop("corpus_root", "wordlists")
        manifest_path = cfg.resolve_resource(manifest_value)
        corpus_root = cfg.resolve_resource(corpus_root_value)

        if manifest_path.is_file():
            global_corpus: Any = ManifestGlobalCorpus(
                manifest_path,
                corpus_root=corpus_root,
            )
        else:
            global_corpus = StaticGlobalCorpus(())
            self.warnings.append(
                f"wordlist manifest not found; exploration corpus is empty: {manifest_path}"
            )

        corpus = WordlistCorpus(
            global_corpus=global_corpus,
            target_events=self.intelligence.events,
            yield_feedback=WordlistYieldFeedbackAdapter(self.intelligence.yield_store),
            config=WordlistCorpusConfig.model_validate(wordlists_raw),
        )

        patterns = PatternEngine(
            target_events=self.intelligence.events,
            feedback=PatternYieldFeedbackAdapter(self.intelligence.yield_store),
            config=PatternEngineConfig.model_validate(pipeline.intelligence.get("patterns", {})),
        )

        self.genome_builder = TargetGenomeBuilder(
            events=self.intelligence.events,
            vocabulary=vocabulary,
            patterns=patterns,
            confidence=confidence,
            novelty=novelty,
            yield_model=self.yield_model,
            config=TargetGenomeConfig.model_validate(pipeline.intelligence.get("genome", {})),
        )

        vulnerability_service: NvdVulnerabilityIntelligence | None = None
        vulnerability_raw = dict(pipeline.intelligence.get("vulnerabilities", {}))
        vulnerability_enabled = bool(vulnerability_raw.pop("enabled", True))
        nvd_cache_value = vulnerability_raw.pop(
            "nvd_cache_path",
            ".nightscout/cache/nvd.sqlite3",
        )
        client_data = vulnerability_raw.pop("client", {})
        if vulnerability_raw:
            unknown = ", ".join(sorted(vulnerability_raw))
            raise ValueError(f"unknown vulnerabilities config fields: {unknown}")

        if vulnerability_enabled:
            self._nvd_cache = SQLiteNvdCache(cfg.resolve(nvd_cache_value))
            await self._nvd_cache.initialize()
            vulnerability_service = NvdVulnerabilityIntelligence(
                cache=self._nvd_cache,
                config=NvdClientConfig.model_validate(client_data),
            )

        self.scope_engine = ScopeEngine(list(effective_scope_rules(cfg.scope.rules)))
        scope_subjects = RuntimeScopeSubjectProvider(self.events)

        route_rules = all_runtime_route_rules()
        exploration_enabled = bool(pipeline.exploration.get("enabled", True))
        enabled_rule_ids = {
            str(rule_id).strip()
            for rule_id in pipeline.routing.get("enabled_rule_ids", [])
            if str(rule_id).strip()
        }
        known_rule_ids = {rule.rule_id for rule in route_rules}
        unknown_rules = enabled_rule_ids - known_rule_ids
        if unknown_rules:
            raise ValueError(
                "pipeline enables unknown route rules: " + ", ".join(sorted(unknown_rules))
            )

        enabled_workers = {
            name
            for name, section in pipeline.workers.items()
            if bool(section.get("enabled", False))
        }
        self.router = Router(
            rule
            for rule in route_rules
            if rule.worker in enabled_workers
            and (not enabled_rule_ids or rule.rule_id in enabled_rule_ids)
            and (
                exploration_enabled
                or not is_exploration_work(
                    rule.action,
                    rule.rule_id,
                    rule.reason,
                )
            )
        )

        event_log_raw = dict(storage.get("event_log", {}))
        event_log = RuntimeEventLog(
            cfg.resolve(event_log_raw.get("path", ".nightscout/events.jsonl")),
            enabled=bool(event_log_raw.get("enabled", True)),
        )

        content_root = cfg.resolve(
            storage.get("content_store", {}).get("root", ".nightscout/content")
        )
        artifact_root = cfg.resolve(
            storage.get("artifact_store", {}).get("root", ".nightscout/artifacts")
        )
        sensitive_root = cfg.resolve(
            storage.get("sensitive_evidence", {}).get(
                "root",
                ".nightscout/sensitive-evidence",
            )
        )
        artifact_root.mkdir(parents=True, exist_ok=True)
        self._artifact_root = artifact_root
        self._sensitive_root = sensitive_root

        effective_disabled_workers: set[str] = set(set(pipeline.workers) - enabled_workers)

        # Nuclei is fail-closed if no explicit audited manifest is available.
        nuclei_catalog: LocalAuditedTemplateCatalog | None = None
        nuclei_section = pipeline.workers.get("nuclei", {})
        if "nuclei" in enabled_workers:
            template_data = dict(nuclei_section.get("templates", {}))
            manifest = cfg.resolve_resource(
                template_data.get("manifest", "configs/nuclei-templates.yaml")
            )
            if not manifest.is_file():
                example = manifest.with_name(manifest.name.replace(".yaml", ".example.yaml"))
                if example.is_file():
                    manifest = example
                    self.warnings.append(
                        f"Nuclei audited manifest missing; using empty/example manifest: {manifest}"
                    )
                else:
                    effective_disabled_workers.add("nuclei")
                    self.warnings.append(
                        "Nuclei worker disabled: audited template manifest missing"
                    )
            if "nuclei" not in effective_disabled_workers:
                nuclei_catalog = LocalAuditedTemplateCatalog(
                    manifest_path=manifest,
                    templates_root=cfg.resolve_resource(
                        template_data.get("root", "nuclei-templates")
                    ),
                    max_template_bytes=int(template_data.get("max_template_bytes", 1024 * 1024)),
                    protected_header_names=self.request_identity.header_names,
                )

        self.event_bus = RuntimeEventBus(
            events=self.events,
            branches=self.branches,
            provenance=self.provenance,
            snapshots=self.snapshots,
            router=self.router,
            queue=self.queue,
            scope_engine=self.scope_engine,
            confidence=confidence,
            novelty=novelty,
            vocabulary=vocabulary,
            vulnerabilities=vulnerability_service,
            event_log=event_log,
            configuration=cfg,
            effective_disabled_workers=frozenset(effective_disabled_workers),
            warnings=self.warnings,
        )

        self.workers = self._build_workers(
            corpus=corpus,
            patterns=patterns,
            content_root=content_root,
            artifact_root=artifact_root,
            sensitive_root=sensitive_root,
            nuclei_catalog=nuclei_catalog,
            disabled=frozenset(effective_disabled_workers),
        )

        signal_provider = CompositeSchedulingSignalProvider(
            events=self.events,
            confidence=confidence,
            novelty=novelty,
            yield_model=self.yield_model,
        )
        self.scheduler = RecordingScheduler(
            self.queue,
            signal_provider=signal_provider,
            config=SchedulerConfig.model_validate(pipeline.scheduler),
            decisions=self.decisions,
        )

        descriptor_provider = StaticActionDescriptorProvider(list(default_recon_descriptor_rules()))
        restrictions = RestrictionsGate(
            engine=RestrictionEngine(
                list(pipeline.restrictions.rules) if pipeline.restrictions.enabled else []
            ),
            descriptors=descriptor_provider,
            recorder=RestrictionDecisionAuditRecorder(self.decisions),
            review_bridge=RuntimeRestrictionReviewBridge(self.review_store),
        )

        activities = StaticWorkerActivityProvider(
            activities={
                "passive_domains": WorkerActivity.PASSIVE,
                "permutations": WorkerActivity.PASSIVE,
                "asn": WorkerActivity.PASSIVE,
                "archives": WorkerActivity.PASSIVE,
                "javascript": WorkerActivity.PASSIVE,
                "mobile": WorkerActivity.PASSIVE,
                "fingerprints": WorkerActivity.PASSIVE,
                "dns": WorkerActivity.ACTIVE,
                "http": WorkerActivity.ACTIVE,
                "tls": WorkerActivity.ACTIVE,
                "crawler": WorkerActivity.ACTIVE,
                "content": WorkerActivity.ACTIVE,
                "parameters": WorkerActivity.ACTIVE,
                "vhost": WorkerActivity.ACTIVE,
                "nuclei": WorkerActivity.ACTIVE,
            }
        )
        scope_gate = ScopeGate(
            engine=self.scope_engine,
            subjects=scope_subjects,
            activities=activities,
            recorder=ScopeDecisionAuditRecorder(self.decisions),
            allow_unknown_passive=cfg.scope.gate.allow_unknown_passive,
        )
        review_gate = ReviewGate(
            signals=RuntimeReviewSignalProvider(self.events),
            cases=self.review_store,
            policy=ReviewPolicy(),
            recorder=ReviewDecisionAuditRecorder(self.decisions),
        )

        budget_inspector = BranchBudgetInspector(
            budget_store,
            profile=budget_profile,
        )
        initial_tier = SearchTier(str(pipeline.exploration.get("initial_tier", "SMALL")).upper())
        maximum_tier = SearchTier(
            str(pipeline.exploration.get("maximum_tier", "EXHAUSTIVE")).upper()
        )
        if initial_tier.rank > maximum_tier.rank:
            raise ValueError("exploration.initial_tier cannot exceed maximum_tier")

        convergence = ConvergenceController(
            yield_model=self.yield_model,
            budget_inspector=budget_inspector,
            state_store=self.intelligence.convergence_store,
            config=ConvergenceConfig.model_validate(pipeline.intelligence.get("convergence", {})),
            maximum_tier=maximum_tier,
        )

        executor = RuntimeWorkerExecutor(
            workers=self.workers,
            event_bus=self.event_bus,
            events=self.events,
            yield_model=self.yield_model,
            convergence=convergence,
            convergence_store=self.intelligence.convergence_store,
            initial_tier=initial_tier,
            run_id_getter=lambda: self._run_id,
            warnings=self.warnings,
        )
        budget_planner = RuntimeBudgetPlanner(
            events=self.events,
            scope_subjects=scope_subjects,
            convergence_store=self.intelligence.convergence_store,
            configuration=cfg,
        )
        convergence_gate = RuntimeConvergenceGate(
            events=self.events,
            state_store=self.intelligence.convergence_store,
        )

        runtime_cfg = pipeline.runtime
        self.lifecycle = Lifecycle(
            queue=self.queue,
            scheduler=self.scheduler,
            budgets=budget_manager,
            gates=(
                RuntimeExplorationGate(enabled=exploration_enabled),
                scope_gate,
                restrictions,
                convergence_gate,
                review_gate,
            ),
            executor=executor,
            budget_planner=budget_planner,
            task_lease_for=timedelta(seconds=runtime_cfg.task_lease_seconds),
            heartbeat_interval=timedelta(seconds=runtime_cfg.heartbeat_interval_seconds),
            review_coordinator=RuntimeLifecycleReviewCoordinator(self.review_store),
            attempt_observer=self.attempt_observer,
        )

        await self.lifecycle.recover_expired(
            task_retry_delay=timedelta(seconds=runtime_cfg.recover_retry_delay_seconds)
        )
        await self.rate_limiter.reap_expired()
        return self

    def _build_workers(
        self,
        *,
        corpus: WordlistCorpus,
        patterns: PatternEngine,
        content_root: Path,
        artifact_root: Path,
        sensitive_root: Path,
        nuclei_catalog: LocalAuditedTemplateCatalog | None,
        disabled: frozenset[str],
    ) -> dict[str, Any]:
        pipeline = self.configuration.pipeline
        request_identity = self.request_identity
        result: dict[str, Any] = {}

        def section(name: str) -> dict[str, Any]:
            return pipeline.workers.get(name, {})

        if (
            pipeline.workers.get("passive_domains", {}).get("enabled")
            and "passive_domains" not in disabled
        ):
            raw = section("passive_domains")
            result["passive_domains"] = PassiveDomainsWorker(
                events=self.events,
                publisher=self.event_bus,
                sources=(SubfinderSource(SubfinderConfig.model_validate(raw.get("backend", {}))),),
                config=PassiveDomainsConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("dns", {}).get("enabled") and "dns" not in disabled:
            raw = section("dns")
            result["dns"] = DNSWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                backend=DnsxBackend(DnsxConfig.model_validate(raw.get("backend", {}))),
                config=DNSWorkerConfig.model_validate(raw.get("config", {})),
            )

        if (
            pipeline.workers.get("permutations", {}).get("enabled")
            and "permutations" not in disabled
        ):
            raw = section("permutations")
            result["permutations"] = PermutationsWorker(
                events=self.events,
                publisher=self.event_bus,
                words=corpus,
                exploration_cursors=PermutationExplorationCursorStore(),
                learned=patterns,
                config=PermutationsConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("http", {}).get("enabled") and "http" not in disabled:
            raw = section("http")
            result["http"] = HTTPWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                backend=HttpxBackend(
                    HttpxConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=HTTPWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("tls", {}).get("enabled") and "tls" not in disabled:
            raw = section("tls")
            result["tls"] = TLSWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                backend=TlsxBackend(TlsxConfig.model_validate(raw.get("backend", {}))),
                config=TLSWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("asn", {}).get("enabled") and "asn" not in disabled:
            raw = section("asn")
            result["asn"] = ASNWorker(
                events=self.events,
                publisher=self.event_bus,
                backend=AsnmapBackend(AsnmapConfig.model_validate(raw.get("backend", {}))),
                config=ASNWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("archives", {}).get("enabled") and "archives" not in disabled:
            raw = section("archives")
            result["archives"] = ArchivesWorker(
                events=self.events,
                publisher=self.event_bus,
                sources=(URLFinderSource(URLFinderConfig.model_validate(raw.get("backend", {}))),),
                config=ArchivesWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("crawler", {}).get("enabled") and "crawler" not in disabled:
            raw = section("crawler")
            result["crawler"] = CrawlerWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                backend=KatanaBackend(
                    KatanaConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=CrawlerWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("content", {}).get("enabled") and "content" not in disabled:
            raw = section("content")
            result["content"] = ContentWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                store=WorkspaceContentStore(content_root),
                backend=HttpxContentBackend(
                    HttpxContentConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=ContentWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("javascript", {}).get("enabled") and "javascript" not in disabled:
            raw = section("javascript")
            result["javascript"] = JavaScriptWorker(
                events=self.events,
                publisher=self.event_bus,
                content=FileJavaScriptContentProvider(content_root),
                config=JavaScriptAnalysisConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("parameters", {}).get("enabled") and "parameters" not in disabled:
            raw = section("parameters")
            result["parameters"] = ParametersWorker(
                events=self.events,
                publisher=self.event_bus,
                candidates=corpus,
                exploration_cursors=ParameterExplorationCursorStore(),
                rate_limiter=self.rate_limiter,
                backend=ArjunBackend(
                    ArjunConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=ParameterDiscoveryConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("vhost", {}).get("enabled") and "vhost" not in disabled:
            raw = section("vhost")
            result["vhost"] = VHostWorker(
                events=self.events,
                publisher=self.event_bus,
                candidates=WordlistVHostCandidateProvider(words=corpus),
                candidate_scope=ScopeEngineVHostCandidateScopeProvider(self.scope_engine),
                rate_limiter=self.rate_limiter,
                backend=HttpxVHostBackend(
                    HttpxVHostConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=VHostWorkerConfig.model_validate(raw.get("config", {})),
            )

        if (
            pipeline.workers.get("nuclei", {}).get("enabled")
            and "nuclei" not in disabled
            and nuclei_catalog is not None
        ):
            raw = section("nuclei")
            result["nuclei"] = NucleiWorker(
                events=self.events,
                publisher=self.event_bus,
                rate_limiter=self.rate_limiter,
                templates=nuclei_catalog,
                request_scope=ScopeEngineNucleiRequestScopeProvider(self.scope_engine),
                backend=NucleiBackend(
                    NucleiBackendConfig.model_validate(raw.get("backend", {})),
                    request_identity=request_identity,
                ),
                config=NucleiWorkerConfig.model_validate(raw.get("config", {})),
            )

        if pipeline.workers.get("mobile", {}).get("enabled") and "mobile" not in disabled:
            raw = section("mobile")
            mobile_config = MobileAnalysisConfig.model_validate(raw.get("config", {}))
            scanners: list[Any] = []
            if mobile_config.enable_gitleaks:
                scanners.append(GitleaksSecretScanner())
            if mobile_config.enable_trufflehog:
                scanners.append(TruffleHogSecretScanner())

            result["mobile"] = MobileWorker(
                events=self.events,
                publisher=self.event_bus,
                artifacts=WorkspaceMobileArtifactProvider(artifact_root),
                config=mobile_config,
                jadx=(JadxDecompiler() if mobile_config.enable_jadx else None),
                apktool=(ApktoolDecompiler() if mobile_config.enable_apktool_fallback else None),
                secret_scanners=tuple(scanners),
                sensitive_evidence=(
                    WorkspaceSensitiveEvidenceStore(sensitive_root)
                    if mobile_config.preserve_raw_secret_evidence
                    else None
                ),
            )

        if (
            pipeline.workers.get("fingerprints", {}).get("enabled")
            and "fingerprints" not in disabled
        ):
            raw = section("fingerprints")
            result["fingerprints"] = FingerprintWorker(
                events=self.events,
                publisher=self.event_bus,
                config=FingerprintWorkerConfig.model_validate(raw.get("config", {})),
            )

        return result

    async def close(self) -> None:
        await self.database.dispose()

    async def seed_domain(
        self,
        domain: str,
        *,
        seed_spec: DomainSeedSpec | None = None,
    ) -> Event:
        normalized = normalize_dns_name(domain)
        decision = self.scope_engine.evaluate(
            ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=normalized)
        )
        if decision.state not in {ScopeState.IN_SCOPE, ScopeState.PASSIVE_ONLY}:
            raise ValueError(
                f"seed {normalized!r} is {decision.state.value}; "
                "Night Scout only starts from IN_SCOPE or PASSIVE_ONLY discovery anchors"
            )

        mode = seed_spec.mode.value if seed_spec is not None else "EXPLICIT"
        source_rule_ids = (
            seed_spec.source_rule_ids if seed_spec is not None else decision.matched_rule_ids
        )
        event = Event(
            type=EventType.ROOT_DOMAIN,
            value=normalized,
            source="cli:seed",
            scope_state=decision.state,
            confidence=1.0,
            novelty=0.85,
            depth=0,
            tags={"seed", "root-domain", f"seed-mode:{mode.lower()}"},
            metadata={
                "target_key": normalized,
                "seed_domain": normalized,
                "seed_mode": mode,
                "seed_source_rule_ids": list(source_rule_ids),
                "scope_matched_rule_id": decision.matched_rule_id,
                "scope_tier": decision.tier,
            },
        )
        with self.event_bus.bind_branch(event.event_id):
            await self.event_bus.publish(event)
            if decision.state is ScopeState.IN_SCOPE:
                # ROOT_DOMAIN drives broad passive enumeration.  Exact listed
                # domains also need their own bounded active confirmation path,
                # so project the same hostname as an unconfirmed DNS_NAME.  The
                # DNS worker must confirm it before HTTP/TLS routes can run.
                await self.event_bus.publish(
                    Event(
                        type=EventType.DNS_NAME,
                        value=normalized,
                        source="cli:seed",
                        parent_event_id=event.event_id,
                        scope_state=decision.state,
                        confidence=1.0,
                        novelty=0.75,
                        depth=1,
                        tags={
                            "seed",
                            "hypothesis",
                            "exact-scope-seed",
                            "requires-dns-confirmation",
                        },
                        metadata={
                            "target_key": normalized,
                            "seed_domain": normalized,
                            "seed_mode": mode,
                            "scope_matched_rule_id": decision.matched_rule_id,
                        },
                    )
                )
        return event

    def plan_domain_seeds(
        self,
        domains: Sequence[str] = (),
    ) -> DomainSeedPlan:
        """Return the authorized domain frontier for explicit seeds or the scope."""

        return plan_domain_seeds(
            self.configuration.scope.rules,
            requested_domains=tuple(domains),
        )

    async def run_domains(
        self,
        domains: Sequence[str] = (),
        *,
        mobile_artifact: RuntimeMobileArtifactInput | None = None,
        max_steps: int | None = None,
        progress: RuntimeProgressCallback | None = None,
    ) -> RuntimeProgramRunSummary:
        """Run one program frontier from domain and optional local mobile seeds."""

        plan = self.plan_domain_seeds(domains)
        prepared_mobile = (
            self._prepare_mobile_ingress(mobile_artifact)
            if mobile_artifact is not None
            else None
        )
        if not plan.seeds and prepared_mobile is None:
            raise ValueError(
                "run has no seeds; add an IN_SCOPE DOMAIN rule, provide explicit "
                "authorized domains, or supply --mobile-artifact with --mobile-app-id"
            )
        return await self._run_seed_plan(
            plan,
            mobile_artifact=prepared_mobile,
            max_steps=max_steps,
            progress=progress,
        )

    def _prepare_mobile_ingress(
        self,
        mobile: RuntimeMobileArtifactInput,
    ) -> _PreparedMobileIngress:
        """Authorize and configure a mobile seed before touching its source file."""

        subject = ScopeSubject(kind=ScopeAssetKind.MOBILE_APP, value=mobile.app_id)
        decision = self.scope_engine.evaluate(subject)
        if decision.state not in {ScopeState.IN_SCOPE, ScopeState.PASSIVE_ONLY}:
            raise ValueError(
                f"mobile application {subject.value!r} is {decision.state.value}; "
                "add an explicit IN_SCOPE or PASSIVE_ONLY MOBILE_APP rule"
            )
        if "mobile" not in self.workers:
            raise RuntimeError("mobile worker is not enabled or available in this pipeline")

        enabled_rule_ids = {
            str(rule_id).strip()
            for rule_id in self.configuration.pipeline.routing.get("enabled_rule_ids", [])
            if str(rule_id).strip()
        }
        mobile_route_id = "mobile.analyze.local-artifact"
        if enabled_rule_ids and mobile_route_id not in enabled_rule_ids:
            raise RuntimeError(f"pipeline routing does not enable {mobile_route_id}")

        mobile_section = self.configuration.worker("mobile")
        mobile_config = MobileAnalysisConfig.model_validate(mobile_section.get("config", {}))
        return _PreparedMobileIngress(
            input=mobile,
            subject=subject,
            decision=decision,
            store=WorkspaceMobileArtifactStore(
                self._artifact_root,
                max_artifact_bytes=mobile_config.max_artifact_bytes,
            ),
        )

    async def _run_seed_plan(
        self,
        plan: DomainSeedPlan,
        *,
        mobile_artifact: _PreparedMobileIngress | None = None,
        max_steps: int | None = None,
        progress: RuntimeProgressCallback | None = None,
    ) -> RuntimeProgramRunSummary:
        seed_pairs: list[tuple[DomainSeedSpec, Event]] = []
        mobile_pair: tuple[ImportedMobileArtifact, Event] | None = None
        seed_summaries: list[RuntimeSeedSummary] = []

        async def initialize() -> None:
            nonlocal mobile_pair
            for seed_spec in plan.seeds:
                event = await self.seed_domain(seed_spec.domain, seed_spec=seed_spec)
                seed_pairs.append((seed_spec, event))

            if mobile_artifact is None:
                return

            imported = await mobile_artifact.store.import_file(
                mobile_artifact.input.artifact_path,
                kind=mobile_artifact.input.kind,
            )
            metadata: dict[str, Any] = {
                "target_key": mobile_artifact.subject.value,
                "app_id": mobile_artifact.subject.value,
                "artifact_ref": imported.artifact_ref,
                "artifact_kind": imported.kind.value,
                "artifact_sha256": imported.sha256,
                "artifact_size_bytes": imported.size_bytes,
                "scope_matched_rule_id": mobile_artifact.decision.matched_rule_id,
                "scope_tier": mobile_artifact.decision.tier,
                "network_request_performed": False,
            }
            if mobile_artifact.input.source_url is not None:
                metadata["source_url"] = mobile_artifact.input.source_url

            artifact_event = Event(
                type=EventType.MOBILE_ARTIFACT,
                value=(
                    f"{mobile_artifact.subject.value}@sha256:{imported.sha256}"
                ),
                source="cli:run:mobile-artifact",
                scope_state=mobile_artifact.decision.state,
                confidence=1.0,
                novelty=0.95,
                depth=0,
                tags={"seed", "local", "mobile", imported.kind.value.lower()},
                metadata=metadata,
            )
            with self.event_bus.bind_branch(artifact_event.event_id):
                published = await self.event_bus.publish(artifact_event)
            if not published:
                raise RuntimeError("mobile artifact event was not published")
            mobile_pair = (imported, artifact_event)

        async def finalize() -> None:
            for seed_spec, seed in seed_pairs:
                genome_fingerprint = await self._build_seed_genome(seed)
                seed_summaries.append(
                    RuntimeSeedSummary(
                        seed_event_id=seed.event_id,
                        target=seed.value,
                        scope_state=seed.scope_state,
                        mode=seed_spec.mode.value,
                        matched_rule_id=seed_spec.matched_rule_id,
                        source_rule_ids=seed_spec.source_rule_ids,
                        genome_fingerprint=genome_fingerprint,
                    )
                )

            if mobile_artifact is not None:
                assert mobile_pair is not None
                imported, seed = mobile_pair
                genome_fingerprint = await self._build_seed_genome(seed)
                seed_summaries.append(
                    RuntimeSeedSummary(
                        seed_event_id=seed.event_id,
                        target=mobile_artifact.subject.value,
                        scope_state=seed.scope_state,
                        mode="MOBILE_ARTIFACT",
                        matched_rule_id=mobile_artifact.decision.matched_rule_id,
                        source_rule_ids=mobile_artifact.decision.matched_rule_ids,
                        genome_fingerprint=genome_fingerprint,
                        artifact_ref=imported.artifact_ref,
                        artifact_kind=imported.kind.value,
                        artifact_sha256=imported.sha256,
                        artifact_size_bytes=imported.size_bytes,
                    )
                )

        targets = tuple(seed.domain for seed in plan.seeds) + (
            (mobile_artifact.subject.value,) if mobile_artifact is not None else ()
        )
        if plan.seeds and mobile_artifact is not None:
            run_kind = "mixed"
        elif mobile_artifact is not None:
            run_kind = "mobile-artifact"
        else:
            run_kind = "domain"
        frontier = await self._run_frontier(
            targets=targets,
            run_kind=run_kind,
            initialize=initialize,
            finalize=finalize,
            max_steps=max_steps,
            progress=progress,
        )
        status = frontier.status_snapshot
        return RuntimeProgramRunSummary(
            run_id=frontier.run_id,
            status=frontier.status,
            seeds=tuple(seed_summaries),
            steps=frontier.steps,
            outcomes=frontier.outcomes,
            stopped_idle=frontier.stopped_idle,
            max_steps_reached=frontier.max_steps_reached,
            paused_deferred=frontier.paused_deferred,
            next_resume_at=frontier.next_resume_at,
            task_counts=status.task_counts,
            attempt_counts=status.attempt_counts,
            event_count=status.event_count,
            asset_count=status.asset_count,
            open_review_cases=status.open_review_cases,
            warnings=tuple(dict.fromkeys((*plan.warnings, *self.warnings))),
        )

    async def _build_seed_genome(self, seed: Event) -> str | None:
        if not self.configuration.pipeline.runtime.build_genome_on_finish:
            return None
        try:
            genome, _report = await self.genome_builder.build(seed)
            await self.intelligence.genome_store.save(genome)
            return genome.fingerprint
        except Exception as exc:
            self.warnings.append(
                f"Target Genome build failed for {seed.value}: "
                f"{type(exc).__name__}: {exc}"
            )
            return None

    async def _run_frontier(
        self,
        *,
        targets: Sequence[str],
        run_kind: str,
        initialize: Callable[[], Awaitable[None]],
        finalize: Callable[[], Awaitable[None]] | None = None,
        max_steps: int | None = None,
        progress: RuntimeProgressCallback | None = None,
    ) -> _RuntimeFrontierResult:
        """Run any authorized ingress through the shared durable lifecycle."""

        if self._run_id is not None:
            raise RuntimeError("runtime already has an active run")

        if not self.configuration.pipeline.runtime.resume_frontier:
            active = [task for task in await self.task_store.all() if not task.is_terminal]
            if active:
                raise RuntimeError(
                    "resume_frontier=false requires an empty active frontier; "
                    f"workspace contains {len(active)} unfinished task(s). "
                    "Resume them with resume_frontier=true or use a fresh workspace."
                )
        else:
            await self._assert_resumed_frontier_request_identity()

        identity_fingerprint = self.request_identity.fingerprint
        effective_config_hash = hashlib.sha256(
            (
                f"{self.configuration.config_hash}\0"
                f"{identity_fingerprint or 'no-request-identity'}"
            ).encode()
        ).hexdigest()

        self._run_id = await self.runs.start(
            target_id=self.configuration.scope.target_id,
            config_hash=effective_config_hash,
            metadata={
                "targets": list(targets),
                "seed_count": len(targets),
                "run_kind": run_kind,
                "profile_id": self.configuration.pipeline.profile_id,
                "scope_target_id": self.configuration.scope.target_id,
                "request_identity_header_names": list(
                    self.request_identity.header_names
                ),
                "request_identity_fingerprint": identity_fingerprint,
            },
        )
        self.event_bus.set_run_id(self._run_id)
        self.task_store.set_run_id(self._run_id)
        self.attempt_observer.set_run_id(self._run_id)
        run_id = self._run_id
        limit = max_steps or self.configuration.pipeline.runtime.max_steps
        steps = 0

        try:
            await initialize()

            outcomes: Counter[str] = Counter()
            stopped_idle = False
            paused_deferred = False
            next_resume_at: datetime | None = None
            self._emit_progress(
                progress,
                RuntimeProgress(
                    run_id=run_id,
                    phase="STARTED",
                    max_steps=limit,
                ),
            )

            while steps < limit:
                current_step = steps + 1
                result = await self.lifecycle.run_once(
                    on_claimed=partial(
                        self._emit_claimed_progress,
                        callback=progress,
                        run_id=run_id,
                        step=current_step,
                        max_steps=limit,
                    ),
                )
                if result.outcome is LifecycleOutcome.IDLE:
                    next_ready_at = await self.task_store.next_ready_at()
                    if next_ready_at is None:
                        outcomes[result.outcome.value] += 1
                        stopped_idle = True
                        self._emit_lifecycle_progress(
                            progress,
                            run_id=run_id,
                            step=steps,
                            max_steps=limit,
                            result=result,
                        )
                        break

                    wait_seconds = max(
                        0.0,
                        (next_ready_at - utc_now()).total_seconds(),
                    )
                    max_wait = self.configuration.pipeline.runtime.max_deferred_wait_seconds
                    if wait_seconds > max_wait:
                        paused_deferred = True
                        next_resume_at = next_ready_at
                        self._emit_progress(
                            progress,
                            RuntimeProgress(
                                run_id=run_id,
                                phase="WAITING",
                                step=steps,
                                max_steps=limit,
                                wait_seconds=wait_seconds,
                                next_resume_at=next_ready_at,
                                reason=("deferred task exceeds this run's maximum wait"),
                            ),
                        )
                        break

                    self._emit_progress(
                        progress,
                        RuntimeProgress(
                            run_id=run_id,
                            phase="WAITING",
                            step=steps,
                            max_steps=limit,
                            wait_seconds=wait_seconds,
                            next_resume_at=next_ready_at,
                            reason="waiting for deferred task",
                        ),
                    )
                    await asyncio.sleep(wait_seconds)
                    continue

                outcomes[result.outcome.value] += 1
                steps += 1
                self._emit_lifecycle_progress(
                    progress,
                    run_id=run_id,
                    step=steps,
                    max_steps=limit,
                    result=result,
                )

            if finalize is not None:
                await finalize()

            max_steps_reached = steps >= limit and not stopped_idle
            if max_steps_reached and next_resume_at is None:
                next_resume_at = await self.task_store.next_ready_at()
            unfinished_frontier = any(not task.is_terminal for task in await self.task_store.all())
            if outcomes[LifecycleOutcome.FAILED.value] > 0:
                run_status = "FAILED"
            elif paused_deferred or next_resume_at is not None or unfinished_frontier:
                run_status = "PAUSED"
            else:
                run_status = "SUCCEEDED"
            await self.runs.finish(run_id, status=run_status)
            status = await self.status(run_id=run_id)

            self._emit_progress(
                progress,
                RuntimeProgress(
                    run_id=run_id,
                    phase="FINISHED",
                    step=steps,
                    max_steps=limit,
                    next_resume_at=next_resume_at,
                    run_status=run_status,
                ),
            )

            return _RuntimeFrontierResult(
                run_id=run_id,
                status=run_status,
                steps=steps,
                outcomes=dict(sorted(outcomes.items())),
                stopped_idle=stopped_idle,
                max_steps_reached=max_steps_reached,
                paused_deferred=paused_deferred,
                next_resume_at=next_resume_at,
                status_snapshot=status,
            )
        except BaseException as exc:
            self._emit_progress(
                progress,
                RuntimeProgress(
                    run_id=run_id,
                    phase="FAILED",
                    step=steps,
                    max_steps=limit,
                    reason=f"{type(exc).__name__}: {exc}",
                    run_status="FAILED",
                ),
            )
            with contextlib.suppress(Exception):
                await self.runs.finish(run_id, status="FAILED")
            raise
        finally:
            self.event_bus.set_run_id(None)
            self.task_store.set_run_id(None)
            self.attempt_observer.set_run_id(None)
            self._run_id = None

    async def _assert_resumed_frontier_request_identity(self) -> None:
        """Require the same CLI identity for unfinished work that originated with it."""

        terminal = tuple(status.value for status in TERMINAL_TASK_STATUSES)
        async with self.database.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(
                            ReconRunRecord.run_id,
                            ReconRunRecord.metadata_json,
                        )
                        .join(TaskRecord, TaskRecord.run_id == ReconRunRecord.run_id)
                        .where(TaskRecord.status.not_in(terminal))
                    )
                ).all()
            )

        required: dict[str, set[str]] = {}
        for _run_id, metadata in rows:
            fingerprint = metadata.get("request_identity_fingerprint")
            if not isinstance(fingerprint, str) or not fingerprint.strip():
                continue
            raw_names = metadata.get("request_identity_header_names", [])
            names_from_run = {
                str(name).strip()
                for name in raw_names
                if str(name).strip()
            } if isinstance(raw_names, list) else set()
            required.setdefault(fingerprint.strip(), set()).update(names_from_run)

        if not required:
            return

        current = self.request_identity.fingerprint
        if len(required) == 1 and current in required:
            return

        required_names = sorted({name for values in required.values() for name in values})
        configured = ", ".join(self.request_identity.header_names) or "none"
        raise RuntimeError(
            "unfinished frontier requires the same CLI identity header values "
            "used when its tasks were created; required headers="
            f"{','.join(required_names) or 'unknown'}; "
            f"currently configured headers={configured}. Repeat the original "
            "--identity-header options. Values and fingerprints are not displayed."
        )

    async def run_domain(
        self,
        domain: str,
        *,
        max_steps: int | None = None,
        progress: RuntimeProgressCallback | None = None,
    ) -> RuntimeRunSummary:
        """Backward-compatible single-domain wrapper over the program runner."""

        program = await self.run_domains(
            (domain,),
            max_steps=max_steps,
            progress=progress,
        )
        seed = program.seeds[0]
        return RuntimeRunSummary(
            run_id=program.run_id,
            status=program.status,
            seed_event_id=seed.seed_event_id,
            target=seed.target,
            scope_state=seed.scope_state,
            steps=program.steps,
            outcomes=program.outcomes,
            stopped_idle=program.stopped_idle,
            max_steps_reached=program.max_steps_reached,
            paused_deferred=program.paused_deferred,
            next_resume_at=program.next_resume_at,
            task_counts=program.task_counts,
            attempt_counts=program.attempt_counts,
            event_count=program.event_count,
            asset_count=program.asset_count,
            open_review_cases=program.open_review_cases,
            genome_fingerprint=seed.genome_fingerprint,
            warnings=program.warnings,
        )

    def _emit_progress(
        self,
        callback: RuntimeProgressCallback | None,
        item: RuntimeProgress,
    ) -> None:
        if callback is None:
            return
        try:
            callback(item)
        except Exception as exc:
            self.warnings.append(f"progress callback failed: {type(exc).__name__}: {exc}")

    def _emit_lifecycle_progress(
        self,
        callback: RuntimeProgressCallback | None,
        *,
        run_id: str,
        step: int,
        max_steps: int,
        result: LifecycleResult,
    ) -> None:
        self._emit_progress(
            callback,
            RuntimeProgress(
                run_id=run_id,
                phase="STEP",
                step=step,
                max_steps=max_steps,
                outcome=result.outcome,
                task_id=result.task_id,
                worker=result.worker,
                action=result.action,
                reason=result.reason,
                queue_status=result.queue_status,
            ),
        )

    def _emit_claimed_progress(
        self,
        task: Task,
        *,
        callback: RuntimeProgressCallback | None,
        run_id: str,
        step: int,
        max_steps: int,
    ) -> None:
        self._emit_progress(
            callback,
            RuntimeProgress(
                run_id=run_id,
                phase="EXECUTING",
                step=step,
                max_steps=max_steps,
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                queue_status=task.status,
            ),
        )

    async def status(self, *, run_id: str | None = None) -> RuntimeStatus:
        """Return global workspace status or a run-attributed summary."""
        async with self.database.session() as session:
            if run_id is None:
                tasks = await self.task_store.all()
                task_counts = Counter(task.status.value for task in tasks)
                open_review_count = len(await self.review_store.open_cases())
                event_filter: tuple[Any, ...] = ()
            else:
                task_run_filter = or_(
                    TaskRecord.run_id == run_id,
                    TaskRecord.execution_run_id == run_id,
                    TaskRecord.task_id.in_(
                        select(TaskAttemptRecord.task_id).where(TaskAttemptRecord.run_id == run_id)
                    ),
                )
                task_rows = list(
                    (
                        await session.execute(
                            select(TaskRecord.status, func.count(TaskRecord.task_id))
                            .where(task_run_filter)
                            .group_by(TaskRecord.status)
                        )
                    ).all()
                )
                task_counts = Counter({str(status): int(count) for status, count in task_rows})
                open_review_count = int(
                    await session.scalar(
                        select(func.count(ReviewCaseRecord.case_id))
                        .join(
                            TaskRecord,
                            TaskRecord.task_id == ReviewCaseRecord.task_id,
                        )
                        .where(
                            ReviewCaseRecord.state == "OPEN",
                            task_run_filter,
                        )
                    )
                    or 0
                )
                event_filter = (EventObservationRecord.run_id == run_id,)

            attempt_conditions = (TaskAttemptRecord.run_id == run_id,) if run_id is not None else ()
            attempt_rows = list(
                (
                    await session.execute(
                        select(
                            TaskAttemptRecord.outcome,
                            func.count(TaskAttemptRecord.attempt_id),
                        )
                        .where(
                            TaskAttemptRecord.outcome.is_not(None),
                            *attempt_conditions,
                        )
                        .group_by(TaskAttemptRecord.outcome)
                    )
                ).all()
            )
            attempt_counts = {
                str(outcome): int(count) for outcome, count in attempt_rows if outcome is not None
            }

            event_count = int(
                await session.scalar(
                    select(func.count(EventObservationRecord.event_id)).where(*event_filter)
                )
                or 0
            )
            asset_statement = (
                select(func.count(AssetRecord.asset_id))
                if run_id is None
                else select(func.count(func.distinct(EventObservationRecord.asset_id))).where(
                    *event_filter
                )
            )
            asset_count = int(await session.scalar(asset_statement) or 0)
            run_rows = list(
                (
                    await session.execute(
                        select(ReconRunRecord.status, func.count(ReconRunRecord.run_id)).group_by(
                            ReconRunRecord.status
                        )
                    )
                ).all()
            )

        return RuntimeStatus(
            target_id=self.configuration.scope.target_id,
            workspace_root=str(self.configuration.workspace_root),
            database_path=str(self.database.config.path),
            event_count=event_count,
            asset_count=asset_count,
            task_counts=dict(sorted(task_counts.items())),
            attempt_counts=dict(sorted(attempt_counts.items())),
            open_review_cases=open_review_count,
            run_counts={str(status): int(count) for status, count in run_rows},
            warnings=tuple(dict.fromkeys(self.warnings)),
        )

    async def list_review_cases(self) -> tuple[ReviewCase, ...]:
        return tuple(await self.review_store.open_cases())

    async def review_case_details(self, case_id: str) -> dict[str, Any] | None:
        review_case = await self.review_store.get(case_id.strip())
        if review_case is None:
            return None
        task = await self.queue.get(review_case.task_id)
        return {
            "case": review_case.model_dump(mode="json"),
            "task": task.model_dump(mode="json") if task is not None else None,
        }

    async def approve_review_case(
        self,
        case_id: str,
        *,
        reason: str | None = None,
    ) -> ReviewCase:
        existing = await self.review_store.get(case_id.strip())
        if existing is None:
            raise KeyError(f"unknown review case: {case_id.strip()}")
        task = await self.queue.get(existing.task_id)
        if task is None:
            raise KeyError(f"review task no longer exists: {existing.task_id}")
        if task.status not in {
            TaskStatus.REVIEW,
            TaskStatus.PENDING,
            TaskStatus.DEFERRED,
        }:
            raise ValueError(f"review task cannot be approved from state {task.status.value}")

        review_case = await self._resolve_review_case(
            case_id,
            state=ReviewCaseState.APPROVED,
            reason=reason,
        )
        if task.status is TaskStatus.REVIEW:
            await self.queue.release_review(task.task_id)
        await self.decisions.record_policy(
            task_id=task.task_id,
            gate="human_review_resolution",
            outcome=ReviewCaseState.APPROVED.value,
            reason=reason,
            details={"case_id": review_case.case_id},
        )
        return review_case

    async def reject_review_case(
        self,
        case_id: str,
        *,
        reason: str | None = None,
    ) -> ReviewCase:
        existing = await self.review_store.get(case_id.strip())
        if existing is None:
            raise KeyError(f"unknown review case: {case_id.strip()}")
        task = await self.queue.get(existing.task_id)
        if task is None:
            raise KeyError(f"review task no longer exists: {existing.task_id}")

        review_case = await self._resolve_review_case(
            case_id,
            state=ReviewCaseState.BLOCKED,
            reason=reason,
        )
        if not task.is_terminal:
            await self.queue.block(
                task.task_id,
                reason=reason or f"rejected by review case {review_case.case_id}",
            )
        await self.decisions.record_policy(
            task_id=task.task_id,
            gate="human_review_resolution",
            outcome=ReviewCaseState.BLOCKED.value,
            reason=reason,
            details={"case_id": review_case.case_id},
        )
        return review_case

    async def _resolve_review_case(
        self,
        case_id: str,
        *,
        state: ReviewCaseState,
        reason: str | None,
    ) -> ReviewCase:
        normalized = case_id.strip()
        if not normalized:
            raise ValueError("review case id must not be blank")
        existing = await self.review_store.get(normalized)
        if existing is None:
            raise KeyError(f"unknown review case: {normalized}")
        if existing.state is state:
            return existing
        if existing.state is not ReviewCaseState.OPEN:
            raise ValueError(f"review case {normalized} is already {existing.state.value}")
        return await self.review_store.resolve(
            normalized,
            state=state,
            reason=reason,
        )

    async def all_events(self) -> tuple[Event, ...]:
        async with self.database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).order_by(
                            EventObservationRecord.first_seen,
                            EventObservationRecord.event_id,
                        )
                    )
                ).all()
            )

        return tuple(event_from_storage_record(record) for record in records)

    async def explain(self, query: str, *, max_depth: int = 8) -> dict[str, Any] | None:
        normalized = query.strip()
        if not normalized:
            raise ValueError("explain query must not be blank")

        async with self.database.session() as session:
            record = await session.get(EventObservationRecord, normalized)
            if record is None:
                record = await session.scalar(
                    select(EventObservationRecord)
                    .where(EventObservationRecord.value == normalized)
                    .order_by(
                        EventObservationRecord.last_seen.desc(),
                        EventObservationRecord.event_id.desc(),
                    )
                    .limit(1)
                )

        if record is None:
            return None

        event = event_from_storage_record(record)
        trace = await self.provenance.ancestors(event.event_id, max_depth=max_depth)

        async with self.database.session() as session:
            task_rows = list(
                (
                    await session.scalars(
                        select(TaskRecord)
                        .where(TaskRecord.input_event_id == event.event_id)
                        .order_by(TaskRecord.created_at, TaskRecord.task_id)
                    )
                ).all()
            )

            task_ids = [row.task_id for row in task_rows]
            decisions: list[SchedulerDecisionRecord] = []
            if task_ids:
                decisions = list(
                    (
                        await session.scalars(
                            select(SchedulerDecisionRecord)
                            .where(SchedulerDecisionRecord.task_id.in_(task_ids))
                            .order_by(
                                SchedulerDecisionRecord.evaluated_at,
                                SchedulerDecisionRecord.decision_id,
                            )
                        )
                    ).all()
                )

        return {
            "event": event.model_dump(mode="json"),
            "provenance": trace.model_dump(mode="json"),
            "tasks": [
                {
                    "task_id": row.task_id,
                    "worker": row.worker,
                    "action": row.action,
                    "status": row.status,
                    "route_rule_id": row.route_rule_id,
                    "routing_reason": row.routing_reason,
                    "attempts": row.attempts,
                    "last_error": row.last_error,
                }
                for row in task_rows
            ],
            "scheduler_decisions": [
                {
                    "task_id": row.task_id,
                    "evaluated_at": row.evaluated_at.isoformat(),
                    "score": row.score,
                    "selected": row.selected,
                    "breakdown": row.breakdown_json,
                    "signals": row.signals_json,
                }
                for row in decisions
            ],
        }

    async def export(
        self,
        *,
        format: str,
        mode: ExportMode,
        confirm_sensitive: bool,
        output: Path | None = None,
    ) -> tuple[Path, ...]:
        events = await self.all_events()
        provider = WorkspaceSensitiveEvidenceProvider(self._sensitive_root)
        fmt = format.strip().lower()

        if fmt == "jsonl":
            destination = output or self.configuration.resolve(
                self.configuration.pipeline.exports.get("jsonl", {}).get(
                    "path", "exports/nightscout.jsonl"
                )
            )
            return (
                await export_jsonl(
                    events,
                    destination,
                    options=JsonlExportOptions(
                        mode=mode,
                        confirm_sensitive_export=confirm_sensitive,
                    ),
                    sensitive_provider=provider,
                ),
            )

        if fmt == "text":
            destination = output or self.configuration.resolve(
                self.configuration.pipeline.exports.get("text", {}).get("directory", "exports/text")
            )
            return await export_text_bundle(
                events,
                destination,
                options=TextExportOptions(
                    mode=mode,
                    confirm_sensitive_export=confirm_sensitive,
                ),
                sensitive_provider=provider,
            )

        if fmt == "csv":
            destination = output or self.configuration.resolve(
                self.configuration.pipeline.exports.get("csv", {}).get("directory", "exports/csv")
            )
            return await export_csv_bundle(
                events,
                destination,
                options=CsvExportOptions(
                    mode=mode,
                    confirm_sensitive_export=confirm_sensitive,
                ),
                sensitive_provider=provider,
            )

        raise ValueError("format must be jsonl, text, or csv")


async def build_runtime(
    *,
    pipeline_path: str | Path,
    scope_path: str | Path | None = None,
    request_identity: RequestIdentityPolicy | None = None,
) -> NightScoutRuntime:
    # Night Scout intentionally supports only Debian GNU/Linux and Kali Linux.
    # Managed specialist binaries are isolated under the Night Scout tool root
    # and are prepended to PATH before any worker subprocess is constructed.
    assert_supported_platform()
    with contextlib.suppress(Exception):
        activate_managed_tool_path()
    return await NightScoutRuntime.build(
        pipeline_path=pipeline_path,
        scope_path=scope_path,
        request_identity=request_identity,
    )


def load_runtime_configuration(
    *,
    pipeline_path: str | Path,
    scope_path: str | Path | None = None,
) -> LoadedRuntimeConfiguration:
    pipeline_file = Path(pipeline_path).expanduser().resolve()
    if not pipeline_file.is_file():
        raise FileNotFoundError(f"pipeline config not found: {pipeline_file}")
    if ".example." in pipeline_file.name.lower():
        raise ValueError(
            "example pipeline is a template, not an operational config; "
            "run nightscout setup or copy and explicitly configure it"
        )

    project_root = discover_project_root(pipeline_file)
    raw_pipeline = load_yaml_mapping(pipeline_file)
    pipeline = PipelineDocument.model_validate(raw_pipeline)

    if scope_path is not None:
        scope_file = Path(scope_path).expanduser().resolve()
    elif pipeline.scope_file:
        configured_scope = Path(pipeline.scope_file).expanduser()
        if configured_scope.is_absolute():
            scope_file = configured_scope.resolve()
        else:
            # User pipeline files own their scope policy. Resource references
            # (wordlists/templates) still resolve against project_root.
            local_scope = (pipeline_file.parent / configured_scope).resolve()
            scope_file = (
                local_scope
                if local_scope.is_file()
                else resolve_project_path(project_root, configured_scope)
            )
    else:
        raise ValueError("scope config is required: set pipeline.scope_file or pass --scope")

    if not scope_file.is_file():
        raise FileNotFoundError(f"scope config not found: {scope_file}")
    if ".example." in scope_file.name.lower():
        raise ValueError(
            "example scope is a template, not an authorization policy; "
            "copy it to a non-example path and review every rule"
        )

    raw_scope = load_yaml_mapping(scope_file)
    scope = ScopeDocument.model_validate(raw_scope)

    digest = hashlib.sha256()
    digest.update(pipeline_file.read_bytes())
    digest.update(b"\0")
    digest.update(scope_file.read_bytes())

    workspace_override = os.environ.get("NIGHTSCOUT_WORKSPACE_ROOT", "").strip()
    if workspace_override:
        workspace_root = Path(workspace_override).expanduser().resolve()
    else:
        if is_standalone_bundle():
            workspace_base_root = user_paths().data_root.resolve()
        else:
            paths = user_paths()
            try:
                pipeline_file.relative_to(paths.config_root.resolve())
            except ValueError:
                workspace_base_root = project_root
            else:
                workspace_base_root = paths.data_root.resolve()
        workspace_root = _target_workspace_root(
            base_root=workspace_base_root,
            target_id=scope.target_id,
            pipeline=pipeline,
        )

    return LoadedRuntimeConfiguration(
        project_root=project_root,
        workspace_root=workspace_root,
        pipeline_path=pipeline_file,
        scope_path=scope_file,
        pipeline=pipeline,
        scope=scope,
        config_hash=digest.hexdigest(),
    )


def runtime_database_config(configuration: LoadedRuntimeConfiguration) -> DatabaseConfig:
    """Resolve the database inside the selected single-target workspace."""

    database_data = dict(configuration.pipeline.storage.get("database", {}))
    database_data["path"] = configuration.resolve(database_data["path"])
    return DatabaseConfig.model_validate(database_data)


def _target_workspace_root(
    *,
    base_root: Path,
    target_id: str,
    pipeline: PipelineDocument,
) -> Path:
    """Select a target directory while retaining attributable flat workspaces."""

    target_root = base_root / "workspaces" / workspace_directory_name(target_id)
    database_value = Path(str(pipeline.storage.get("database", {}).get("path", ""))).expanduser()
    if database_value.is_absolute():
        return target_root.resolve()

    target_database = (target_root / database_value).resolve()
    if target_database.is_file():
        return target_root.resolve()

    legacy_database = (base_root / database_value).resolve()
    if legacy_database.is_file():
        recorded = recorded_workspace_target_ids(legacy_database)
        # An unattributed legacy DB is selected so runtime can fail closed and
        # direct the operator to the explicit adoption command. A mixed DB is
        # also selected so binding rejects it visibly. A legacy DB attributed
        # to one different target does not block creation of this target's DB.
        if not recorded or recorded == {target_id} or len(recorded) > 1:
            return base_root.resolve()

    return target_root.resolve()


def all_runtime_route_rules() -> tuple[RouteRule, ...]:
    rules: list[RouteRule] = []
    factories = (
        passive_domain_route_rules,
        dns_route_rules,
        permutation_route_rules,
        http_route_rules,
        tls_route_rules,
        asn_route_rules,
        archive_route_rules,
        crawler_route_rules,
        content_route_rules,
        javascript_route_rules,
        parameter_route_rules,
        vhost_route_rules,
        mobile_route_rules,
        fingerprint_route_rules,
        nuclei_route_rules,
    )
    for factory in factories:
        rules.extend(factory())
    return tuple(rules)


def scope_subject_from_event(event: Event) -> ScopeSubject | None:
    """Return a direct scope subject without inferring ownership relationships."""

    if event.type in {EventType.ROOT_DOMAIN, EventType.DNS_NAME, EventType.CERT_SAN}:
        value = event.value[2:] if event.value.startswith("*.") else event.value
        try:
            return ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=value)
        except ValueError:
            return None

    if event.type is EventType.IP_ADDRESS:
        try:
            return ScopeSubject(kind=ScopeAssetKind.IP_ADDRESS, value=event.value)
        except ValueError:
            return None

    if event.type is EventType.CIDR:
        try:
            return ScopeSubject(kind=ScopeAssetKind.CIDR, value=event.value)
        except ValueError:
            return None

    url: str | None = None
    if event.type in {
        EventType.URL,
        EventType.API_ENDPOINT,
        EventType.JAVASCRIPT,
        EventType.HTTP_SERVICE,
    }:
        url = event.value
    elif event.type in {
        EventType.HTTP_RESPONSE,
        EventType.FAVICON,
        EventType.TECHNOLOGY,
        EventType.VULNERABILITY_CANDIDATE,
        EventType.VULNERABILITY_FINDING,
    }:
        for key in ("target_url", "url", "observed_on"):
            candidate = event.metadata.get(key)
            if isinstance(candidate, str) and candidate.startswith(("http://", "https://")):
                url = candidate
                break

    if url is not None:
        try:
            return ScopeSubject(kind=ScopeAssetKind.URL, value=url)
        except ValueError:
            return None

    if event.type is EventType.CERTIFICATE:
        host = event.metadata.get("hostname")
        if isinstance(host, str) and host.strip():
            try:
                return ScopeSubject(kind=ScopeAssetKind.DOMAIN, value=host)
            except ValueError:
                return None

    if event.type is EventType.MOBILE_ARTIFACT:
        for key in ("app_id", "package_name", "bundle_id", "application_id"):
            candidate = event.metadata.get(key)
            if isinstance(candidate, str) and candidate.strip():
                try:
                    return ScopeSubject(kind=ScopeAssetKind.MOBILE_APP, value=candidate)
                except ValueError:
                    return None

    return None


def task_budget_lane(task: Task) -> BudgetLane:
    return (
        BudgetLane.EXPLORATION
        if is_exploration_work(
            task.action,
            task.route_rule_id,
            task.routing_reason,
        )
        else BudgetLane.NORMAL
    )


def is_exploration_work(*descriptors: str | None) -> bool:
    material = " ".join(value for value in descriptors if value).lower()
    return "exploration" in material


def event_from_storage_record(record: EventObservationRecord) -> Event:
    return Event(
        event_id=record.event_id,
        type=EventType(record.event_type),
        value=record.value,
        source=record.source,
        parent_event_id=record.parent_event_id,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        scope_state=ScopeState(record.scope_state),
        confidence=record.confidence,
        novelty=record.novelty,
        depth=record.depth,
        tags=set(record.tags_json),
        metadata=dict(record.metadata_json),
    )


def _safe_evidence_fingerprint(event: Event) -> str:
    raw = event.metadata.get("evidence_fingerprint")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    material = f"{event.event_id}|{event.type.value}|{event.source}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def doctor_from_files(
    *,
    pipeline_path: str | Path,
    scope_path: str | Path | None = None,
    request_identity: RequestIdentityPolicy | None = None,
) -> DoctorReport:
    """Validate config and external dependency availability without opening DB."""

    checks: list[DoctorCheck] = []
    try:
        cfg = load_runtime_configuration(
            pipeline_path=pipeline_path,
            scope_path=scope_path,
        )
    except Exception as exc:
        return DoctorReport(
            pipeline_path=str(Path(pipeline_path).expanduser()),
            scope_path=(str(scope_path) if scope_path is not None else None),
            checks=(
                DoctorCheck(
                    name="configuration",
                    ok=False,
                    required=True,
                    detail=f"{type(exc).__name__}: {exc}",
                ),
            ),
        )

    checks.append(
        DoctorCheck(
            name="configuration",
            ok=True,
            detail=(
                f"pipeline={cfg.pipeline_path}; scope={cfg.scope_path}; "
                f"scope_rules={len(cfg.scope.rules)}"
            ),
        )
    )

    identity = request_identity or RequestIdentityPolicy()
    identity_workers = tuple(
        sorted(
            worker
            for worker in TARGET_HTTP_IDENTITY_WORKERS
            if cfg.worker_enabled(worker)
        )
    )
    if identity.configured:
        checks.append(
            DoctorCheck(
                name="request-identity",
                ok=True,
                required=True,
                detail=(
                    "configured; values=redacted; headers="
                    f"{','.join(identity.header_names)}; target_http_workers="
                    f"{','.join(identity_workers) or 'none enabled'}"
                ),
            )
        )
    else:
        checks.append(
            DoctorCheck(
                name="request-identity",
                ok=False,
                required=False,
                detail=(
                    "not configured; target HTTP requests are untagged. Add "
                    "--identity-header when the program requires researcher "
                    "identification"
                ),
            )
        )

    try:
        import aiosqlite  # noqa: F401

        aiosqlite_ok = True
    except Exception:
        aiosqlite_ok = False
    checks.append(
        DoctorCheck(
            name="python:aiosqlite",
            ok=aiosqlite_ok,
            required=True,
            detail="installed" if aiosqlite_ok else "missing; install project dependencies",
        )
    )

    platform_info = detect_platform()
    platform_ok = platform_info.supported
    checks.append(
        DoctorCheck(
            name="platform",
            ok=platform_ok,
            required=True,
            detail=(
                f"{platform_info.pretty_name}; arch={platform_info.architecture}"
                if platform_ok
                else (
                    "unsupported platform; Night Scout supports only Debian GNU/Linux "
                    "and Kali Linux on x86_64/aarch64; detected "
                    f"{platform_info.pretty_name} / {platform_info.architecture}"
                )
            ),
        )
    )

    try:
        tools_manifest = load_tools_manifest()
    except Exception as exc:
        tools_manifest = None
        checks.append(
            DoctorCheck(
                name="tools:manifest",
                ok=False,
                required=True,
                detail=f"{type(exc).__name__}: {exc}",
            )
        )
    else:
        assert tools_manifest is not None
        activate_managed_tool_path(tools_manifest)
        checks.append(
            DoctorCheck(
                name="tools:manifest",
                ok=True,
                required=True,
                detail=f"loaded {len(tools_manifest.tools)} tool definitions",
            )
        )

        checked_ids: set[str] = set()
        for spec in tools_manifest.tools:
            enabled_workers = tuple(worker for worker in spec.workers if cfg.worker_enabled(worker))
            if spec.tool_id == "pdtm":
                # PDTM is an installer dependency, not a runtime dependency once
                # the ProjectDiscovery binaries are present.
                should_check = True
                required = False
            elif enabled_workers:
                should_check = True
                required = spec.requirement is ToolRequirement.REQUIRED or any(
                    worker != "mobile" for worker in enabled_workers
                )
            else:
                should_check = False
                required = False

            if not should_check or spec.tool_id in checked_ids:
                continue
            checked_ids.add(spec.tool_id)

            # Mobile enhancements remain optional according to the worker config.
            if enabled_workers == ("mobile",):
                mobile = cfg.worker("mobile").get("config", {})
                feature_map = {
                    "jadx": "enable_jadx",
                    "apktool": "enable_apktool_fallback",
                    "gitleaks": "enable_gitleaks",
                    "trufflehog": "enable_trufflehog",
                }
                flag = feature_map.get(spec.tool_id)
                if flag and not mobile.get(flag, True):
                    continue
                required = False

            status = probe_tool(spec, tools_manifest)
            ok = status.installed and status.identity_ok
            checks.append(
                DoctorCheck(
                    name=f"tool:{spec.tool_id}",
                    ok=ok,
                    required=required,
                    detail=(f"{status.path}; {status.detail}" if status.path else status.detail),
                )
            )

    wordlist_raw = cfg.pipeline.intelligence.get("wordlists", {})
    manifest = cfg.resolve_resource(wordlist_raw.get("manifest", "wordlists/manifest.yaml"))
    checks.append(
        DoctorCheck(
            name="wordlists:manifest",
            ok=manifest.is_file(),
            required=False,
            detail=(
                str(manifest)
                if manifest.is_file()
                else f"missing; target-only corpus still works: {manifest}"
            ),
        )
    )

    if cfg.worker_enabled("nuclei"):
        templates = cfg.worker("nuclei").get("templates", {})
        manifest = cfg.resolve_resource(templates.get("manifest", "configs/nuclei-templates.yaml"))
        example = manifest.with_name(manifest.name.replace(".yaml", ".example.yaml"))
        ok = manifest.is_file() or example.is_file()
        checks.append(
            DoctorCheck(
                name="nuclei:audited-manifest",
                ok=ok,
                required=True,
                detail=(
                    str(manifest)
                    if manifest.is_file()
                    else (
                        f"using example/empty manifest: {example}"
                        if example.is_file()
                        else f"missing: {manifest}"
                    )
                ),
            )
        )

    return DoctorReport(
        pipeline_path=str(cfg.pipeline_path),
        scope_path=str(cfg.scope_path),
        checks=tuple(checks),
    )
