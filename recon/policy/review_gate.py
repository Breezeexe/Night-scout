"""Human-review gate for Night Scout.

Night Scout should automate reconnaissance aggressively where policy is clear,
but stop before crossing boundaries that require human judgment.

This module handles *review signals*, not ordinary novelty.

Important distinction:

    New endpoint discovered in JavaScript
        -> store it
        -> feed vocabulary / Target Genome
        -> continue normal safe recon

    New endpoint + possible secret/private-data/auth-boundary signal
        -> preserve the discovery
        -> open a review case
        -> pause the risky follow-up task

Review therefore never means "delete the finding". It means "preserve the
finding, but require a human decision before this particular follow-up action".

The future event/storage layer can implement ReviewSignalProvider by examining
the task's input Event, provenance, artifact metadata, confidence signals, and
policy decisions without coupling this module to SQLite.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timezone
from enum import IntEnum, StrEnum
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.lifecycle import GateDecision, GateOutcome
from recon.core.queue import Task
from recon.core.scheduler import ScheduleDecision


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def new_review_case_id() -> str:
    """Create a unique human-review case identifier."""
    return f"rev_{uuid4().hex}"


class ReviewCategory(StrEnum):
    """Categories that may require human judgment before follow-up."""

    POSSIBLE_SECRET = "POSSIBLE_SECRET"
    PRIVATE_DATA = "PRIVATE_DATA"
    AUTH_BOUNDARY = "AUTH_BOUNDARY"

    SCOPE_AMBIGUITY = "SCOPE_AMBIGUITY"
    POLICY_AMBIGUITY = "POLICY_AMBIGUITY"

    HIGH_IMPACT_SURFACE = "HIGH_IMPACT_SURFACE"
    SENSITIVE_ARTIFACT = "SENSITIVE_ARTIFACT"

    UNKNOWN_SENSITIVE_CONTENT = "UNKNOWN_SENSITIVE_CONTENT"


class ReviewSeverity(IntEnum):
    """Relative importance of a review signal."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class ReviewCaseState(StrEnum):
    """Persistent lifecycle of one review case."""

    OPEN = "OPEN"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    DISMISSED = "DISMISSED"


class ReviewSignal(BaseModel):
    """Safe metadata describing why a task may need human review.

    `summary` must not contain raw credentials, tokens, private records, or
    other sensitive values. Providers should redact those values and may use
    `evidence_fingerprint` to correlate repeated detections safely.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: ReviewCategory
    severity: ReviewSeverity = ReviewSeverity.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    summary: str

    source_event_id: str | None = None
    evidence_fingerprint: str | None = None

    tags: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("summary")
    @classmethod
    def normalize_summary(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("review signal summary must not be blank")
        return normalized

    @field_validator("source_event_id", "evidence_fingerprint")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: frozenset[str]) -> frozenset[str]:
        return frozenset(
            tag.strip().lower()
            for tag in value
            if tag.strip()
        )

    @property
    def stable_fingerprint(self) -> str:
        """Return a safe deterministic fingerprint for case deduplication."""
        if self.evidence_fingerprint is not None:
            return self.evidence_fingerprint

        material = "|".join(
            (
                self.category.value,
                self.source_event_id or "",
                self.summary,
                ",".join(sorted(self.tags)),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ReviewPolicy(BaseModel):
    """Configuration controlling which signals actually pause automation.

    By default every category is reviewable, but a minimum confidence of 0.50
    prevents extremely weak heuristic signals from stopping the pipeline.

    A category can have its own threshold. Lowering thresholds should be done
    deliberately because false-positive review queues can become unusable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    review_categories: frozenset[ReviewCategory] = Field(
        default_factory=lambda: frozenset(ReviewCategory)
    )

    minimum_confidence: float = Field(default=0.50, ge=0.0, le=1.0)

    category_minimum_confidence: dict[ReviewCategory, float] = Field(
        default_factory=dict
    )

    minimum_severity: ReviewSeverity = ReviewSeverity.MEDIUM

    @field_validator("category_minimum_confidence")
    @classmethod
    def validate_category_thresholds(
        cls,
        value: dict[ReviewCategory, float],
    ) -> dict[ReviewCategory, float]:
        for category, threshold in value.items():
            if not 0.0 <= threshold <= 1.0:
                raise ValueError(
                    f"confidence threshold for {category.value} must be 0..1"
                )
        return value

    def requires_review(self, signal: ReviewSignal) -> bool:
        """Return whether one signal meets configured review criteria."""
        if signal.category not in self.review_categories:
            return False

        if signal.severity < self.minimum_severity:
            return False

        threshold = self.category_minimum_confidence.get(
            signal.category,
            self.minimum_confidence,
        )
        return signal.confidence >= threshold


class ReviewCase(BaseModel):
    """Persistable human-review case.

    Only redacted summaries/fingerprints are stored here. Raw sensitive
    evidence belongs in the future evidence store with stricter handling.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(default_factory=new_review_case_id)

    task_id: str
    worker: str
    action: str
    input_event_id: str

    signal_fingerprints: tuple[str, ...]
    categories: tuple[ReviewCategory, ...]

    summaries: tuple[str, ...]

    state: ReviewCaseState = ReviewCaseState.OPEN

    opened_at: datetime = Field(default_factory=utc_now)
    resolved_at: datetime | None = None

    resolution_reason: str | None = None

    @field_validator("opened_at", "resolved_at")
    @classmethod
    def timestamps_must_be_aware(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ValueError("review timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_case_state(self) -> ReviewCase:
        if not self.signal_fingerprints:
            raise ValueError(
                "review case requires at least one signal fingerprint"
            )

        if not self.categories:
            raise ValueError(
                "review case requires at least one category"
            )

        if self.state is ReviewCaseState.OPEN:
            if self.resolved_at is not None:
                raise ValueError(
                    "OPEN review cases cannot have resolved_at"
                )
        elif self.resolved_at is None:
            raise ValueError(
                "resolved review cases require resolved_at"
            )

        return self


class ReviewEvaluation(BaseModel):
    """Explainable result before conversion into Lifecycle GateDecision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: GateOutcome
    task_id: str

    triggering_signals: tuple[ReviewSignal, ...] = ()
    ignored_signals: tuple[ReviewSignal, ...] = ()

    case_id: str | None = None
    reason: str


class ReviewSignalProvider(Protocol):
    """Produce review signals from persisted task/event/provenance context."""

    async def signals_for(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> tuple[ReviewSignal, ...]:
        """Return redacted review signals relevant to this follow-up task."""
        ...


class ReviewCaseStore(Protocol):
    """Persistence contract for the human-review queue."""

    async def open_or_get(
        self,
        *,
        task: Task,
        signals: tuple[ReviewSignal, ...],
    ) -> ReviewCase:
        """Open or return an equivalent still-open case."""
        ...

    async def get(self, case_id: str) -> ReviewCase | None:
        """Return one review case."""
        ...

    async def open_cases(self) -> list[ReviewCase]:
        """Return current human-review backlog."""
        ...

    async def approved_for_task(
        self,
        task_id: str,
        *,
        signal_fingerprints: tuple[str, ...] | None = None,
    ) -> ReviewCase | None:
        """Return an approval that authorizes this exact queued task."""
        ...

    async def resolve(
        self,
        case_id: str,
        *,
        state: ReviewCaseState,
        reason: str | None = None,
    ) -> ReviewCase:
        """Resolve an OPEN case."""
        ...


class ReviewDecisionRecorder(Protocol):
    """Optional persistence hook for explainability/audit history."""

    async def record(
        self,
        *,
        task: Task,
        evaluation: ReviewEvaluation,
    ) -> None:
        """Persist one review-gate evaluation."""
        ...


class InMemoryReviewCaseStore:
    """Concurrency-safe development store for human-review cases."""

    def __init__(self) -> None:
        self._cases: dict[str, ReviewCase] = {}
        self._open_keys: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def open_or_get(
        self,
        *,
        task: Task,
        signals: tuple[ReviewSignal, ...],
    ) -> ReviewCase:
        if not signals:
            raise ValueError(
                "cannot open review case without triggering signals"
            )

        fingerprints = tuple(
            sorted({signal.stable_fingerprint for signal in signals})
        )
        key = _review_dedupe_key(
            task_id=task.task_id,
            fingerprints=fingerprints,
        )

        async with self._lock:
            existing_id = self._open_keys.get(key)
            if existing_id is not None:
                existing = self._cases.get(existing_id)
                if (
                    existing is not None
                    and existing.state is ReviewCaseState.OPEN
                ):
                    return existing.model_copy(deep=True)
                self._open_keys.pop(key, None)

            categories = tuple(
                sorted(
                    {signal.category for signal in signals},
                    key=lambda category: category.value,
                )
            )
            summaries = tuple(
                dict.fromkeys(signal.summary for signal in signals)
            )

            review_case = ReviewCase(
                task_id=task.task_id,
                worker=task.worker,
                action=task.action,
                input_event_id=task.input_event_id,
                signal_fingerprints=fingerprints,
                categories=categories,
                summaries=summaries,
            )

            self._cases[review_case.case_id] = review_case
            self._open_keys[key] = review_case.case_id

            return review_case.model_copy(deep=True)

    async def get(self, case_id: str) -> ReviewCase | None:
        async with self._lock:
            review_case = self._cases.get(case_id)
            return (
                review_case.model_copy(deep=True)
                if review_case is not None
                else None
            )

    async def open_cases(self) -> list[ReviewCase]:
        async with self._lock:
            cases = [
                case.model_copy(deep=True)
                for case in self._cases.values()
                if case.state is ReviewCaseState.OPEN
            ]

        cases.sort(
            key=lambda case: (
                case.opened_at,
                case.case_id,
            )
        )
        return cases

    async def approved_for_task(
        self,
        task_id: str,
        *,
        signal_fingerprints: tuple[str, ...] | None = None,
    ) -> ReviewCase | None:
        async with self._lock:
            cases = [
                case
                for case in self._cases.values()
                if case.task_id == task_id
                and case.state is ReviewCaseState.APPROVED
                and (
                    signal_fingerprints is None
                    or case.signal_fingerprints == signal_fingerprints
                )
            ]
            if not cases:
                return None
            cases.sort(
                key=lambda case: case.resolved_at or case.opened_at,
                reverse=True,
            )
            return cases[0].model_copy(deep=True)

    async def resolve(
        self,
        case_id: str,
        *,
        state: ReviewCaseState,
        reason: str | None = None,
    ) -> ReviewCase:
        if state is ReviewCaseState.OPEN:
            raise ValueError(
                "resolve() requires a non-OPEN review state"
            )

        async with self._lock:
            try:
                review_case = self._cases[case_id]
            except KeyError as exc:
                raise KeyError(
                    f"unknown review case: {case_id}"
                ) from exc

            if review_case.state is not ReviewCaseState.OPEN:
                raise ValueError(
                    f"review case {case_id} is already resolved"
                )

            normalized_reason = (
                reason.strip() if reason is not None else None
            ) or None

            resolved = review_case.model_copy(
                update={
                    "state": state,
                    "resolved_at": utc_now(),
                    "resolution_reason": normalized_reason,
                }
            )
            self._cases[case_id] = resolved

            key = _review_dedupe_key(
                task_id=review_case.task_id,
                fingerprints=review_case.signal_fingerprints,
            )
            if self._open_keys.get(key) == case_id:
                self._open_keys.pop(key, None)

            return resolved.model_copy(deep=True)


class ReviewGate:
    """Lifecycle gate that pauses only genuinely review-worthy follow-ups."""

    def __init__(
        self,
        *,
        signals: ReviewSignalProvider,
        cases: ReviewCaseStore,
        policy: ReviewPolicy | None = None,
        recorder: ReviewDecisionRecorder | None = None,
    ) -> None:
        self._signals = signals
        self._cases = cases
        self._policy = policy or ReviewPolicy()
        self._recorder = recorder

    async def evaluate(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> GateDecision:
        """Evaluate signals and open a human-review case when needed."""
        all_signals = await self._signals.signals_for(
            task,
            schedule,
        )

        triggering = tuple(
            signal
            for signal in all_signals
            if self._policy.requires_review(signal)
        )
        ignored = tuple(
            signal
            for signal in all_signals
            if not self._policy.requires_review(signal)
        )

        if not triggering:
            evaluation = ReviewEvaluation(
                outcome=GateOutcome.ALLOW,
                task_id=task.task_id,
                triggering_signals=(),
                ignored_signals=ignored,
                reason=(
                    "no review signal met configured confidence/severity "
                    "thresholds"
                ),
            )
        else:
            fingerprints = tuple(
                sorted({signal.stable_fingerprint for signal in triggering})
            )
            approved = await self._cases.approved_for_task(
                task.task_id,
                signal_fingerprints=fingerprints,
            )
            if approved is not None:
                evaluation = ReviewEvaluation(
                    outcome=GateOutcome.ALLOW,
                    task_id=task.task_id,
                    triggering_signals=triggering,
                    ignored_signals=ignored,
                    case_id=approved.case_id,
                    reason=f"signals approved by human review case={approved.case_id}",
                )
            else:
                review_case = await self._cases.open_or_get(
                    task=task,
                    signals=triggering,
                )
                categories = ", ".join(
                    category.value
                    for category in review_case.categories
                )
                evaluation = ReviewEvaluation(
                    outcome=GateOutcome.REVIEW,
                    task_id=task.task_id,
                    triggering_signals=triggering,
                    ignored_signals=ignored,
                    case_id=review_case.case_id,
                    reason=(
                        f"human review required; case={review_case.case_id}; "
                        f"categories={categories}"
                    ),
                )

        if self._recorder is not None:
            await self._recorder.record(
                task=task,
                evaluation=evaluation,
            )

        return GateDecision(
            outcome=evaluation.outcome,
            reason=evaluation.reason,
            review_case_id=(
                evaluation.case_id
                if evaluation.outcome is GateOutcome.REVIEW
                else None
            ),
        )


class NoReviewSignals:
    """Default provider for deployments before evidence classifiers exist."""

    async def signals_for(
        self,
        task: Task,
        schedule: ScheduleDecision,
    ) -> tuple[ReviewSignal, ...]:
        """Return no signals."""
        del task, schedule
        return ()


def _review_dedupe_key(
    *,
    task_id: str,
    fingerprints: tuple[str, ...],
) -> str:
    material = "|".join(
        (
            task_id,
            *fingerprints,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
