"""CPE resolution and cached NVD CVE intelligence for Night Scout.

This module enriches already-detected product/version observations with public
vulnerability intelligence. It does NOT contact the target, validate a CVE, or
turn a CVE match into a finding.

Core flow
---------
TECHNOLOGY / normalized service version
        |
        v
TechnologyVersionObservation
        |
        v
CPE family resolution (NVD CPE API + local cache)
        |
        v
version-specific CPE candidates
        |
        v
NVD CVE API lookup (local cache first)
        |
        v
CveCandidate(status=UNVALIDATED_CANDIDATE)

Important boundaries
--------------------
- CVE candidate != vulnerable target.
- CPE match != exploitability.
- High CVSS != bug-bounty severity.
- This module never runs exploit templates or uses credentials.
- NVD receives only normalized product/version/vendor hints, never target
  hostname, URL, IP, cookies, auth headers, or secrets.
- All remote NVD requests are cached and serialized through a conservative
  request pacer.

NVD API notes
-------------
The NVD 2.0 APIs use:
    CPE: https://services.nvd.nist.gov/rest/json/cpes/2.0
    CVE: https://services.nvd.nist.gov/rest/json/cves/2.0

API keys are supplied in the `apiKey` request header. The default request
interval here is six seconds, matching NVD's published best-practice guidance.
A caller may configure another interval while remaining responsible for NVD
terms/rate limits.

The required NVD attribution notice is exposed as `NVD_ATTRIBUTION_NOTICE`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recon.core.events import Event, EventType


NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_ATTRIBUTION_NOTICE = (
    "This product uses data from the NVD API but is not endorsed or certified "
    "by the NVD."
)

_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:v(?:ersion)?[-_ ]*)?"
    r"([0-9]+(?:[._-][0-9A-Za-z]+){1,7}(?:[-+._][0-9A-Za-z.-]+)?)"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)

_PRODUCT_VERSION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^\s*(?P<product>.+?)\s*[/@:]\s*(?P<version>"
        r"[0-9][0-9A-Za-z._+\-]*)\s*$"
    ),
    re.compile(
        r"^\s*(?P<product>.+?)\s+v?(?P<version>"
        r"[0-9]+(?:[._-][0-9A-Za-z]+)+(?:[-+._][0-9A-Za-z.-]+)?)\s*$",
        re.IGNORECASE,
    ),
)

_TARGET_IDENTIFIER_RE = re.compile(
    r"(?:https?://|^[0-9a-f:]+$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$)",
    re.IGNORECASE,
)

_SAFE_PRODUCT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-()]{0,127}$")
_SAFE_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+\-]{0,127}$")

_COMMON_PRODUCT_ALIASES: dict[str, tuple[str, ...]] = {
    "apache": ("apache http server", "http server"),
    "apache httpd": ("apache http server",),
    "httpd": ("apache http server",),
    "nginx": ("nginx",),
    "openssl": ("openssl",),
    "openssh": ("openssh",),
    "tomcat": ("apache tomcat", "tomcat"),
    "apache tomcat": ("apache tomcat",),
    "jetty": ("eclipse jetty", "jetty"),
    "iis": ("internet information services", "iis"),
    "microsoft iis": ("internet information services", "iis"),
    "wordpress": ("wordpress",),
    "drupal": ("drupal",),
    "joomla": ("joomla",),
    "php": ("php",),
    "node.js": ("node.js", "nodejs"),
    "nodejs": ("node.js", "nodejs"),
    "python": ("python",),
    "django": ("django",),
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "spring": ("spring framework", "spring"),
    "spring boot": ("spring boot",),
    "react": ("react",),
    "angular": ("angular",),
    "vue.js": ("vue.js", "vue"),
    "vue": ("vue.js", "vue"),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalized_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        text = value.strip()
        if not text:
            return None

        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"

        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


class CveCandidateStatus(StrEnum):
    """A CVE match is intelligence until separately validated."""

    UNVALIDATED_CANDIDATE = "UNVALIDATED_CANDIDATE"


class CpePart(StrEnum):
    APPLICATION = "a"
    OPERATING_SYSTEM = "o"
    HARDWARE = "h"


class CvssSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    base_score: float | None = Field(default=None, ge=0.0, le=10.0)
    base_severity: str | None = None
    vector: str | None = None
    source: str | None = None
    metric_type: str | None = None


class CveReference(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    source: str | None = None
    tags: tuple[str, ...] = ()


class TechnologyVersionObservation(BaseModel):
    """Normalized product/version evidence safe to send to NVD."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product: str
    version: str

    vendor_hint: str | None = None
    part_hint: CpePart = CpePart.APPLICATION

    source_event_id: str | None = None
    source: str | None = None

    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("product")
    @classmethod
    def valid_product(cls, value: str) -> str:
        normalized = normalize_product(value)

        if normalized is None:
            raise ValueError("invalid or unsafe product name")

        return normalized

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        normalized = normalize_version(value)

        if normalized is None:
            raise ValueError("invalid or unsafe version")

        return normalized

    @field_validator("vendor_hint")
    @classmethod
    def valid_vendor_hint(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = normalize_product(value)
        return normalized

    @property
    def cache_key(self) -> str:
        payload = {
            "product": self.product.lower(),
            "version": self.version.lower(),
            "vendor": (
                self.vendor_hint.lower()
                if self.vendor_hint is not None
                else None
            ),
            "part": self.part_hint.value,
        }

        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()


class CpeCandidate(BaseModel):
    """Resolved CPE family rendered with the observed version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpe_name: str

    part: CpePart
    vendor: str
    product: str
    version: str

    title: str | None = None
    cpe_name_id: str | None = None

    deprecated: bool = False
    synthetic_version: bool = False

    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    reasons: tuple[str, ...] = ()
    source: str = "nvd-cpe-api"

    @field_validator("cpe_name")
    @classmethod
    def valid_cpe_name(cls, value: str) -> str:
        components = split_cpe23(value)

        if components is None:
            raise ValueError("invalid CPE 2.3 name")

        return value


class CveCandidate(BaseModel):
    """Public vulnerability intelligence associated with a CPE candidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: str
    status: CveCandidateStatus = CveCandidateStatus.UNVALIDATED_CANDIDATE

    matched_cpe: str
    cpe_score: float = Field(ge=0.0, le=1.0)

    description: str | None = None

    published: datetime | None = None
    last_modified: datetime | None = None
    vuln_status: str | None = None

    cvss: CvssSummary | None = None
    cwes: tuple[str, ...] = ()
    references: tuple[CveReference, ...] = ()

    known_exploited: bool = False
    cisa_exploit_add: datetime | None = None
    cisa_action_due: datetime | None = None

    source_identifier: str | None = None

    applicability_basis: str = "NVD_CPE_MATCH"
    validated_on_target: bool = False
    exploitation_attempted: bool = False

    nvd_attribution: str = NVD_ATTRIBUTION_NOTICE

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("cve_id")
    @classmethod
    def valid_cve_id(cls, value: str) -> str:
        normalized = value.strip().upper()

        if _CVE_ID_RE.fullmatch(normalized) is None:
            raise ValueError("invalid CVE ID")

        return normalized


class VulnerabilityLookupResult(BaseModel):
    """Result for one observed product/version."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observation: TechnologyVersionObservation

    cpe_candidates: tuple[CpeCandidate, ...] = ()
    cves: tuple[CveCandidate, ...] = ()

    cpe_cache_hit: bool = False
    cve_cache_hits: int = Field(default=0, ge=0)
    nvd_requests: int = Field(default=0, ge=0)

    truncated: bool = False

    warnings: tuple[str, ...] = ()

    @property
    def has_candidates(self) -> bool:
        return bool(self.cves)


class NvdClientConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    cpe_api_url: str = NVD_CPE_API_URL
    cve_api_url: str = NVD_CVE_API_URL

    api_key_env: str = "NVD_API_KEY"

    user_agent: str = (
        "NightScout/0.1 authorized-security-research "
        "(NVD vulnerability-intelligence client)"
    )

    timeout_seconds: float = Field(default=20.0, gt=0.0, le=120.0)

    # NVD currently recommends sleeping six seconds between requests.
    min_request_interval_seconds: float = Field(
        default=6.0,
        ge=0.0,
        le=60.0,
    )

    max_attempts: int = Field(default=3, ge=1, le=8)
    base_retry_delay_seconds: float = Field(default=6.0, ge=0.1, le=300.0)
    max_retry_delay_seconds: float = Field(default=60.0, ge=0.1, le=900.0)

    max_response_bytes: int = Field(
        default=16 * 1024 * 1024,
        ge=1024,
        le=256 * 1024 * 1024,
    )

    cpe_results_per_page: int = Field(default=100, ge=1, le=10_000)
    max_cpe_records: int = Field(default=250, ge=1, le=10_000)

    cve_results_per_page: int = Field(default=2_000, ge=1, le=2_000)
    max_cves_per_cpe: int = Field(default=500, ge=1, le=20_000)

    cpe_cache_ttl_seconds: int = Field(
        default=30 * 24 * 60 * 60,
        ge=60,
    )

    cve_cache_ttl_seconds: int = Field(
        default=24 * 60 * 60,
        ge=60,
    )

    negative_cache_ttl_seconds: int = Field(
        default=6 * 60 * 60,
        ge=60,
    )

    min_cpe_score: float = Field(default=0.60, ge=0.0, le=1.0)
    max_cpe_candidates: int = Field(default=5, ge=1, le=50)

    max_references_per_cve: int = Field(default=32, ge=0, le=512)

    @model_validator(mode="after")
    def valid_retry_bounds(self) -> "NvdClientConfig":
        if self.base_retry_delay_seconds > self.max_retry_delay_seconds:
            raise ValueError(
                "base_retry_delay_seconds cannot exceed max_retry_delay_seconds"
            )

        return self


class NvdApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = False,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


class NvdHttpTransport(Protocol):
    async def get_json(
        self,
        *,
        base_url: str,
        params: Mapping[str, str | int],
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> Mapping[str, Any]:
        ...


class UrllibNvdTransport:
    """Small stdlib transport; avoids adding an `httpx` Python dependency."""

    async def get_json(
        self,
        *,
        base_url: str,
        params: Mapping[str, str | int],
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> Mapping[str, Any]:
        return await asyncio.to_thread(
            self._get_json_sync,
            base_url=base_url,
            params=dict(params),
            headers=dict(headers),
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    @staticmethod
    def _get_json_sync(
        *,
        base_url: str,
        params: dict[str, str | int],
        headers: dict[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> Mapping[str, Any]:
        query = urlencode(params)
        url = f"{base_url}?{query}" if query else base_url

        request = Request(
            url=url,
            method="GET",
            headers=headers,
        )

        try:
            with urlopen(
                request,
                timeout=timeout_seconds,
            ) as response:
                raw = response.read(
                    max_response_bytes + 1
                )

                if len(raw) > max_response_bytes:
                    raise NvdApiError(
                        "NVD response exceeded configured size limit",
                        retryable=False,
                    )

        except HTTPError as exc:
            retry_after = parse_retry_after(
                exc.headers.get("Retry-After")
                if exc.headers is not None
                else None
            )

            message = (
                exc.headers.get("message")
                if exc.headers is not None
                else None
            )

            raise NvdApiError(
                message or f"NVD HTTP error {exc.code}",
                status_code=exc.code,
                retryable=(
                    exc.code == 429
                    or 500 <= exc.code <= 599
                ),
                retry_after_seconds=retry_after,
            ) from exc

        except URLError as exc:
            raise NvdApiError(
                f"NVD transport error: {exc.reason}",
                retryable=True,
            ) from exc

        try:
            payload = json.loads(
                raw.decode("utf-8")
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise NvdApiError(
                "NVD returned invalid JSON",
                retryable=False,
            ) from exc

        if not isinstance(payload, dict):
            raise NvdApiError(
                "NVD returned a non-object JSON response",
                retryable=False,
            )

        return payload


class NvdCache(Protocol):
    async def get(
        self,
        cache_key: str,
    ) -> Mapping[str, Any] | None:
        ...

    async def set(
        self,
        cache_key: str,
        payload: Mapping[str, Any],
        *,
        ttl_seconds: int,
    ) -> None:
        ...


class InMemoryNvdCache:
    def __init__(self) -> None:
        self._items: dict[
            str,
            tuple[
                datetime,
                dict[str, Any],
            ],
        ] = {}

        self._lock = asyncio.Lock()

    async def get(
        self,
        cache_key: str,
    ) -> Mapping[str, Any] | None:
        now = utc_now()

        async with self._lock:
            item = self._items.get(cache_key)

            if item is None:
                return None

            expires_at, payload = item

            if expires_at <= now:
                self._items.pop(
                    cache_key,
                    None,
                )
                return None

            return json.loads(
                json.dumps(payload)
            )

    async def set(
        self,
        cache_key: str,
        payload: Mapping[str, Any],
        *,
        ttl_seconds: int,
    ) -> None:
        expires_at = (
            utc_now()
            + timedelta(seconds=ttl_seconds)
        )

        copied = json.loads(
            json.dumps(dict(payload))
        )

        async with self._lock:
            self._items[
                cache_key
            ] = (
                expires_at,
                copied,
            )


class SQLiteNvdCache:
    """Standalone local NVD cache.

    The cache is deliberately separate from Night Scout's canonical event DB:
    it is disposable public reference data and can be rebuilt from NVD.
    """

    def __init__(
        self,
        path: str | Path,
    ) -> None:
        self.path = Path(path)

    async def initialize(self) -> None:
        await asyncio.to_thread(
            self._initialize_sync
        )

    async def get(
        self,
        cache_key: str,
    ) -> Mapping[str, Any] | None:
        return await asyncio.to_thread(
            self._get_sync,
            cache_key,
        )

    async def set(
        self,
        cache_key: str,
        payload: Mapping[str, Any],
        *,
        ttl_seconds: int,
    ) -> None:
        await asyncio.to_thread(
            self._set_sync,
            cache_key,
            dict(payload),
            ttl_seconds,
        )

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = sqlite3.connect(
            self.path,
            timeout=10.0,
        )

        connection.execute(
            "PRAGMA journal_mode=WAL"
        )
        connection.execute(
            "PRAGMA synchronous=NORMAL"
        )

        return connection

    def _initialize_sync(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS ix_nvd_cache_expires_at
                ON nvd_cache(expires_at)
                """
            )

    def _get_sync(
        self,
        cache_key: str,
    ) -> Mapping[str, Any] | None:
        self._initialize_sync()

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload_json, expires_at
                FROM nvd_cache
                WHERE cache_key = ?
                """,
                (cache_key,),
            ).fetchone()

            if row is None:
                return None

            payload_json, expires_at_text = row

            expires_at = normalized_datetime(
                expires_at_text
            )

            if (
                expires_at is None
                or expires_at <= utc_now()
            ):
                connection.execute(
                    """
                    DELETE FROM nvd_cache
                    WHERE cache_key = ?
                    """,
                    (cache_key,),
                )
                return None

            try:
                payload = json.loads(
                    payload_json
                )
            except json.JSONDecodeError:
                connection.execute(
                    """
                    DELETE FROM nvd_cache
                    WHERE cache_key = ?
                    """,
                    (cache_key,),
                )
                return None

            if not isinstance(payload, dict):
                return None

            return payload

    def _set_sync(
        self,
        cache_key: str,
        payload: dict[str, Any],
        ttl_seconds: int,
    ) -> None:
        self._initialize_sync()

        fetched_at = utc_now()
        expires_at = (
            fetched_at
            + timedelta(
                seconds=ttl_seconds
            )
        )

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        )

        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO nvd_cache (
                    cache_key,
                    payload_json,
                    fetched_at,
                    expires_at
                )
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (
                    cache_key,
                    serialized,
                    fetched_at.isoformat(),
                    expires_at.isoformat(),
                ),
            )


class NvdVulnerabilityIntelligence:
    """High-level CPE resolution + cached CVE lookup service."""

    def __init__(
        self,
        *,
        cache: NvdCache,
        config: NvdClientConfig | None = None,
        transport: NvdHttpTransport | None = None,
    ) -> None:
        self.cache = cache
        self.config = (
            config
            or NvdClientConfig()
        )
        self.transport = (
            transport
            or UrllibNvdTransport()
        )

        self._request_lock = asyncio.Lock()
        self._last_request_monotonic: float | None = None

    async def lookup_event(
        self,
        event: Event,
    ) -> VulnerabilityLookupResult | None:
        observation = technology_version_from_event(
            event
        )

        if observation is None:
            return None

        return await self.lookup(
            observation
        )

    async def lookup_events(
        self,
        events: Sequence[Event],
        *,
        max_unique_products: int = 2_000,
    ) -> tuple[VulnerabilityLookupResult, ...]:
        """Lookup unique product/version observations.

        Duplicate service versions across many hosts intentionally collapse into
        one NVD lookup. The caller can associate the result back to each Event
        through `TechnologyVersionObservation.cache_key`.
        """

        unique: dict[
            str,
            TechnologyVersionObservation,
        ] = {}

        for event in events:
            observation = technology_version_from_event(
                event
            )

            if observation is None:
                continue

            unique.setdefault(
                observation.cache_key,
                observation,
            )

            if len(unique) >= max_unique_products:
                break

        results: list[
            VulnerabilityLookupResult
        ] = []

        for observation in unique.values():
            results.append(
                await self.lookup(
                    observation
                )
            )

        return tuple(results)

    async def lookup(
        self,
        observation: TechnologyVersionObservation,
    ) -> VulnerabilityLookupResult:
        cpe_candidates, cpe_cache_hit, cpe_requests, cpe_truncated = (
            await self.resolve_cpes(
                observation
            )
        )

        warnings: list[str] = []

        if not cpe_candidates:
            warnings.append(
                "no sufficiently confident CPE family was resolved"
            )

            return VulnerabilityLookupResult(
                observation=observation,
                cpe_candidates=(),
                cves=(),
                cpe_cache_hit=cpe_cache_hit,
                cve_cache_hits=0,
                nvd_requests=cpe_requests,
                truncated=cpe_truncated,
                warnings=tuple(warnings),
            )

        cves_by_id: dict[
            str,
            CveCandidate,
        ] = {}

        cve_cache_hits = 0
        request_count = cpe_requests
        truncated = cpe_truncated

        for candidate in cpe_candidates:
            (
                cves,
                cache_hit,
                requests,
                cve_truncated,
            ) = await self.lookup_cves_for_cpe(
                candidate
            )

            if cache_hit:
                cve_cache_hits += 1

            request_count += requests
            truncated = (
                truncated
                or cve_truncated
            )

            for cve in cves:
                existing = cves_by_id.get(
                    cve.cve_id
                )

                if (
                    existing is None
                    or cve.cpe_score
                    > existing.cpe_score
                ):
                    cves_by_id[
                        cve.cve_id
                    ] = cve

        cves = tuple(
            sorted(
                cves_by_id.values(),
                key=cve_sort_key,
            )
        )

        if truncated:
            warnings.append(
                "NVD results were truncated by configured safety limits"
            )

        return VulnerabilityLookupResult(
            observation=observation,
            cpe_candidates=(
                cpe_candidates
            ),
            cves=cves,
            cpe_cache_hit=(
                cpe_cache_hit
            ),
            cve_cache_hits=(
                cve_cache_hits
            ),
            nvd_requests=request_count,
            truncated=truncated,
            warnings=tuple(warnings),
        )

    async def resolve_cpes(
        self,
        observation: TechnologyVersionObservation,
    ) -> tuple[
        tuple[CpeCandidate, ...],
        bool,
        int,
        bool,
    ]:
        key = cache_key(
            "cpe",
            {
                "product": observation.product.lower(),
                "version": observation.version.lower(),
                "vendor_hint": (
                    observation.vendor_hint.lower()
                    if observation.vendor_hint
                    else None
                ),
                "part": observation.part_hint.value,
                "resolver_version": 1,
            },
        )

        cached = await self.cache.get(
            key
        )

        if cached is not None:
            candidates = tuple(
                CpeCandidate.model_validate(
                    item
                )
                for item
                in cached.get(
                    "candidates",
                    [],
                )
                if isinstance(
                    item,
                    dict,
                )
            )

            return (
                candidates,
                True,
                0,
                bool(
                    cached.get(
                        "truncated",
                        False,
                    )
                ),
            )

        search_terms = cpe_search_terms(
            observation
        )

        raw_records: list[
            Mapping[str, Any]
        ] = []

        request_count = 0
        truncated = False

        seen_ids: set[str] = set()

        for search_term in search_terms:
            payload = await self._request_json(
                base_url=(
                    self.config.cpe_api_url
                ),
                params={
                    "keywordSearch": (
                        search_term
                    ),
                    "resultsPerPage": (
                        self.config.cpe_results_per_page
                    ),
                    "startIndex": 0,
                },
            )

            request_count += 1

            products = payload.get(
                "products",
                [],
            )

            if not isinstance(
                products,
                list,
            ):
                products = []

            for product in products:
                if not isinstance(
                    product,
                    dict,
                ):
                    continue

                cpe = product.get(
                    "cpe"
                )

                if not isinstance(
                    cpe,
                    dict,
                ):
                    continue

                record_id = str(
                    cpe.get(
                        "cpeNameId",
                        "",
                    )
                )

                identity = (
                    record_id
                    or str(
                        cpe.get(
                            "cpeName",
                            "",
                        )
                    )
                )

                if not identity or identity in seen_ids:
                    continue

                seen_ids.add(
                    identity
                )
                raw_records.append(
                    product
                )

                if (
                    len(raw_records)
                    >= self.config.max_cpe_records
                ):
                    truncated = True
                    break

            total_results = safe_int(
                payload.get(
                    "totalResults"
                )
            )

            if (
                total_results is not None
                and total_results
                > self.config.cpe_results_per_page
            ):
                # Search is intentionally bounded. We do not enumerate huge
                # product families merely to resolve one observed service.
                truncated = True

            if (
                len(raw_records)
                >= self.config.max_cpe_records
            ):
                break

        candidates = rank_cpe_candidates(
            observation,
            raw_records,
            min_score=(
                self.config.min_cpe_score
            ),
            limit=(
                self.config.max_cpe_candidates
            ),
        )

        ttl = (
            self.config.cpe_cache_ttl_seconds
            if candidates
            else self.config.negative_cache_ttl_seconds
        )

        await self.cache.set(
            key,
            {
                "schema_version": 1,
                "kind": "cpe-resolution",
                "candidates": [
                    candidate.model_dump(
                        mode="json"
                    )
                    for candidate
                    in candidates
                ],
                "truncated": truncated,
                "nvd_attribution": (
                    NVD_ATTRIBUTION_NOTICE
                ),
            },
            ttl_seconds=ttl,
        )

        return (
            candidates,
            False,
            request_count,
            truncated,
        )

    async def lookup_cves_for_cpe(
        self,
        candidate: CpeCandidate,
    ) -> tuple[
        tuple[CveCandidate, ...],
        bool,
        int,
        bool,
    ]:
        key = cache_key(
            "cve",
            {
                "cpe_name": (
                    candidate.cpe_name
                ),
                "parser_version": 1,
            },
        )

        cached = await self.cache.get(
            key
        )

        if cached is not None:
            cves = tuple(
                CveCandidate.model_validate(
                    item
                )
                for item
                in cached.get(
                    "cves",
                    [],
                )
                if isinstance(
                    item,
                    dict,
                )
            )

            return (
                cves,
                True,
                0,
                bool(
                    cached.get(
                        "truncated",
                        False,
                    )
                ),
            )

        cves: list[
            CveCandidate
        ] = []

        request_count = 0
        start_index = 0
        truncated = False

        while True:
            remaining = (
                self.config.max_cves_per_cpe
                - len(cves)
            )

            if remaining <= 0:
                truncated = True
                break

            page_size = min(
                self.config.cve_results_per_page,
                remaining,
            )

            payload = await self._request_json(
                base_url=(
                    self.config.cve_api_url
                ),
                params={
                    "cpeName": (
                        candidate.cpe_name
                    ),
                    "noRejected": "",
                    "resultsPerPage": (
                        page_size
                    ),
                    "startIndex": (
                        start_index
                    ),
                },
            )

            request_count += 1

            vulnerabilities = payload.get(
                "vulnerabilities",
                [],
            )

            if not isinstance(
                vulnerabilities,
                list,
            ):
                vulnerabilities = []

            for record in vulnerabilities:
                cve = parse_nvd_cve(
                    record,
                    candidate=candidate,
                    max_references=(
                        self.config.max_references_per_cve
                    ),
                )

                if cve is not None:
                    cves.append(
                        cve
                    )

                if (
                    len(cves)
                    >= self.config.max_cves_per_cpe
                ):
                    truncated = True
                    break

            total_results = (
                safe_int(
                    payload.get(
                        "totalResults"
                    )
                )
                or 0
            )

            returned = (
                safe_int(
                    payload.get(
                        "resultsPerPage"
                    )
                )
                or len(
                    vulnerabilities
                )
            )

            actual_start = (
                safe_int(
                    payload.get(
                        "startIndex"
                    )
                )
                or start_index
            )

            next_index = (
                actual_start
                + returned
            )

            if (
                not vulnerabilities
                or next_index
                >= total_results
            ):
                break

            if (
                len(cves)
                >= self.config.max_cves_per_cpe
            ):
                truncated = True
                break

            start_index = next_index

        deduped = {
            cve.cve_id: cve
            for cve in cves
        }

        final_cves = tuple(
            sorted(
                deduped.values(),
                key=cve_sort_key,
            )
        )

        ttl = (
            self.config.cve_cache_ttl_seconds
            if final_cves
            else self.config.negative_cache_ttl_seconds
        )

        await self.cache.set(
            key,
            {
                "schema_version": 1,
                "kind": "cve-by-cpe",
                "cves": [
                    cve.model_dump(
                        mode="json"
                    )
                    for cve
                    in final_cves
                ],
                "truncated": truncated,
                "nvd_attribution": (
                    NVD_ATTRIBUTION_NOTICE
                ),
            },
            ttl_seconds=ttl,
        )

        return (
            final_cves,
            False,
            request_count,
            truncated,
        )

    async def _request_json(
        self,
        *,
        base_url: str,
        params: Mapping[str, str | int],
    ) -> Mapping[str, Any]:
        headers = {
            "Accept": "application/json",
            "User-Agent": (
                self.config.user_agent
            ),
        }

        api_key = os.environ.get(
            self.config.api_key_env,
            "",
        ).strip()

        if api_key:
            headers[
                "apiKey"
            ] = api_key

        last_error: NvdApiError | None = None

        for attempt in range(
            1,
            self.config.max_attempts + 1,
        ):
            try:
                async with self._request_lock:
                    await self._pace_request()

                    payload = await self.transport.get_json(
                        base_url=base_url,
                        params=params,
                        headers=headers,
                        timeout_seconds=(
                            self.config.timeout_seconds
                        ),
                        max_response_bytes=(
                            self.config.max_response_bytes
                        ),
                    )

                    self._last_request_monotonic = (
                        time.monotonic()
                    )

                return payload

            except NvdApiError as exc:
                last_error = exc

                if (
                    not exc.retryable
                    or attempt
                    >= self.config.max_attempts
                ):
                    raise

                delay = retry_delay(
                    attempt=attempt,
                    base=(
                        self.config.base_retry_delay_seconds
                    ),
                    maximum=(
                        self.config.max_retry_delay_seconds
                    ),
                    retry_after=(
                        exc.retry_after_seconds
                    ),
                )

                await asyncio.sleep(
                    delay
                )

        assert last_error is not None
        raise last_error

    async def _pace_request(self) -> None:
        if (
            self._last_request_monotonic
            is None
            or self.config.min_request_interval_seconds
            <= 0.0
        ):
            return

        elapsed = (
            time.monotonic()
            - self._last_request_monotonic
        )

        delay = (
            self.config.min_request_interval_seconds
            - elapsed
        )

        if delay > 0.0:
            await asyncio.sleep(
                delay
            )


def technology_version_from_event(
    event: Event,
) -> TechnologyVersionObservation | None:
    """Extract a product/version pair without leaking target identity.

    Only TECHNOLOGY Events are consumed directly. If version metadata is
    present, it takes precedence over parsing the display value.
    """

    if event.type is not EventType.TECHNOLOGY:
        return None

    if event_is_sensitive(
        event
    ):
        return None

    metadata_product = first_text_metadata(
        event.metadata,
        "product",
        "technology",
        "name",
    )

    metadata_version = first_text_metadata(
        event.metadata,
        "version",
        "product_version",
        "technology_version",
    )

    vendor_hint = first_text_metadata(
        event.metadata,
        "vendor",
        "vendor_hint",
    )

    part_hint = parse_part_hint(
        first_text_metadata(
            event.metadata,
            "cpe_part",
            "part",
        )
    )

    if (
        metadata_product is not None
        and metadata_version is not None
    ):
        product = normalize_product(
            metadata_product
        )

        version = normalize_version(
            metadata_version
        )

    else:
        parsed = parse_product_version(
            event.value
        )

        if parsed is None:
            return None

        product, version = parsed

    if (
        product is None
        or version is None
    ):
        return None

    return TechnologyVersionObservation(
        product=product,
        version=version,
        vendor_hint=vendor_hint,
        part_hint=part_hint,
        source_event_id=event.event_id,
        source=event.source,
        confidence=event.confidence,
        metadata={
            "source_event_type": (
                event.type.value
            ),
            "source_family": (
                event.source.split(
                    ":",
                    1,
                )[0]
            ),
            "target_identifiers_forwarded_to_nvd": False,
        },
    )


def parse_product_version(
    value: str,
) -> tuple[str, str] | None:
    """Conservatively parse common technology/version display strings."""

    text = " ".join(
        value.strip().split()
    )

    if (
        not text
        or len(text) > 256
        or _TARGET_IDENTIFIER_RE.search(text)
    ):
        return None

    for pattern in _PRODUCT_VERSION_PATTERNS:
        match = pattern.fullmatch(
            text
        )

        if match is None:
            continue

        product = normalize_product(
            match.group(
                "product"
            )
        )

        version = normalize_version(
            match.group(
                "version"
            )
        )

        if (
            product is not None
            and version is not None
        ):
            return (
                product,
                version,
            )

    match = _VERSION_RE.search(
        text
    )

    if match is None:
        return None

    version = normalize_version(
        match.group(1)
    )

    if version is None:
        return None

    product_text = (
        text[
            : match.start()
        ]
        .strip(
            " /@:-_"
        )
    )

    product = normalize_product(
        product_text
    )

    if product is None:
        return None

    return (
        product,
        version,
    )


def normalize_product(
    value: str,
) -> str | None:
    normalized = " ".join(
        value.strip().split()
    )

    if (
        not normalized
        or len(normalized) > 128
        or _SAFE_PRODUCT_RE.fullmatch(
            normalized
        )
        is None
        or _TARGET_IDENTIFIER_RE.search(
            normalized
        )
    ):
        return None

    if looks_secret_like(
        normalized
    ):
        return None

    return normalized


def normalize_version(
    value: str,
) -> str | None:
    normalized = value.strip()

    if normalized.lower().startswith(
        "version "
    ):
        normalized = normalized[
            len("version "):
        ].strip()

    if (
        normalized.lower().startswith(
            "v"
        )
        and len(normalized) > 1
        and normalized[1].isdigit()
    ):
        normalized = normalized[1:]

    if (
        not normalized
        or len(normalized) > 128
        or _SAFE_VERSION_RE.fullmatch(
            normalized
        )
        is None
        or not any(
            character.isdigit()
            for character
            in normalized
        )
    ):
        return None

    return normalized


def cpe_search_terms(
    observation: TechnologyVersionObservation,
) -> tuple[str, ...]:
    """Return bounded product-family search terms, never target identifiers."""

    product = observation.product.lower()
    aliases = _COMMON_PRODUCT_ALIASES.get(
        product,
        (),
    )

    candidates: list[str] = []

    if observation.vendor_hint:
        candidates.append(
            f"{observation.vendor_hint} {observation.product}"
        )

    candidates.extend(
        aliases
    )
    candidates.append(
        observation.product
    )

    result: list[str] = []

    for candidate in candidates:
        normalized = " ".join(
            candidate.strip().split()
        )

        if (
            normalized
            and normalized.lower()
            not in {
                item.lower()
                for item in result
            }
            and normalize_product(
                normalized
            )
            is not None
        ):
            result.append(
                normalized
            )

    return tuple(
        result[
            :4
        ]
    )


def rank_cpe_candidates(
    observation: TechnologyVersionObservation,
    raw_products: Sequence[Mapping[str, Any]],
    *,
    min_score: float,
    limit: int,
) -> tuple[CpeCandidate, ...]:
    """Resolve CPE family, then render it with the observed exact version."""

    families: dict[
        tuple[
            str,
            str,
            str,
        ],
        dict[str, Any],
    ] = {}

    for record in raw_products:
        cpe = record.get(
            "cpe"
        )

        if not isinstance(
            cpe,
            Mapping,
        ):
            continue

        cpe_name = cpe.get(
            "cpeName"
        )

        if not isinstance(
            cpe_name,
            str,
        ):
            continue

        components = split_cpe23(
            cpe_name
        )

        if components is None:
            continue

        part_value = components[2]

        try:
            part = CpePart(
                part_value
            )
        except ValueError:
            continue

        if part is not observation.part_hint:
            continue

        vendor = unescape_cpe_component(
            components[3]
        )

        product = unescape_cpe_component(
            components[4]
        )

        record_version = unescape_cpe_component(
            components[5]
        )

        if (
            not vendor
            or vendor in {"*", "-"}
            or not product
            or product in {"*", "-"}
        ):
            continue

        titles = cpe.get(
            "titles",
            []
        )

        title = preferred_english_title(
            titles
        )

        score, reasons = score_cpe_family(
            observation=observation,
            vendor=vendor,
            product=product,
            record_version=record_version,
            title=title,
            deprecated=bool(
                cpe.get(
                    "deprecated",
                    False,
                )
            ),
        )

        family_key = (
            part.value,
            vendor.lower(),
            product.lower(),
        )

        existing = families.get(
            family_key
        )

        candidate_state = {
            "part": part,
            "vendor": vendor,
            "product": product,
            "record_version": record_version,
            "title": title,
            "cpe_name_id": (
                str(
                    cpe.get(
                        "cpeNameId"
                    )
                )
                if cpe.get(
                    "cpeNameId"
                )
                is not None
                else None
            ),
            "deprecated": bool(
                cpe.get(
                    "deprecated",
                    False,
                )
            ),
            "score": score,
            "reasons": reasons,
        }

        if (
            existing is None
            or score
            > existing[
                "score"
            ]
        ):
            families[
                family_key
            ] = candidate_state

    ranked: list[
        CpeCandidate
    ] = []

    for family in families.values():
        score = float(
            family[
                "score"
            ]
        )

        if score < min_score:
            continue

        exact_record_version = (
            normalize_version(
                str(
                    family[
                        "record_version"
                    ]
                )
            )
        )

        synthetic = (
            exact_record_version
            != observation.version
        )

        versioned_cpe = render_cpe23(
            part=(
                family[
                    "part"
                ]
            ),
            vendor=(
                family[
                    "vendor"
                ]
            ),
            product=(
                family[
                    "product"
                ]
            ),
            version=(
                observation.version
            ),
        )

        confidence = min(
            0.98,
            max(
                0.35,
                (
                    observation.confidence
                    * 0.45
                    + score
                    * 0.55
                ),
            ),
        )

        reasons = list(
            family[
                "reasons"
            ]
        )

        if synthetic:
            reasons.append(
                "observed version applied to resolved CPE family"
            )
        else:
            reasons.append(
                "official CPE record version matches observation"
            )

        ranked.append(
            CpeCandidate(
                cpe_name=versioned_cpe,
                part=(
                    family[
                        "part"
                    ]
                ),
                vendor=(
                    family[
                        "vendor"
                    ]
                ),
                product=(
                    family[
                        "product"
                    ]
                ),
                version=(
                    observation.version
                ),
                title=(
                    family[
                        "title"
                    ]
                ),
                cpe_name_id=(
                    family[
                        "cpe_name_id"
                    ]
                ),
                deprecated=(
                    family[
                        "deprecated"
                    ]
                ),
                synthetic_version=(
                    synthetic
                ),
                score=score,
                confidence=confidence,
                reasons=tuple(
                    reasons
                ),
            )
        )

    ranked.sort(
        key=lambda candidate: (
            -candidate.score,
            candidate.deprecated,
            candidate.vendor,
            candidate.product,
        )
    )

    return tuple(
        ranked[
            :limit
        ]
    )


def score_cpe_family(
    *,
    observation: TechnologyVersionObservation,
    vendor: str,
    product: str,
    record_version: str,
    title: str | None,
    deprecated: bool,
) -> tuple[float, tuple[str, ...]]:
    observed_product = canonical_words(
        observation.product
    )

    cpe_product = canonical_words(
        product
    )

    reasons: list[str] = []
    score = 0.0

    product_similarity = word_similarity(
        observed_product,
        cpe_product,
    )

    score += (
        product_similarity
        * 0.42
    )

    if product_similarity >= 0.95:
        reasons.append(
            "CPE product strongly matches detected product"
        )

    aliases = {
        canonical_words(alias)
        for alias
        in _COMMON_PRODUCT_ALIASES.get(
            observation.product.lower(),
            (),
        )
    }

    title_words = canonical_words(
        title or ""
    )

    if aliases:
        alias_similarity = max(
            (
                word_similarity(
                    alias,
                    cpe_product,
                )
                for alias
                in aliases
            ),
            default=0.0,
        )

        title_alias_similarity = max(
            (
                word_similarity(
                    alias,
                    title_words,
                )
                for alias
                in aliases
            ),
            default=0.0,
        )

        alias_score = max(
            alias_similarity,
            title_alias_similarity,
        )

        score += (
            alias_score
            * 0.18
        )

        if alias_score >= 0.80:
            reasons.append(
                "known product alias matches NVD product/title"
            )

    title_similarity = word_similarity(
        observed_product,
        title_words,
    )

    score += (
        title_similarity
        * 0.14
    )

    if title_similarity >= 0.80:
        reasons.append(
            "NVD title supports product match"
        )

    if observation.vendor_hint:
        vendor_similarity = word_similarity(
            canonical_words(
                observation.vendor_hint
            ),
            canonical_words(
                vendor
            ),
        )

        score += (
            vendor_similarity
            * 0.14
        )

        if vendor_similarity >= 0.90:
            reasons.append(
                "vendor hint matches CPE vendor"
            )
    else:
        # No vendor hint: do not punish the candidate, but avoid granting the
        # vendor-specific confidence bonus.
        score += 0.05

    normalized_record_version = normalize_version(
        record_version
    )

    if normalized_record_version == observation.version:
        score += 0.12
        reasons.append(
            "official CPE version exactly matches detected version"
        )

    elif record_version in {
        "*",
        "-",
        "",
    }:
        score += 0.04
        reasons.append(
            "generic CPE family record available"
        )

    if deprecated:
        score -= 0.22
        reasons.append(
            "deprecated CPE record penalized"
        )

    return (
        clamp01(
            score
        ),
        tuple(
            reasons
        ),
    )


def render_cpe23(
    *,
    part: CpePart,
    vendor: str,
    product: str,
    version: str,
) -> str:
    """Render a version-specific CPE 2.3 name for NVD applicability lookup."""

    return ":".join(
        (
            "cpe",
            "2.3",
            part.value,
            escape_cpe_component(
                vendor
            ),
            escape_cpe_component(
                product
            ),
            escape_cpe_component(
                version
            ),
            "*",
            "*",
            "*",
            "*",
            "*",
            "*",
            "*",
        )
    )


def split_cpe23(
    value: str,
) -> tuple[str, ...] | None:
    """Split CPE 2.3 while respecting backslash-escaped colons."""

    components: list[str] = []
    current: list[str] = []
    escaped = False

    for character in value:
        if escaped:
            current.append("\\")
            current.append(
                character
            )
            escaped = False
            continue

        if character == "\\":
            escaped = True
            continue

        if character == ":":
            components.append(
                "".join(
                    current
                )
            )
            current = []
            continue

        current.append(
            character
        )

    if escaped:
        current.append(
            "\\"
        )

    components.append(
        "".join(
            current
        )
    )

    if (
        len(components) != 13
        or components[0] != "cpe"
        or components[1] != "2.3"
    ):
        return None

    return tuple(
        components
    )


def escape_cpe_component(
    value: str,
) -> str:
    """Escape the common CPE 2.3 component metacharacters."""

    normalized = value.strip().lower()

    escaped: list[str] = []

    for character in normalized:
        if character in {
            "\\",
            ":",
            "*",
            "?",
            "!",
            '"',
            "#",
            "$",
            "%",
            "&",
            "'",
            "(",
            ")",
            "+",
            ",",
            "/",
            ";",
            "<",
            "=",
            ">",
            "@",
            "[",
            "]",
            "^",
            "`",
            "{",
            "|",
            "}",
            "~",
        }:
            escaped.append(
                "\\"
            )

        escaped.append(
            character
        )

    return "".join(
        escaped
    )


def unescape_cpe_component(
    value: str,
) -> str:
    result: list[str] = []
    escaped = False

    for character in value:
        if escaped:
            result.append(
                character
            )
            escaped = False
            continue

        if character == "\\":
            escaped = True
            continue

        result.append(
            character
        )

    if escaped:
        result.append(
            "\\"
        )

    return "".join(
        result
    )


def parse_nvd_cve(
    record: Mapping[str, Any],
    *,
    candidate: CpeCandidate,
    max_references: int,
) -> CveCandidate | None:
    raw_cve = record.get(
        "cve"
    )

    if not isinstance(
        raw_cve,
        Mapping,
    ):
        return None

    cve_id = raw_cve.get(
        "id"
    )

    if (
        not isinstance(
            cve_id,
            str,
        )
        or _CVE_ID_RE.fullmatch(
            cve_id.strip()
        )
        is None
    ):
        return None

    description = preferred_english_description(
        raw_cve.get(
            "descriptions"
        )
    )

    references = parse_references(
        raw_cve.get(
            "references"
        ),
        limit=max_references,
    )

    cwes = parse_cwes(
        raw_cve.get(
            "weaknesses"
        )
    )

    cvss = parse_best_cvss(
        raw_cve.get(
            "metrics"
        )
    )

    cisa_exploit_add = normalized_datetime(
        raw_cve.get(
            "cisaExploitAdd"
        )
    )

    cisa_action_due = normalized_datetime(
        raw_cve.get(
            "cisaActionDue"
        )
    )

    known_exploited = (
        cisa_exploit_add is not None
        or cisa_action_due is not None
        or bool(
            raw_cve.get(
                "cisaRequiredAction"
            )
        )
    )

    return CveCandidate(
        cve_id=cve_id,
        matched_cpe=(
            candidate.cpe_name
        ),
        cpe_score=(
            candidate.score
        ),
        description=description,
        published=normalized_datetime(
            raw_cve.get(
                "published"
            )
        ),
        last_modified=normalized_datetime(
            raw_cve.get(
                "lastModified"
            )
        ),
        vuln_status=(
            str(
                raw_cve.get(
                    "vulnStatus"
                )
            )
            if raw_cve.get(
                "vulnStatus"
            )
            is not None
            else None
        ),
        cvss=cvss,
        cwes=cwes,
        references=references,
        known_exploited=(
            known_exploited
        ),
        cisa_exploit_add=(
            cisa_exploit_add
        ),
        cisa_action_due=(
            cisa_action_due
        ),
        source_identifier=(
            str(
                raw_cve.get(
                    "sourceIdentifier"
                )
            )
            if raw_cve.get(
                "sourceIdentifier"
            )
            is not None
            else None
        ),
        metadata={
            "cisa_required_action": (
                raw_cve.get(
                    "cisaRequiredAction"
                )
            ),
            "cisa_vulnerability_name": (
                raw_cve.get(
                    "cisaVulnerabilityName"
                )
            ),
            "nvd_cpe_candidate_confidence": (
                candidate.confidence
            ),
            "nvd_cpe_candidate_synthetic_version": (
                candidate.synthetic_version
            ),
        },
    )


def parse_best_cvss(
    value: Any,
) -> CvssSummary | None:
    if not isinstance(
        value,
        Mapping,
    ):
        return None

    keys = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    for key in keys:
        metrics = value.get(
            key
        )

        if not isinstance(
            metrics,
            list,
        ):
            continue

        ordered = sorted(
            (
                metric
                for metric
                in metrics
                if isinstance(
                    metric,
                    Mapping,
                )
            ),
            key=lambda metric: (
                0
                if str(
                    metric.get(
                        "type",
                        "",
                    )
                ).lower()
                == "primary"
                else 1
            ),
        )

        for metric in ordered:
            cvss_data = metric.get(
                "cvssData"
            )

            if not isinstance(
                cvss_data,
                Mapping,
            ):
                continue

            version = cvss_data.get(
                "version"
            )

            if not isinstance(
                version,
                str,
            ):
                continue

            base_score = safe_float(
                cvss_data.get(
                    "baseScore"
                )
            )

            base_severity = (
                cvss_data.get(
                    "baseSeverity"
                )
                or metric.get(
                    "baseSeverity"
                )
            )

            vector = cvss_data.get(
                "vectorString"
            )

            return CvssSummary(
                version=version,
                base_score=(
                    base_score
                    if (
                        base_score is None
                        or 0.0
                        <= base_score
                        <= 10.0
                    )
                    else None
                ),
                base_severity=(
                    str(
                        base_severity
                    )
                    if base_severity
                    is not None
                    else None
                ),
                vector=(
                    str(
                        vector
                    )
                    if vector
                    is not None
                    else None
                ),
                source=(
                    str(
                        metric.get(
                            "source"
                        )
                    )
                    if metric.get(
                        "source"
                    )
                    is not None
                    else None
                ),
                metric_type=(
                    str(
                        metric.get(
                            "type"
                        )
                    )
                    if metric.get(
                        "type"
                    )
                    is not None
                    else None
                ),
            )

    return None


def parse_cwes(
    value: Any,
) -> tuple[str, ...]:
    if not isinstance(
        value,
        list,
    ):
        return ()

    result: list[str] = []

    for weakness in value:
        if not isinstance(
            weakness,
            Mapping,
        ):
            continue

        descriptions = weakness.get(
            "description"
        )

        if not isinstance(
            descriptions,
            list,
        ):
            continue

        for description in descriptions:
            if not isinstance(
                description,
                Mapping,
            ):
                continue

            raw = description.get(
                "value"
            )

            if not isinstance(
                raw,
                str,
            ):
                continue

            normalized = raw.strip().upper()

            if (
                normalized.startswith(
                    "CWE-"
                )
                and normalized
                not in result
            ):
                result.append(
                    normalized
                )

    return tuple(
        sorted(
            result
        )
    )


def parse_references(
    value: Any,
    *,
    limit: int,
) -> tuple[CveReference, ...]:
    if (
        limit <= 0
        or not isinstance(
            value,
            list,
        )
    ):
        return ()

    result: list[
        CveReference
    ] = []

    seen_urls: set[str] = set()

    for item in value:
        if len(result) >= limit:
            break

        if not isinstance(
            item,
            Mapping,
        ):
            continue

        url = item.get(
            "url"
        )

        if (
            not isinstance(
                url,
                str,
            )
            or not url.startswith(
                (
                    "https://",
                    "http://",
                )
            )
            or url in seen_urls
        ):
            continue

        seen_urls.add(
            url
        )

        tags_raw = item.get(
            "tags"
        )

        if isinstance(
            tags_raw,
            list,
        ):
            tags = tuple(
                sorted(
                    {
                        str(
                            tag
                        ).strip()
                        for tag
                        in tags_raw
                        if str(
                            tag
                        ).strip()
                    }
                )
            )
        else:
            tags = ()

        result.append(
            CveReference(
                url=url,
                source=(
                    str(
                        item.get(
                            "source"
                        )
                    )
                    if item.get(
                        "source"
                    )
                    is not None
                    else None
                ),
                tags=tags,
            )
        )

    return tuple(
        result
    )


def preferred_english_description(
    value: Any,
) -> str | None:
    if not isinstance(
        value,
        list,
    ):
        return None

    fallback: str | None = None

    for item in value:
        if not isinstance(
            item,
            Mapping,
        ):
            continue

        raw = item.get(
            "value"
        )

        if not isinstance(
            raw,
            str,
        ):
            continue

        text = " ".join(
            raw.strip().split()
        )

        if not text:
            continue

        if fallback is None:
            fallback = text

        if str(
            item.get(
                "lang",
                "",
            )
        ).lower().startswith(
            "en"
        ):
            return text

    return fallback


def preferred_english_title(
    value: Any,
) -> str | None:
    if not isinstance(
        value,
        list,
    ):
        return None

    fallback: str | None = None

    for item in value:
        if not isinstance(
            item,
            Mapping,
        ):
            continue

        title = item.get(
            "title"
        )

        if not isinstance(
            title,
            str,
        ):
            continue

        normalized = " ".join(
            title.strip().split()
        )

        if not normalized:
            continue

        if fallback is None:
            fallback = normalized

        if str(
            item.get(
                "lang",
                "",
            )
        ).lower().startswith(
            "en"
        ):
            return normalized

    return fallback


def cve_sort_key(
    candidate: CveCandidate,
) -> tuple[Any, ...]:
    score = (
        candidate.cvss.base_score
        if (
            candidate.cvss is not None
            and candidate.cvss.base_score
            is not None
        )
        else -1.0
    )

    return (
        not candidate.known_exploited,
        -score,
        -candidate.cpe_score,
        candidate.cve_id,
    )


def canonical_words(
    value: str,
) -> frozenset[str]:
    tokens = re.findall(
        r"[a-z0-9]+",
        value.lower(),
    )

    stop = {
        "server",
        "software",
        "project",
        "framework",
        "platform",
        "the",
        "for",
    }

    return frozenset(
        token
        for token
        in tokens
        if token not in stop
    )


def word_similarity(
    left: frozenset[str],
    right: frozenset[str],
) -> float:
    if not left or not right:
        return 0.0

    intersection = len(
        left & right
    )

    union = len(
        left | right
    )

    if union <= 0:
        return 0.0

    jaccard = (
        intersection
        / union
    )

    containment = (
        intersection
        / min(
            len(left),
            len(right),
        )
    )

    return clamp01(
        jaccard * 0.55
        + containment * 0.45
    )


def cache_key(
    kind: str,
    payload: Mapping[str, Any],
) -> str:
    digest = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    return f"nvd:{kind}:{digest}"


def retry_delay(
    *,
    attempt: int,
    base: float,
    maximum: float,
    retry_after: float | None,
) -> float:
    exponential = min(
        maximum,
        base
        * (
            2 ** max(
                0,
                attempt - 1,
            )
        ),
    )

    if retry_after is not None:
        return min(
            maximum,
            max(
                exponential,
                retry_after,
            ),
        )

    return exponential


def parse_retry_after(
    value: str | None,
) -> float | None:
    if value is None:
        return None

    try:
        seconds = float(
            value.strip()
        )
    except ValueError:
        return None

    if seconds < 0.0:
        return None

    return seconds


def event_is_sensitive(
    event: Event,
) -> bool:
    tags = {
        tag.strip().lower()
        for tag
        in event.tags
        if tag.strip()
    }

    if any(
        (
            "secret" in tag
            or "credential" in tag
            or "private-key" in tag
            or "access-token" in tag
        )
        for tag in tags
    ):
        return True

    for key in (
        "possible_secret",
        "credential_candidate",
        "secret_candidate",
        "contains_secret",
    ):
        if event.metadata.get(
            key
        ) is True:
            return True

    return False


def looks_secret_like(
    value: str,
) -> bool:
    lower = value.strip().lower()

    if lower.startswith(
        (
            "bearer ",
            "basic ",
            "-----begin",
        )
    ):
        return True

    if (
        value.count(
            "."
        )
        == 2
        and all(
            len(part) >= 8
            for part
            in value.split(
                "."
            )
        )
    ):
        return True

    return False


def parse_part_hint(
    value: str | None,
) -> CpePart:
    if value is None:
        return CpePart.APPLICATION

    normalized = value.strip().lower()

    aliases = {
        "a": CpePart.APPLICATION,
        "application": CpePart.APPLICATION,
        "app": CpePart.APPLICATION,
        "o": CpePart.OPERATING_SYSTEM,
        "os": CpePart.OPERATING_SYSTEM,
        "operating_system": CpePart.OPERATING_SYSTEM,
        "operating-system": CpePart.OPERATING_SYSTEM,
        "h": CpePart.HARDWARE,
        "hardware": CpePart.HARDWARE,
    }

    return aliases.get(
        normalized,
        CpePart.APPLICATION,
    )


def first_text_metadata(
    metadata: Mapping[str, Any],
    *keys: str,
) -> str | None:
    for key in keys:
        value = metadata.get(
            key
        )

        if not isinstance(
            value,
            str,
        ):
            continue

        normalized = " ".join(
            value.strip().split()
        )

        if normalized:
            return normalized

    return None


def safe_int(
    value: Any,
) -> int | None:
    try:
        return int(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None


def safe_float(
    value: Any,
) -> float | None:
    try:
        parsed = float(
            value
        )
    except (
        TypeError,
        ValueError,
    ):
        return None

    if not math.isfinite(
        parsed
    ):
        return None

    return parsed


def clamp01(
    value: float,
) -> float:
    return min(
        1.0,
        max(
            0.0,
            float(
                value
            ),
        ),
    )