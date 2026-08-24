"""Map storage/event identities onto stable real-world surface identities."""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from recon.core.events import EventType
from recon.surface.models import SurfaceNodeKind

_EXCLUDED_INTELLIGENCE = frozenset(
    {
        EventType.PROJECT_NAME,
        EventType.VOCAB_TOKEN,
        EventType.NAMING_PATTERN,
    }
)


@dataclass(frozen=True, slots=True)
class SurfaceIdentity:
    kind: SurfaceNodeKind
    canonical_value: str

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.canonical_value}"

    @property
    def node_id(self) -> str:
        digest = hashlib.sha256(self.key.encode("utf-8")).hexdigest()[:24]
        return f"sgn_{digest}"


def surface_identity(
    event_type: EventType | str,
    value: str,
    *,
    include_intelligence: bool = False,
) -> SurfaceIdentity | None:
    kind = EventType(event_type)
    material = value.strip()
    if not material:
        return None
    if kind in _EXCLUDED_INTELLIGENCE and not include_intelligence:
        return None
    if kind in {
        EventType.POLICY_BLOCK,
        EventType.HUMAN_REVIEW,
        EventType.RELATIONSHIP,
        EventType.HTTP_RESPONSE,
        EventType.URL_PATH,
    }:
        return None

    if kind in {EventType.ROOT_DOMAIN, EventType.DNS_NAME, EventType.CERT_SAN}:
        return SurfaceIdentity(SurfaceNodeKind.DOMAIN, _normalize_domain(material))
    if kind is EventType.DNS_RECORD:
        return SurfaceIdentity(SurfaceNodeKind.DNS_RECORD, " ".join(material.split()))
    if kind is EventType.IP_ADDRESS:
        return SurfaceIdentity(SurfaceNodeKind.IP_ADDRESS, str(ipaddress.ip_address(material)))
    if kind is EventType.CIDR:
        return SurfaceIdentity(
            SurfaceNodeKind.CIDR, str(ipaddress.ip_network(material, strict=False))
        )
    if kind is EventType.ASN:
        canonical = material.upper()
        if not canonical.startswith("AS"):
            canonical = f"AS{canonical}"
        return SurfaceIdentity(SurfaceNodeKind.ASN, canonical)
    if kind is EventType.HTTP_SERVICE:
        return SurfaceIdentity(SurfaceNodeKind.HTTP_SERVICE, _normalize_service(material))
    if kind in {EventType.URL, EventType.API_ENDPOINT}:
        return SurfaceIdentity(SurfaceNodeKind.ENDPOINT, _normalize_url(material))
    if kind is EventType.JAVASCRIPT:
        return SurfaceIdentity(SurfaceNodeKind.JAVASCRIPT, _normalize_url_if_possible(material))
    if kind is EventType.CERTIFICATE:
        return SurfaceIdentity(SurfaceNodeKind.CERTIFICATE, material.lower())
    if kind is EventType.TECHNOLOGY:
        return SurfaceIdentity(SurfaceNodeKind.TECHNOLOGY, material.casefold())
    if kind is EventType.FINGERPRINT:
        return SurfaceIdentity(SurfaceNodeKind.FINGERPRINT, material.casefold())
    if kind is EventType.FAVICON:
        return SurfaceIdentity(SurfaceNodeKind.FAVICON, material)
    if kind is EventType.PARAMETER_NAME:
        return SurfaceIdentity(SurfaceNodeKind.PARAMETER, material)
    if kind is EventType.ARTIFACT:
        return SurfaceIdentity(SurfaceNodeKind.ARTIFACT, _normalize_url_if_possible(material))
    if kind is EventType.MOBILE_ARTIFACT:
        return SurfaceIdentity(SurfaceNodeKind.MOBILE_ARTIFACT, material)
    if kind is EventType.VULNERABILITY_CANDIDATE:
        return SurfaceIdentity(SurfaceNodeKind.VULNERABILITY_CANDIDATE, material)
    if kind is EventType.VULNERABILITY_FINDING:
        return SurfaceIdentity(SurfaceNodeKind.VULNERABILITY_FINDING, material)
    if include_intelligence and kind in _EXCLUDED_INTELLIGENCE:
        return SurfaceIdentity(SurfaceNodeKind.INTELLIGENCE, material.casefold())
    return None


def domain_from_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    return parsed.hostname.lower().rstrip(".") if parsed.hostname else None


def service_from_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        if not parsed.scheme or not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return None
    default = 443 if scheme == "https" else 80 if scheme == "http" else None
    suffix = "" if port is None or port == default else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _normalize_domain(value: str) -> str:
    wildcard = value.startswith("*.")
    normalized = value[2:] if wildcard else value
    normalized = normalized.strip().lower().rstrip(".")
    return f"*.{normalized}" if wildcard else normalized


def _normalize_service(value: str) -> str:
    normalized = service_from_url(value)
    return normalized or value.strip().lower().rstrip("/")


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return value.strip()
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    default = 443 if scheme == "https" else 80 if scheme == "http" else None
    netloc = host if port is None or port == default else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit(SplitResult(scheme, netloc, path, parsed.query, ""))


def _normalize_url_if_possible(value: str) -> str:
    try:
        return _normalize_url(value)
    except ValueError:
        return value.strip()
