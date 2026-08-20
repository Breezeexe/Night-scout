#!/usr/bin/env python3
"""Explicit, reproducible wordlist synchronization for Night Scout.

Runtime reconnaissance never downloads public corpora. This script is the
separate supply-chain step that:

1. reads `wordlists/sources.yaml`;
2. downloads selected HTTPS sources with bounded size/redirect policy;
3. normalizes them into Night Scout's token-oriented corpus format;
4. records exact raw + normalized SHA-256 hashes in a local lock file;
5. generates `wordlists/generated/manifest.local.yaml` for wordlists.py.

Large upstream files remain under `wordlists/cache/` and are gitignored.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Direct `python scripts/wordlists_sync.py ...` execution puts only scripts/ on
# sys.path. Add the repository root explicitly before importing Night Scout.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from recon.intelligence.wordlists import WordlistManifest


DEFAULT_CATALOG = Path("wordlists/sources.yaml")
DEFAULT_BASE_MANIFEST = Path("wordlists/manifest.yaml")
DEFAULT_LOCK = Path("wordlists/generated/sources.lock.yaml")
DEFAULT_GENERATED_MANIFEST = Path("wordlists/generated/manifest.local.yaml")

USER_AGENT = "NightScout-Wordlists/0.1"
MAX_LINE_BYTES = 16_384

_SAFE_WORD_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-\[\]]{0,127}$")
_SAFE_PARAMETER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,127}$")
_SPLIT_PATH_RE = re.compile(r"[^A-Za-z0-9_.\-\[\]]+")


class SourceTransform(str):
    WORDS = "words"
    DNS_LABELS = "dns_labels"
    PARAMETER_NAMES = "parameter_names"
    PATH_TOKENS = "path_tokens"


class CatalogSource(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(alias="id")
    url: str
    local_path: str
    categories: tuple[str, ...]
    transform: str

    weight: float = Field(default=1.0, ge=0.0, le=100.0)
    max_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    max_entries: int = Field(default=250_000, ge=1)
    default: bool = False

    expected_sha256: str | None = None
    license: str | None = None
    upstream: str | None = None
    allowed_redirect_hosts: tuple[str, ...] = ()

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        normalized = value.strip().lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", normalized) is None:
            raise ValueError("unsupported source id")
        return normalized

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parts = urlsplit(value.strip())
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("wordlist upstream must be an HTTPS URL")
        if parts.username or parts.password:
            raise ValueError("credentials in wordlist URL are not allowed")
        return value.strip()

    @field_validator("local_path")
    @classmethod
    def validate_local_path(cls, value: str) -> str:
        normalized = value.strip().replace("\\", "/")
        path = Path(normalized)
        if not normalized or path.is_absolute() or ".." in path.parts:
            raise ValueError("local_path must stay inside wordlists/")
        if not normalized.startswith("cache/"):
            raise ValueError("external wordlists must be stored under cache/")
        return normalized

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {
            "general",
            "dns",
            "parameter",
            "path",
            "api",
            "vhost",
            "project",
            "technology",
        }
        normalized = tuple(dict.fromkeys(value.strip().lower() for value in values))
        if not normalized or any(value not in allowed for value in normalized):
            raise ValueError("unsupported wordlist category")
        return normalized

    @field_validator("transform")
    @classmethod
    def validate_transform(cls, value: str) -> str:
        normalized = value.strip().lower()
        allowed = {
            SourceTransform.WORDS,
            SourceTransform.DNS_LABELS,
            SourceTransform.PARAMETER_NAMES,
            SourceTransform.PATH_TOKENS,
        }
        if normalized not in allowed:
            raise ValueError(f"unsupported transform: {normalized}")
        return normalized

    @field_validator("expected_sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
            raise ValueError("expected_sha256 must contain 64 hex characters")
        return normalized

    @field_validator("allowed_redirect_hosts")
    @classmethod
    def normalize_hosts(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted({value.strip().lower().rstrip(".") for value in values if value.strip()})
        )


class SourceCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1)
    sources: tuple[CatalogSource, ...]

    @model_validator(mode="after")
    def unique_ids_and_paths(self) -> "SourceCatalog":
        ids = [source.source_id for source in self.sources]
        paths = [source.local_path for source in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("catalog source ids must be unique")
        if len(paths) != len(set(paths)):
            raise ValueError("catalog local paths must be unique")
        return self


class LockEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str
    url: str
    local_path: str
    categories: tuple[str, ...]
    transform: str
    weight: float
    max_entries: int

    raw_sha256: str
    normalized_sha256: str
    raw_bytes: int = Field(ge=0)
    normalized_bytes: int = Field(ge=0)
    normalized_entries: int = Field(ge=0)

    synced_at: str
    license: str | None = None
    upstream: str | None = None


class LockFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1)
    sources: tuple[LockEntry, ...] = ()


class DownloadResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_sha256: str
    raw_bytes: int
    temporary_path: Path


class SyncResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    entry: LockEntry
    changed: bool


class StrictRedirectHandler(HTTPRedirectHandler):
    """Allow HTTPS redirects only to explicitly trusted hosts."""

    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self.allowed_hosts = {host.lower().rstrip(".") for host in allowed_hosts}

    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> Request | None:
        parts = urlsplit(newurl)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme != "https" or host not in self.allowed_hosts:
            raise HTTPError(
                req.full_url,
                code,
                f"blocked redirect to untrusted wordlist host: {newurl}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_from_root(root: Path, value: Path) -> Path:
    return value if value.is_absolute() else (root / value)


def read_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_catalog(path: Path) -> SourceCatalog:
    document = read_yaml(path)
    if not isinstance(document, dict):
        raise ValueError("wordlist catalog root must be a mapping")
    return SourceCatalog.model_validate(document)


def load_lock(path: Path) -> LockFile:
    if not path.is_file():
        return LockFile()
    document = read_yaml(path)
    if not isinstance(document, dict):
        raise ValueError("wordlist lock root must be a mapping")
    return LockFile.model_validate(document)


def atomic_write_text(path: Path, text: str, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def download_source(source: CatalogSource, *, temporary_directory: Path) -> DownloadResult:
    parts = urlsplit(source.url)
    original_host = (parts.hostname or "").lower().rstrip(".")
    allowed_hosts = {original_host, *source.allowed_redirect_hosts}
    opener = build_opener(StrictRedirectHandler(allowed_hosts))

    request = Request(
        source.url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain, application/octet-stream;q=0.8, */*;q=0.1",
        },
        method="GET",
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f"nightscout-{source.source_id.replace('.', '-')}-",
        dir=temporary_directory,
    )
    os.close(fd)
    temporary = Path(temporary_name)

    digest = hashlib.sha256()
    size = 0

    try:
        try:
            response = opener.open(request, timeout=45.0)
        except (HTTPError, URLError) as exc:
            raise RuntimeError(f"download failed for {source.source_id}: {exc}") from exc

        with response, temporary.open("wb") as output:
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared = int(content_length)
                except ValueError:
                    declared = None
                if declared is not None and declared > source.max_bytes:
                    raise RuntimeError(
                        f"source {source.source_id} exceeds max_bytes before download: "
                        f"{declared} > {source.max_bytes}"
                    )

            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > source.max_bytes:
                    raise RuntimeError(
                        f"source {source.source_id} exceeded max_bytes while downloading"
                    )
                digest.update(chunk)
                output.write(chunk)

        raw_sha256 = digest.hexdigest()

        with temporary.open("rb") as prefix_handle:
            prefix = prefix_handle.read(2048).lstrip().lower()
        if prefix.startswith((b"<!doctype html", b"<html", b"<?xml")):
            raise RuntimeError(
                f"source {source.source_id} returned markup instead of a wordlist"
            )

        if source.expected_sha256 and raw_sha256 != source.expected_sha256:
            raise RuntimeError(
                f"SHA-256 mismatch for {source.source_id}: "
                f"expected {source.expected_sha256}, got {raw_sha256}"
            )

        return DownloadResult(
            raw_sha256=raw_sha256,
            raw_bytes=size,
            temporary_path=temporary,
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def iter_text_lines(path: Path) -> Iterable[str]:
    with path.open("rb") as handle:
        for raw_line in handle:
            if len(raw_line) > MAX_LINE_BYTES:
                continue
            if b"\x00" in raw_line:
                continue
            try:
                line = raw_line.decode("utf-8")
            except UnicodeDecodeError:
                line = raw_line.decode("utf-8", errors="ignore")
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            yield line


def normalize_word(value: str) -> str | None:
    normalized = value.strip().lower().lstrip(".")
    if not normalized or len(normalized) < 2 or len(normalized) > 128:
        return None
    if normalized.isdigit() and len(normalized) > 6:
        return None
    if _SAFE_WORD_RE.fullmatch(normalized) is None:
        return None
    return normalized


def transform_words(line: str) -> Iterable[str]:
    token = normalize_word(line)
    if token is not None:
        yield token


def transform_parameter_names(line: str) -> Iterable[str]:
    value = line.strip()
    if len(value) <= 128 and _SAFE_PARAMETER_RE.fullmatch(value):
        yield value


def transform_dns_labels(line: str) -> Iterable[str]:
    value = line.strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]

    # URL-like accidental input: keep hostname only.
    if "://" in value:
        value = (urlsplit(value).hostname or "").lower().rstrip(".")

    labels = [part for part in value.split(".") if part]
    if len(labels) > 1:
        # Drop only the right-most label as a conservative TLD-like component.
        labels = labels[:-1]

    for label in labels or [value]:
        normalized = normalize_word(label)
        if normalized is not None:
            yield normalized
        for piece in label.split("-"):
            normalized_piece = normalize_word(piece)
            if normalized_piece is not None:
                yield normalized_piece


def transform_path_tokens(line: str) -> Iterable[str]:
    value = line.strip()
    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.path
        if parsed.query:
            value = f"{value}?{parsed.query}"

    # Parameter values are not useful corpus material; names are.
    if "?" in value:
        path_part, query = value.split("?", 1)
        value = path_part
        for pair in query.split("&"):
            name = pair.split("=", 1)[0].strip()
            token = normalize_word(name)
            if token is not None:
                yield token

    for coarse in value.split("/"):
        for piece in _SPLIT_PATH_RE.split(coarse):
            token = normalize_word(piece)
            if token is not None:
                yield token


TRANSFORMS = {
    SourceTransform.WORDS: transform_words,
    SourceTransform.DNS_LABELS: transform_dns_labels,
    SourceTransform.PARAMETER_NAMES: transform_parameter_names,
    SourceTransform.PATH_TOKENS: transform_path_tokens,
}


def normalize_download(source: CatalogSource, downloaded: DownloadResult) -> tuple[bytes, int]:
    transform = TRANSFORMS[source.transform]
    seen: set[str] = set()
    output: list[str] = []

    for line in iter_text_lines(downloaded.temporary_path):
        for token in transform(line):
            dedupe_key = token if "parameter" in source.categories else token.lower()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            output.append(token)
            if len(output) >= source.max_entries:
                break
        if len(output) >= source.max_entries:
            break

    if not output:
        raise RuntimeError(
            f"source {source.source_id} produced zero usable entries after {source.transform}"
        )

    payload = ("\n".join(output) + "\n").encode("utf-8")
    return payload, len(output)


def sync_source(root: Path, source: CatalogSource, existing: LockEntry | None) -> SyncResult:
    wordlists_root = root / "wordlists"
    destination = (wordlists_root / source.local_path).resolve()
    destination.relative_to(wordlists_root.resolve())

    temporary_directory = wordlists_root / "generated"
    temporary_directory.mkdir(parents=True, exist_ok=True)

    download = download_source(source, temporary_directory=temporary_directory)
    try:
        payload, entry_count = normalize_download(source, download)
    finally:
        download.temporary_path.unlink(missing_ok=True)

    normalized_sha256 = hashlib.sha256(payload).hexdigest()
    changed = (
        existing is None
        or existing.raw_sha256 != download.raw_sha256
        or existing.normalized_sha256 != normalized_sha256
        or not destination.is_file()
    )

    if changed:
        atomic_write_bytes(destination, payload)

    entry = LockEntry(
        source_id=source.source_id,
        url=source.url,
        local_path=source.local_path,
        categories=source.categories,
        transform=source.transform,
        weight=source.weight,
        max_entries=source.max_entries,
        raw_sha256=download.raw_sha256,
        normalized_sha256=normalized_sha256,
        raw_bytes=download.raw_bytes,
        normalized_bytes=len(payload),
        normalized_entries=entry_count,
        synced_at=(
            existing.synced_at
            if (
                existing is not None
                and existing.raw_sha256 == download.raw_sha256
                and existing.normalized_sha256 == normalized_sha256
            )
            else utc_now_iso()
        ),
        license=source.license,
        upstream=source.upstream,
    )

    return SyncResult(entry=entry, changed=changed)


def write_lock(path: Path, entries: Sequence[LockEntry]) -> None:
    document = {
        "version": 1,
        "sources": [entry.model_dump(mode="json") for entry in sorted(entries, key=lambda e: e.source_id)],
    }
    atomic_write_text(path, yaml.safe_dump(document, sort_keys=False, allow_unicode=True))


def build_local_manifest(
    root: Path,
    *,
    base_manifest_path: Path,
    lock_path: Path,
    output_path: Path,
) -> WordlistManifest:
    base_document = read_yaml(base_manifest_path)
    if not isinstance(base_document, dict):
        raise ValueError("base wordlist manifest must be a mapping")
    base = WordlistManifest.model_validate(base_document)
    lock = load_lock(lock_path)

    sources: list[dict[str, Any]] = [
        source.model_dump(by_alias=True, mode="json")
        for source in base.sources
        if source.enabled
    ]

    wordlists_root = (root / "wordlists").resolve()

    for entry in sorted(lock.sources, key=lambda item: item.source_id):
        path = (wordlists_root / entry.local_path).resolve()
        path.relative_to(wordlists_root)
        if not path.is_file():
            continue
        if sha256_file(path) != entry.normalized_sha256:
            raise RuntimeError(
                f"local wordlist hash does not match lock: {entry.source_id}; run verify/sync"
            )

        sources.append(
            {
                "id": entry.source_id,
                "path": entry.local_path,
                "categories": list(entry.categories),
                "weight": entry.weight,
                "enabled": True,
                "max_entries": entry.max_entries,
                "metadata": {
                    "external": True,
                    "upstream_url": entry.url,
                    "upstream": entry.upstream,
                    "license": entry.license,
                    "transform": entry.transform,
                    "raw_sha256": entry.raw_sha256,
                    "normalized_sha256": entry.normalized_sha256,
                    "synced_at": entry.synced_at,
                },
            }
        )

    manifest_document = {"version": 1, "sources": sources}
    manifest = WordlistManifest.model_validate(manifest_document)
    atomic_write_text(
        output_path,
        yaml.safe_dump(
            manifest.model_dump(by_alias=True, mode="json"),
            sort_keys=False,
            allow_unicode=True,
        ),
    )
    return manifest


def verify_lock(root: Path, lock_path: Path) -> tuple[int, list[str]]:
    wordlists_root = (root / "wordlists").resolve()
    lock = load_lock(lock_path)
    failures: list[str] = []
    verified = 0

    for entry in lock.sources:
        path = (wordlists_root / entry.local_path).resolve()
        try:
            path.relative_to(wordlists_root)
        except ValueError:
            failures.append(f"{entry.source_id}: path escapes wordlists root")
            continue

        if not path.is_file():
            failures.append(f"{entry.source_id}: missing {path}")
            continue

        digest = sha256_file(path)
        if digest != entry.normalized_sha256:
            failures.append(
                f"{entry.source_id}: SHA-256 mismatch, expected {entry.normalized_sha256}, got {digest}"
            )
            continue

        verified += 1

    return verified, failures


def select_sources(
    catalog: SourceCatalog,
    *,
    requested: Sequence[str],
    all_sources: bool,
) -> tuple[CatalogSource, ...]:
    by_id = {source.source_id: source for source in catalog.sources}

    if all_sources:
        return catalog.sources

    if requested:
        missing = sorted(set(requested) - set(by_id))
        if missing:
            raise ValueError(f"unknown wordlist source ids: {', '.join(missing)}")
        return tuple(by_id[source_id] for source_id in requested)

    return tuple(source for source in catalog.sources if source.default)


def command_list(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    catalog_path = resolve_from_root(root, Path(args.catalog))
    lock_path = resolve_from_root(root, Path(args.lock))
    catalog = load_catalog(catalog_path)
    lock = {entry.source_id: entry for entry in load_lock(lock_path).sources}

    print("ID\tDEFAULT\tINSTALLED\tENTRIES\tCATEGORIES")
    for source in catalog.sources:
        entry = lock.get(source.source_id)
        path = root / "wordlists" / source.local_path
        installed = entry is not None and path.is_file()
        count = str(entry.normalized_entries) if entry is not None else "-"
        print(
            f"{source.source_id}\t{'yes' if source.default else 'no'}\t"
            f"{'yes' if installed else 'no'}\t{count}\t{','.join(source.categories)}"
        )
    return 0


def command_verify(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    lock_path = resolve_from_root(root, Path(args.lock))
    verified, failures = verify_lock(root, lock_path)
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    print(f"verified={verified} failed={len(failures)}")
    return 1 if failures else 0


def command_build_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    manifest = build_local_manifest(
        root,
        base_manifest_path=resolve_from_root(root, Path(args.base_manifest)),
        lock_path=resolve_from_root(root, Path(args.lock)),
        output_path=resolve_from_root(root, Path(args.output)),
    )
    print(f"generated {args.output} with {len(manifest.sources)} sources")
    return 0


def command_sync(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    catalog_path = resolve_from_root(root, Path(args.catalog))
    lock_path = resolve_from_root(root, Path(args.lock))
    catalog = load_catalog(catalog_path)
    selected = select_sources(
        catalog,
        requested=tuple(args.source or ()),
        all_sources=bool(args.all),
    )

    if not selected:
        print("No sources selected.")
        return 0

    existing_lock = load_lock(lock_path)
    entries = {entry.source_id: entry for entry in existing_lock.sources}

    for index, source in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {source.source_id}")
        result = sync_source(root, source, entries.get(source.source_id))
        entries[source.source_id] = result.entry
        print(
            f"  {'updated' if result.changed else 'unchanged'} "
            f"entries={result.entry.normalized_entries} "
            f"raw_sha256={result.entry.raw_sha256[:12]}… "
            f"normalized_sha256={result.entry.normalized_sha256[:12]}…"
        )
        write_lock(lock_path, tuple(entries.values()))

        if args.sleep > 0 and index < len(selected):
            time.sleep(args.sleep)

    if not args.no_manifest:
        manifest = build_local_manifest(
            root,
            base_manifest_path=resolve_from_root(root, Path(args.base_manifest)),
            lock_path=lock_path,
            output_path=resolve_from_root(root, Path(args.output)),
        )
        print(f"generated {args.output} with {len(manifest.sources)} sources")

    return 0


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wordlists_sync.py",
        description="Explicit Night Scout public-wordlist synchronization",
    )
    parser.add_argument("--root", default=str(project_root()))
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG))
    parser.add_argument("--lock", default=str(DEFAULT_LOCK))

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="show catalog/install state")
    list_parser.set_defaults(handler=command_list)

    verify_parser = subparsers.add_parser("verify", help="verify installed files against lock")
    verify_parser.set_defaults(handler=command_verify)

    build_parser = subparsers.add_parser("build-manifest", help="regenerate local runtime manifest")
    build_parser.add_argument("--base-manifest", default=str(DEFAULT_BASE_MANIFEST))
    build_parser.add_argument("--output", default=str(DEFAULT_GENERATED_MANIFEST))
    build_parser.set_defaults(handler=command_build_manifest)

    sync_parser = subparsers.add_parser("sync", help="download/update selected public sources")
    sync_parser.add_argument("--source", action="append", help="exact source id; repeatable")
    sync_parser.add_argument("--all", action="store_true", help="include large/optional sources")
    sync_parser.add_argument("--base-manifest", default=str(DEFAULT_BASE_MANIFEST))
    sync_parser.add_argument("--output", default=str(DEFAULT_GENERATED_MANIFEST))
    sync_parser.add_argument("--no-manifest", action="store_true")
    sync_parser.add_argument(
        "--sleep",
        type=float,
        default=0.25,
        help="polite delay between upstream downloads",
    )
    sync_parser.set_defaults(handler=command_sync)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
