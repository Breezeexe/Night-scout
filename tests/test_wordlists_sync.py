from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from recon.intelligence.wordlists import ManifestGlobalCorpus, WordlistManifest
from scripts.wordlists_sync import (
    CatalogSource,
    LockEntry,
    build_local_manifest,
    select_sources,
    transform_dns_labels,
    transform_path_tokens,
    write_lock,
)


def test_bundled_wordlist_manifest_loads() -> None:
    root = Path(__file__).resolve().parents[1]
    corpus = ManifestGlobalCorpus(
        root / "wordlists" / "manifest.yaml",
        corpus_root=root / "wordlists",
    )
    manifest = corpus.load_manifest()

    assert len(manifest.sources) == 3
    assert all(source.enabled for source in manifest.sources)
    assert {source.source_id for source in manifest.sources} == {
        "nightscout.builtin.core",
        "nightscout.builtin.parameters",
        "nightscout.builtin.api",
    }


def test_catalog_rejects_insecure_url_and_path_escape() -> None:
    base = {
        "id": "test.source",
        "local_path": "cache/test.txt",
        "categories": ["dns"],
        "transform": "dns_labels",
    }

    try:
        CatalogSource.model_validate({**base, "url": "http://example.com/test.txt"})
    except ValidationError:
        pass
    else:
        raise AssertionError("HTTP source must be rejected")

    try:
        CatalogSource.model_validate(
            {
                **base,
                "url": "https://example.com/test.txt",
                "local_path": "../escape.txt",
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("path traversal must be rejected")


def test_transforms_drop_query_values_and_tld() -> None:
    path_tokens = set(transform_path_tokens("/api/v2/orders?tenantId=SECRET&debug=true"))

    assert {"api", "v2", "orders", "tenantid", "debug"} <= path_tokens
    assert "secret" not in path_tokens
    assert "true" not in path_tokens

    dns_tokens = set(transform_dns_labels("warehouse-api.preprod.example.com"))
    assert "warehouse-api" in dns_tokens
    assert "warehouse" in dns_tokens
    assert "api" in dns_tokens
    assert "preprod" in dns_tokens
    assert "com" not in dns_tokens


def test_generated_manifest_uses_locked_local_file(tmp_path: Path) -> None:
    root = tmp_path
    wordlists = root / "wordlists"
    (wordlists / "builtins").mkdir(parents=True)
    (wordlists / "cache" / "test").mkdir(parents=True)
    (wordlists / "generated").mkdir(parents=True)

    builtin = wordlists / "builtins" / "core.txt"
    builtin.write_text("admin\napi\n", encoding="utf-8")

    base_manifest = wordlists / "manifest.yaml"
    base_manifest.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "sources": [
                    {
                        "id": "nightscout.builtin.core",
                        "path": "builtins/core.txt",
                        "categories": ["general", "dns"],
                        "enabled": True,
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    external = wordlists / "cache" / "test" / "dns.txt"
    payload = b"admin\nportal\n"
    external.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    lock_path = wordlists / "generated" / "sources.lock.yaml"
    write_lock(
        lock_path,
        (
            LockEntry(
                source_id="test.dns",
                url="https://example.com/dns.txt",
                local_path="cache/test/dns.txt",
                categories=("dns", "vhost"),
                transform="dns_labels",
                weight=1.0,
                max_entries=100,
                raw_sha256="1" * 64,
                normalized_sha256=digest,
                raw_bytes=len(payload),
                normalized_bytes=len(payload),
                normalized_entries=2,
                synced_at="2026-08-19T00:00:00+00:00",
            ),
        ),
    )

    output = wordlists / "generated" / "manifest.local.yaml"
    manifest = build_local_manifest(
        root,
        base_manifest_path=base_manifest,
        lock_path=lock_path,
        output_path=output,
    )

    assert isinstance(manifest, WordlistManifest)
    assert {source.source_id for source in manifest.sources} == {
        "nightscout.builtin.core",
        "test.dns",
    }

    loaded = ManifestGlobalCorpus(output, corpus_root=wordlists).load_manifest()
    external_source = next(source for source in loaded.sources if source.source_id == "test.dns")
    assert external_source.metadata["normalized_sha256"] == digest
    assert external_source.path == "cache/test/dns.txt"


def test_source_selection_defaults_and_all() -> None:
    first = CatalogSource.model_validate(
        {
            "id": "first",
            "url": "https://example.com/first.txt",
            "local_path": "cache/first.txt",
            "categories": ["dns"],
            "transform": "dns_labels",
            "default": True,
        }
    )
    second = CatalogSource.model_validate(
        {
            "id": "second",
            "url": "https://example.com/second.txt",
            "local_path": "cache/second.txt",
            "categories": ["path"],
            "transform": "words",
            "default": False,
        }
    )

    class Catalog:
        sources = (first, second)

    defaults = select_sources(Catalog(), requested=(), all_sources=False)  # type: ignore[arg-type]
    assert defaults == (first,)

    everything = select_sources(Catalog(), requested=(), all_sources=True)  # type: ignore[arg-type]
    assert everything == (first, second)
