from __future__ import annotations

import hashlib

from recon.workers.nuclei import NucleiTemplateManifestEntry, audit_nuclei_template


def entry_for(path, cve="CVE-2025-12345"):
    return NucleiTemplateManifestEntry(
        cve_id=cve,
        template_id=cve,
        path=path.name,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        audited=True,
        audit_note="test fixture",
        max_requests=2,
        require_signed=True,
    )


def test_safe_get_template_allowed_and_active_features_denied(tmp_path):
    safe = tmp_path / "safe.yaml"
    safe.write_text(
        """id: CVE-2025-12345\ninfo:\n  name: Fixture\n  author: tests\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/version\"\n    matchers:\n      - type: status\n        status: [200]\n""",
        encoding="utf-8",
    )
    audit = audit_nuclei_template(safe, entry=entry_for(safe), max_template_bytes=1024 * 1024, max_requests=3)
    assert audit.allowed
    assert audit.request_count == 1

    variants = {
        "post": safe.read_text().replace("method: GET", "method: POST"),
        "oast": safe.read_text().replace("{{BaseURL}}/version", "{{BaseURL}}/{{interactsh-url}}"),
        "payload": safe.read_text().replace("    matchers:", "    payloads:\n      x: [a,b]\n    matchers:"),
        "host": safe.read_text().replace("    matchers:", "    headers:\n      Host: other.example.com\n    matchers:"),
    }
    for name, text in variants.items():
        path = tmp_path / f"{name}.yaml"
        path.write_text(text, encoding="utf-8")
        bad = audit_nuclei_template(path, entry=entry_for(path), max_template_bytes=1024 * 1024, max_requests=3)
        assert not bad.allowed, name


def test_template_hash_pin_is_mandatory(tmp_path):
    path = tmp_path / "safe.yaml"
    path.write_text(
        """id: CVE-2025-12345\ninfo:\n  name: Fixture\n  author: tests\n  severity: info\nhttp:\n  - method: HEAD\n    path: [\"{{BaseURL}}/\"]\n""",
        encoding="utf-8",
    )
    entry = entry_for(path).model_copy(update={"sha256": "0" * 64})
    assert not audit_nuclei_template(path, entry=entry, max_template_bytes=1024 * 1024, max_requests=3).allowed
