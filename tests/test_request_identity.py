from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from sqlalchemy import select

from recon.policy.request_identity import RequestIdentityPolicy
from recon.runtime import build_runtime, doctor_from_files
from recon.storage.models import ReconRunRecord
from recon.workers.content import HttpxContentBackend
from recon.workers.crawler import KatanaBackend, KatanaPacing
from recon.workers.http import HttpxBackend
from recon.workers.nuclei import (
    AuditedNucleiTemplate,
    NucleiBackend,
    NucleiPacing,
    NucleiTemplateManifestEntry,
    audit_nuclei_template,
)
from recon.workers.parameters import (
    ArjunBackend,
    ArjunPacing,
    ParameterDiscoveryConfig,
)
from recon.workers.vhost import HttpxVHostBackend


@pytest.fixture
def identity() -> RequestIdentityPolicy:
    return RequestIdentityPolicy(
        http_headers={
            "X_Bug_Bounty": "test-researcher",
            "X-Research-Program": "company",
        }
    )


def _assert_repeated_header_args(command: tuple[str, ...]) -> None:
    assert command.count("X_Bug_Bounty: test-researcher") == 1
    assert command.count("X-Research-Program: company") == 1


def test_request_identity_rejects_reserved_duplicate_and_injected_headers() -> None:
    for headers in (
        {"Host": "other.example"},
        {"Authorization": "Bearer fixture"},
        {"Cookie": "session=fixture"},
        {"Content-Length": "0"},
        {"X_Bug_Bounty": "test-researcher\r\nX-Injected: true"},
        {"X_Bug_Bounty": "one", "x_bug_bounty": "two"},
    ):
        with pytest.raises(ValidationError):
            RequestIdentityPolicy(http_headers=headers)


def test_projectdiscovery_backends_receive_program_headers(
    identity: RequestIdentityPolicy,
    tmp_path: Path,
) -> None:
    commands = (
        HttpxBackend(request_identity=identity).command_for(rate_limit_rps=30),
        HttpxContentBackend(request_identity=identity).command_for(rate_limit_rps=30),
        KatanaBackend(request_identity=identity).command_for(
            pacing=KatanaPacing(host_rps=30)
        ),
        HttpxVHostBackend(request_identity=identity).command_for(
            host_header="internal.company.example",
            rate_limit_rps=30,
        ),
        NucleiBackend(request_identity=identity).command_for(
            target_url="https://company.example",
            template=AuditedNucleiTemplate(
                cve_id="CVE-2025-12345",
                template_id="CVE-2025-12345",
                path=tmp_path / "template.yaml",
                sha256="a" * 64,
                request_count=1,
                request_paths=("{{BaseURL}}/",),
            ),
            pacing=NucleiPacing(requests=30, duration="1s"),
            isolated_config=tmp_path / "nuclei-empty-config.yaml",
        ),
    )

    for command in commands:
        _assert_repeated_header_args(command)
        assert command.count("-H") >= 2


def test_arjun_receives_validated_headers_as_one_block(
    identity: RequestIdentityPolicy,
    tmp_path: Path,
) -> None:
    command = ArjunBackend(request_identity=identity).command_for(
        target_url="https://company.example/api",
        wordlist_path=tmp_path / "words.txt",
        output_path=tmp_path / "result.json",
        pacing=ArjunPacing(requests_per_second=30),
        discovery=ParameterDiscoveryConfig(),
    )

    index = command.index("--headers")
    assert command[index + 1] == (
        "X_Bug_Bounty: test-researcher\nX-Research-Program: company"
    )


def test_nuclei_template_cannot_override_program_identity_header(
    identity: RequestIdentityPolicy,
    tmp_path: Path,
) -> None:
    path = tmp_path / "template.yaml"
    path.write_text(
        """id: CVE-2025-12345
info:
  name: Fixture
  author: tests
  severity: info
http:
  - method: GET
    headers:
      x_bug_bounty: attacker-controlled
    path: ["{{BaseURL}}/"]
""",
        encoding="utf-8",
    )
    entry = NucleiTemplateManifestEntry(
        cve_id="CVE-2025-12345",
        template_id="CVE-2025-12345",
        path=path.name,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        max_requests=1,
    )

    audit = audit_nuclei_template(
        path,
        entry=entry,
        max_template_bytes=1024 * 1024,
        max_requests=1,
        protected_header_names=identity.header_names,
    )

    assert not audit.allowed
    assert any("protected identification header" in reason for reason in audit.reasons)


def test_default_policy_does_not_add_identification_headers() -> None:
    command = HttpxBackend().command_for(rate_limit_rps=30)

    assert "X_Bug_Bounty: test-researcher" not in command


def test_doctor_reports_header_names_but_redacts_values(
    tmp_path: Path,
    project_root: Path,
) -> None:
    project = tmp_path / "project"
    configs = project / "configs"
    configs.mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", project / "pyproject.toml")

    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text(encoding="utf-8")
    )
    pipeline["scope_file"] = "scope.yaml"
    for worker in pipeline["workers"].values():
        worker["enabled"] = False

    scope = yaml.safe_load(
        (project_root / "configs" / "scope.example.yaml").read_text(encoding="utf-8")
    )
    pipeline_path = configs / "pipeline.yaml"
    scope_path = configs / "scope.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")
    scope_path.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")

    report = doctor_from_files(
        pipeline_path=pipeline_path,
        scope_path=scope_path,
        request_identity=RequestIdentityPolicy(
            http_headers={"X_Bug_Bounty": "test-researcher"}
        ),
    )
    check = next(item for item in report.checks if item.name == "request-identity")

    assert check.ok
    assert check.required
    assert "X_Bug_Bounty" in check.detail
    assert "test-researcher" not in check.detail
    assert "values=redacted" in check.detail


@pytest.mark.asyncio
async def test_runtime_binds_one_identity_policy_to_every_target_http_worker(
    tmp_path: Path,
    project_root: Path,
) -> None:
    project = tmp_path / "runtime-project"
    configs = project / "configs"
    configs.mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", project / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        configs / "scope.yaml",
    )
    shutil.copy(
        project_root / "configs" / "nuclei-templates.example.yaml",
        configs / "nuclei-templates.example.yaml",
    )

    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text(encoding="utf-8")
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "identity.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "snapshot_diff_on_write": False,
            "build_genome_on_finish": False,
        }
    )
    target_workers = {"http", "content", "crawler", "parameters", "vhost", "nuclei"}
    for name, worker in pipeline["workers"].items():
        worker["enabled"] = name in target_workers

    pipeline_path = configs / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")

    identity = RequestIdentityPolicy(
        http_headers={"X_Bug_Bounty": "test-researcher"}
    )
    runtime = await build_runtime(
        pipeline_path=pipeline_path,
        request_identity=identity,
    )
    try:
        assert target_workers <= runtime.workers.keys()
        for name in target_workers:
            backend = runtime.workers[name]._backend
            assert backend.request_identity is runtime.request_identity

        catalog = runtime.workers["nuclei"]._templates
        assert catalog.protected_header_names == frozenset({"x_bug_bounty"})
    finally:
        await runtime.close()


@pytest.mark.asyncio
async def test_unfinished_frontier_requires_same_cli_identity_on_resume(
    tmp_path: Path,
    project_root: Path,
) -> None:
    project = tmp_path / "resume-project"
    configs = project / "configs"
    configs.mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", project / "pyproject.toml")
    shutil.copy(
        project_root / "configs" / "scope.example.yaml",
        configs / "scope.yaml",
    )

    pipeline = yaml.safe_load(
        (project_root / "configs" / "pipeline.example.yaml").read_text(encoding="utf-8")
    )
    pipeline["scope_file"] = "configs/scope.yaml"
    pipeline["storage"]["database"]["path"] = "resume.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"].update(
        {
            "project_vocabulary": False,
            "vulnerability_enrichment": False,
            "snapshot_capture": False,
            "snapshot_diff_on_write": False,
            "build_genome_on_finish": False,
        }
    )
    pipeline["routing"]["enabled_rule_ids"] = [
        "permutations.root.targeted",
        "permutations.root.exploration",
    ]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["permutations"]["enabled"] = True

    pipeline_path = configs / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")
    identity = RequestIdentityPolicy(
        http_headers={"X_Bug_Bounty": "test-researcher"}
    )

    first = await build_runtime(
        pipeline_path=pipeline_path,
        request_identity=identity,
    )
    try:
        summary = await first.run_domain("example.com", max_steps=1)
        assert summary.status == "PAUSED"
        assert any(not task.is_terminal for task in await first.task_store.all())
        async with first.database.session() as session:
            run = await session.scalar(
                select(ReconRunRecord).where(ReconRunRecord.run_id == summary.run_id)
            )
        assert run is not None
        assert run.metadata_json["request_identity_header_names"] == ["X_Bug_Bounty"]
        assert run.metadata_json["request_identity_fingerprint"] == identity.fingerprint
        assert "test-researcher" not in json.dumps(run.metadata_json)
    finally:
        await first.close()

    missing = await build_runtime(pipeline_path=pipeline_path)
    try:
        with pytest.raises(RuntimeError, match="same CLI identity"):
            await missing.run_domain("example.com", max_steps=1)
    finally:
        await missing.close()

    matching = await build_runtime(
        pipeline_path=pipeline_path,
        request_identity=identity,
    )
    try:
        resumed = await matching.run_domain("example.com", max_steps=1)
        assert resumed.run_id
    finally:
        await matching.close()
