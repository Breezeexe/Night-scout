from __future__ import annotations

import hashlib
import shutil
import zipfile
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from recon.core.events import Event, EventType, ScopeState
from recon.core.queue import TaskStatus
from recon.runtime import RuntimeMobileArtifactInput, build_runtime
from recon.storage.models import EventObservationRecord, ReconRunRecord
from recon.workers.mobile import (
    MobileArtifactKind,
    WorkspaceMobileArtifactProvider,
    WorkspaceMobileArtifactStore,
)


def _write_apk(path: Path, *, package_name: str = "com.company.mobile") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            f'<manifest package="{package_name}"></manifest>',
        )
        archive.writestr("assets/config.txt", "https://api.company.example/v1/")


def _write_mobile_project(
    root: Path,
    project_root: Path,
    *,
    scope_state: str = "IN_SCOPE",
) -> tuple[Path, Path]:
    (root / "configs").mkdir(parents=True)
    shutil.copy(project_root / "pyproject.toml", root / "pyproject.toml")

    scope = {
        "schema_version": 1,
        "target_id": "company-mobile",
        "display_name": "Company Mobile",
        "gate": {"allow_unknown_passive": False},
        "rules": [
            {
                "rule_id": "company-domain",
                "kind": "DOMAIN",
                "pattern": "company.example",
                "state": "IN_SCOPE",
                "priority": 90,
                "tier": "bounty",
                "reason": "test fixture",
            },
            {
                "rule_id": "company-android",
                "kind": "MOBILE_APP",
                "pattern": "com.company.mobile",
                "state": scope_state,
                "priority": 100,
                "tier": "bounty",
                "reason": "test fixture",
            }
        ],
    }
    scope_path = root / "configs" / "scope.yaml"
    scope_path.write_text(yaml.safe_dump(scope, sort_keys=False), encoding="utf-8")

    pipeline = yaml.safe_load((project_root / "configs" / "pipeline.example.yaml").read_text())
    pipeline["scope_file"] = "scope.yaml"
    pipeline["storage"]["database"]["path"] = "workspace.sqlite3"
    pipeline["storage"]["event_log"]["enabled"] = False
    pipeline["runtime"] = {
        "max_steps": 10,
        "project_vocabulary": False,
        "vulnerability_enrichment": False,
        "snapshot_capture": False,
        "snapshot_diff_on_write": False,
        "build_genome_on_finish": False,
    }
    pipeline["routing"]["enabled_rule_ids"] = ["mobile.analyze.local-artifact"]
    for worker in pipeline["workers"].values():
        worker["enabled"] = False
    pipeline["workers"]["mobile"]["enabled"] = True
    mobile_config = pipeline["workers"]["mobile"]["config"]
    mobile_config["enable_jadx"] = False
    mobile_config["enable_apktool_fallback"] = False
    mobile_config["enable_builtin_secret_scan"] = False
    mobile_config["enable_gitleaks"] = False
    mobile_config["enable_trufflehog"] = False
    mobile_config["preserve_raw_secret_evidence"] = False

    pipeline_path = root / "configs" / "pipeline.yaml"
    pipeline_path.write_text(yaml.safe_dump(pipeline, sort_keys=False), encoding="utf-8")
    return pipeline_path, scope_path


@pytest.mark.asyncio
async def test_workspace_mobile_artifact_store_is_content_addressed_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    source = tmp_path / "company.apk"
    _write_apk(source)
    store = WorkspaceMobileArtifactStore(
        tmp_path / "artifacts",
        max_artifact_bytes=1024 * 1024,
    )

    first = await store.import_file(source)
    second = await store.import_file(source)

    expected_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    assert first == second
    assert first.kind is MobileArtifactKind.APK
    assert first.sha256 == expected_sha256
    assert first.artifact_ref == f"{expected_sha256}.apk"
    assert first.path.read_bytes() == source.read_bytes()
    assert first.path.stat().st_mode & 0o777 == 0o400
    assert store.root.stat().st_mode & 0o777 == 0o700

    link = tmp_path / "linked.apk"
    link.symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        await store.import_file(link)

    provider = WorkspaceMobileArtifactProvider(store.root)
    event = Event(
        type=EventType.MOBILE_ARTIFACT,
        value=f"com.company.mobile@sha256:{first.sha256}",
        source="test:mobile-import",
        tags={"local"},
        metadata={
            "artifact_ref": first.artifact_ref,
            "artifact_kind": first.kind.value,
            "artifact_sha256": first.sha256,
            "artifact_size_bytes": first.size_bytes,
            "app_id": "com.company.mobile",
        },
    )
    assert await provider.material_for(event) is not None

    first.path.chmod(0o600)
    first.path.write_bytes(b"modified after import")
    assert await provider.material_for(event) is None


@pytest.mark.asyncio
async def test_runtime_combines_domain_and_mobile_seeds_in_one_frontier(
    tmp_path: Path,
    project_root: Path,
) -> None:
    root = tmp_path / "project"
    pipeline_path, scope_path = _write_mobile_project(root, project_root)
    source = tmp_path / "company.apk"
    _write_apk(source)

    runtime = await build_runtime(pipeline_path=pipeline_path, scope_path=scope_path)
    try:
        summary = await runtime.run_domains(
            (),
            mobile_artifact=RuntimeMobileArtifactInput(
                artifact_path=source,
                app_id="com.company.mobile",
                source_url=(
                    "https://play.google.com/store/apps/details?id=com.company.mobile"
                ),
            ),
            max_steps=5,
        )
        domain_seed, mobile_seed = summary.seeds
        event = await runtime.events.get_event(mobile_seed.seed_event_id)
        tasks = await runtime.task_store.all()
        async with runtime.database.session() as session:
            observations = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).where(
                            EventObservationRecord.event_id.in_(
                                [domain_seed.seed_event_id, mobile_seed.seed_event_id]
                            )
                        )
                    )
                ).all()
            )
            runs = list((await session.scalars(select(ReconRunRecord))).all())
    finally:
        await runtime.close()

    assert summary.status == "SUCCEEDED"
    assert [seed.mode for seed in summary.seeds] == ["EXACT", "MOBILE_ARTIFACT"]
    assert all(seed.scope_state is ScopeState.IN_SCOPE for seed in summary.seeds)
    assert summary.outcomes["SUCCEEDED"] == 1
    assert summary.steps == 1
    assert len(runs) == 1
    assert runs[0].run_id == summary.run_id
    assert runs[0].metadata_json["run_kind"] == "mixed"
    assert runs[0].metadata_json["seed_count"] == 2
    assert {observation.run_id for observation in observations} == {summary.run_id}
    assert event is not None
    assert event.type is EventType.MOBILE_ARTIFACT
    assert event.scope_state is ScopeState.IN_SCOPE
    assert event.metadata["app_id"] == "com.company.mobile"
    assert event.metadata["source_url"].startswith("https://play.google.com/")
    assert event.metadata["network_request_performed"] is False
    assert len(tasks) == 1
    assert tasks[0].worker == "mobile"
    assert tasks[0].action == "analyze"
    assert tasks[0].status is TaskStatus.SUCCEEDED

    imported = (
        root
        / "workspaces"
        / "company-mobile"
        / ".nightscout"
        / "artifacts"
        / str(mobile_seed.artifact_ref)
    )
    assert imported.is_file()
    assert imported.read_bytes() == source.read_bytes()


@pytest.mark.asyncio
async def test_runtime_mobile_seed_fails_closed_before_copying_out_of_scope_app(
    tmp_path: Path,
    project_root: Path,
) -> None:
    root = tmp_path / "project"
    pipeline_path, scope_path = _write_mobile_project(
        root,
        project_root,
        scope_state="OUT_OF_SCOPE",
    )
    source = tmp_path / "company.apk"
    _write_apk(source)

    runtime = await build_runtime(pipeline_path=pipeline_path, scope_path=scope_path)
    try:
        with pytest.raises(ValueError, match="OUT_OF_SCOPE"):
            await runtime.run_domains(
                (),
                mobile_artifact=RuntimeMobileArtifactInput(
                    artifact_path=source,
                    app_id="com.company.mobile",
                ),
            )
    finally:
        await runtime.close()

    artifact_root = root / "workspaces" / "company-mobile" / ".nightscout" / "artifacts"
    assert not artifact_root.exists() or not any(artifact_root.iterdir())
