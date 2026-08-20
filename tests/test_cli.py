from __future__ import annotations

from typer.testing import CliRunner

from recon.cli import app
from recon.runtime import RuntimeProgress


def test_cli_version_and_help():
    runner = CliRunner()
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert "Night Scout" in version.stdout

    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    for command in (
        "setup",
        "doctor",
        "run",
        "status",
        "explain",
        "export",
        "review",
        "workspace",
        "tools",
        "wordlists",
    ):
        assert command in help_result.stdout

    review_help = runner.invoke(app, ["review", "--help"])
    assert review_help.exit_code == 0
    for command in ("list", "show", "approve", "reject"):
        assert command in review_help.stdout

    workspace_help = runner.invoke(app, ["workspace", "--help"])
    assert workspace_help.exit_code == 0
    assert "adopt" in workspace_help.stdout

    adopt_help = runner.invoke(app, ["workspace", "adopt", "--help"])
    assert adopt_help.exit_code == 0
    assert "target_id" in adopt_help.stdout

    run_help = runner.invoke(app, ["run", "--help"])
    assert run_help.exit_code == 0
    assert "target_id selects" in run_help.stdout
    assert "workspace" in run_help.stdout
    assert "--mobile-artifact" in run_help.stdout
    assert "--mobile-app-id" in run_help.stdout
    assert "--mobile-source" in run_help.stdout
    assert "--identity-header" in run_help.stdout
    assert "provenance only" in run_help.stdout

    doctor_help = runner.invoke(app, ["doctor", "--help"])
    assert doctor_help.exit_code == 0
    assert "--identity-header" in doctor_help.stdout

    removed_mobile_command = runner.invoke(app, ["mobile", "--help"])
    assert removed_mobile_command.exit_code != 0


def test_cli_run_combines_domain_and_mobile_ingress(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    calls: dict[str, object] = {}

    class FakeRuntime:
        async def run_domains(self, domains, **kwargs):
            calls["domains"] = domains
            calls.update(kwargs)
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-mobile",
                    "status": "SUCCEEDED",
                    "seeds": [
                        {
                            "seed_event_id": "evt-domain",
                            "target": "company.example",
                            "scope_state": "IN_SCOPE",
                            "mode": "EXPLICIT",
                        },
                        {
                            "seed_event_id": "evt-mobile",
                            "target": "com.company.mobile",
                            "scope_state": "IN_SCOPE",
                            "mode": "MOBILE_ARTIFACT",
                            "artifact_ref": "abc.apk",
                            "artifact_kind": "APK",
                            "artifact_sha256": "a" * 64,
                            "artifact_size_bytes": 123,
                        },
                    ],
                    "steps": 1,
                    "outcomes": {"SUCCEEDED": 1},
                    "task_counts": {"SUCCEEDED": 1},
                    "attempt_counts": {"SUCCEEDED": 1},
                    "event_count": 2,
                    "asset_count": 1,
                    "open_review_cases": 0,
                    "warnings": [],
                }
            )

        async def close(self):
            calls["closed"] = True

    async def fake_build_runtime(**kwargs):
        calls["build"] = kwargs
        return FakeRuntime()

    monkeypatch.setattr("recon.cli.build_runtime", fake_build_runtime)
    artifact = tmp_path / "company.apk"
    artifact.write_bytes(b"fixture")
    scope = tmp_path / "scope.yaml"
    result = CliRunner().invoke(
        app,
        [
            "run",
            "company.example",
            "--mobile-artifact",
            str(artifact),
            "--mobile-app-id",
            "com.company.mobile",
            "--mobile-source-url",
            "https://play.google.com/store/apps/details?id=com.company.mobile",
            "--identity-header",
            "X_Bug_Bounty: test-researcher",
            "--scope",
            str(scope),
            "--max-steps",
            "3",
            "--no-progress",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert calls["domains"] == ("company.example",)
    mobile_input = calls["mobile_artifact"]
    assert mobile_input.artifact_path == artifact.absolute()
    assert mobile_input.app_id == "com.company.mobile"
    assert isinstance(mobile_input.source_url, str)
    assert mobile_input.source_url.startswith("https://play.google.com/")
    assert calls["max_steps"] == 3
    request_identity = calls["build"]["request_identity"]
    assert request_identity.http_headers == {
        "X_Bug_Bounty": "test-researcher"
    }
    assert calls["closed"] is True
    assert "com.company.mobile" in result.stdout
    assert "artifact=abc.apk" in result.stdout


def test_cli_run_requires_mobile_artifact_and_app_id_together(tmp_path) -> None:
    artifact = tmp_path / "company.apk"
    artifact.write_bytes(b"fixture")

    result = CliRunner().invoke(
        app,
        ["run", "--mobile-artifact", str(artifact), "--no-progress"],
    )

    assert result.exit_code == 2
    assert "must be provided together" in result.output


def test_cli_rejects_invalid_identity_header_before_building_runtime() -> None:
    result = CliRunner().invoke(
        app,
        ["run", "--identity-header", "missing-colon", "--no-progress"],
    )

    assert result.exit_code == 2
    assert "invalid --identity-header" in result.output


def test_cli_tools_list() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["tools", "list", "--json"])
    assert result.exit_code == 0
    assert '"subfinder"' in result.stdout
    assert '"debian"' in result.stdout or '"kali"' in result.stdout


def test_cli_review_lists_and_approves_case(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    calls: list[tuple[str, str]] = []
    open_payload = {
        "case_id": "rev_fixture",
        "task_id": "tsk_fixture",
        "worker": "permutations",
        "action": "generate_targeted",
        "categories": ["POLICY_AMBIGUITY"],
        "summaries": ["program restriction fixture: approval required"],
        "state": "OPEN",
    }

    class FakeRuntime:
        async def list_review_cases(self):
            return (SimpleNamespace(model_dump=lambda mode="json": open_payload),)

        async def approve_review_case(self, case_id, *, reason=None):
            calls.append((case_id, reason))
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    **open_payload,
                    "state": "APPROVED",
                }
            )

        async def close(self):
            pass

    async def fake_build_runtime(**kwargs):
        return FakeRuntime()

    monkeypatch.setattr("recon.cli.build_runtime", fake_build_runtime)
    pipeline = tmp_path / "pipeline.yaml"
    runner = CliRunner()

    listed = runner.invoke(
        app,
        ["review", "list", "--pipeline", str(pipeline)],
    )
    assert listed.exit_code == 0
    assert "rev_fixture" in listed.stdout
    assert "approval required" in listed.stdout

    approved = runner.invoke(
        app,
        [
            "review",
            "approve",
            "rev_fixture",
            "--reason",
            "authorized",
            "--pipeline",
            str(pipeline),
        ],
    )
    assert approved.exit_code == 0
    assert "APPROVED" in approved.stdout
    assert calls == [("rev_fixture", "authorized")]


def test_cli_setup_without_tool_install(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    runner = CliRunner()
    result = runner.invoke(app, ["setup", "--skip-tools", "--skip-wordlists"])
    assert result.exit_code == 0
    assert "Night Scout setup" in result.stdout
    assert (tmp_path / "config" / "nightscout" / "pipeline.yaml").is_file()
    assert (tmp_path / "config" / "nightscout" / "scope.yaml").is_file()


def test_cli_wordlists_works_without_source_checkout_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    runner = CliRunner()
    setup = runner.invoke(app, ["setup", "--skip-tools", "--skip-wordlists"])
    assert setup.exit_code == 0

    listed = runner.invoke(app, ["wordlists", "list"])
    assert listed.exit_code == 0
    assert "seclists" in listed.stdout.lower()

    verified = runner.invoke(app, ["wordlists", "verify"])
    assert verified.exit_code == 0
    assert "failed=0" in verified.stdout


def test_cli_setup_default_runs_wordlists_tools_and_doctor(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    from recon.tooling import (
        PlatformInfo,
        ToolInstallPhase,
        ToolInstallProgress,
    )

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    calls = {"wordlists": 0, "tools": 0, "doctor": 0}

    def fake_platform():
        return PlatformInfo(
            os_id="debian",
            pretty_name="Debian GNU/Linux 13",
            version_id="13",
            architecture="x86_64",
            goarch="amd64",
            asset_arch="x64",
        )

    def fake_wordlists(argv):
        calls["wordlists"] += 1
        assert "sync" in argv
        return 0

    def fake_install_tools(**kwargs):
        calls["tools"] += 1
        assert kwargs["install_prerequisites"] is True
        progress = kwargs.get("progress")
        assert progress is not None
        progress(
            ToolInstallProgress(
                tool_id="subfinder",
                index=1,
                total=1,
                phase=ToolInstallPhase.INSTALLING,
                detail="ProjectDiscovery PDTM download/install; test progress",
            )
        )
        return ()

    def fake_doctor(**kwargs):
        calls["doctor"] += 1
        return SimpleNamespace(healthy=True, checks=())

    monkeypatch.setattr("recon.cli.assert_supported_platform", fake_platform)
    monkeypatch.setattr("recon.cli.wordlists_sync_main", fake_wordlists)
    monkeypatch.setattr("recon.cli.install_tools", fake_install_tools)
    monkeypatch.setattr("recon.cli.doctor_from_files", fake_doctor)

    runner = CliRunner()
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 0
    assert calls == {"wordlists": 1, "tools": 1, "doctor": 1}
    assert "default public corpus synchronized" in result.stdout
    assert "doctor:    healthy" in result.stdout
    assert "[setup 4/5] Preparing companion tools" in result.stdout
    assert "first setup can take several minutes" in result.stdout
    assert "[tool 1/1] subfinder: installing" in result.stdout


def test_cli_run_accepts_many_explicit_seeds(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    calls: dict[str, object] = {}

    class FakeRuntime:
        async def run_domains(self, domains, *, max_steps=None, progress=None):
            calls["domains"] = tuple(domains)
            calls["max_steps"] = max_steps
            if progress is not None:
                progress(
                    RuntimeProgress(
                        run_id="run-many",
                        phase="STARTED",
                        max_steps=max_steps or 10_000,
                    )
                )
                progress(
                    RuntimeProgress(
                        run_id="run-many",
                        phase="EXECUTING",
                        step=1,
                        max_steps=max_steps or 10_000,
                        worker="http",
                        action="probe",
                    )
                )
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-many",
                    "status": "SUCCEEDED",
                    "seeds": [
                        {
                            "seed_event_id": "seed-a",
                            "target": "a.example.com",
                            "scope_state": "IN_SCOPE",
                            "mode": "EXPLICIT",
                            "matched_rule_id": "a",
                            "source_rule_ids": ["a"],
                            "genome_fingerprint": None,
                        },
                        {
                            "seed_event_id": "seed-b",
                            "target": "b.example.com",
                            "scope_state": "IN_SCOPE",
                            "mode": "EXPLICIT",
                            "matched_rule_id": "b",
                            "source_rule_ids": ["b"],
                            "genome_fingerprint": None,
                        },
                    ],
                    "steps": 2,
                    "outcomes": {"SUCCEEDED": 2},
                    "stopped_idle": True,
                    "max_steps_reached": False,
                    "task_counts": {"SUCCEEDED": 2},
                    "event_count": 2,
                    "asset_count": 2,
                    "open_review_cases": 0,
                    "warnings": [],
                }
            )

        async def close(self):
            calls["closed"] = True

    async def fake_build_runtime(**kwargs):
        calls["build"] = kwargs
        return FakeRuntime()

    monkeypatch.setattr("recon.cli.build_runtime", fake_build_runtime)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "run",
            "a.example.com",
            "b.example.com",
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--max-steps",
            "7",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert calls["domains"] == ("a.example.com", "b.example.com")
    assert calls["max_steps"] == 7
    assert calls["build"]["request_identity"].configured is False
    assert calls["closed"] is True
    assert "seeds:       2" in result.stdout
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout
    assert "recon: run=run-many phase=STARTED" in result.stderr
    assert "phase=EXECUTING step=1/7 worker=http action=probe" in result.stderr


def test_cli_run_returns_nonzero_for_failed_summary(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    class FakeRuntime:
        async def run_domains(self, domains, *, max_steps=None, progress=None):
            del domains, max_steps, progress
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-failed",
                    "status": "FAILED",
                    "seeds": [],
                    "steps": 1,
                    "outcomes": {"FAILED": 1},
                    "task_counts": {"FAILED": 1},
                    "event_count": 1,
                    "asset_count": 1,
                    "open_review_cases": 0,
                    "warnings": [],
                }
            )

        async def close(self):
            return None

    async def fake_build_runtime(**kwargs):
        del kwargs
        return FakeRuntime()

    monkeypatch.setattr("recon.cli.build_runtime", fake_build_runtime)
    result = CliRunner().invoke(
        app,
        [
            "run",
            "example.com",
            "--scope",
            str(tmp_path / "scope.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 1
    assert '"status": "FAILED"' in result.stdout


def test_cli_run_can_derive_seeds_from_scope_when_no_positional_targets(
    monkeypatch, tmp_path
) -> None:
    from types import SimpleNamespace

    calls: dict[str, object] = {}

    class FakeRuntime:
        async def run_domains(self, domains, *, max_steps=None, progress=None):
            calls["domains"] = tuple(domains)
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-scope",
                    "status": "SUCCEEDED",
                    "seeds": [
                        {
                            "seed_event_id": "seed-anchor",
                            "target": "example.org",
                            "scope_state": "PASSIVE_ONLY",
                            "mode": "WILDCARD_ANCHOR",
                            "matched_rule_id": "seed-anchor",
                            "source_rule_ids": ["wildcard"],
                            "genome_fingerprint": None,
                        }
                    ],
                    "steps": 0,
                    "outcomes": {"IDLE": 1},
                    "stopped_idle": True,
                    "max_steps_reached": False,
                    "task_counts": {},
                    "event_count": 1,
                    "asset_count": 1,
                    "open_review_cases": 0,
                    "warnings": [],
                }
            )

        async def close(self):
            pass

    async def fake_build_runtime(**kwargs):
        calls["build"] = kwargs
        return FakeRuntime()

    monkeypatch.setattr("recon.cli.build_runtime", fake_build_runtime)
    runner = CliRunner()
    scope_path = tmp_path / "program.yaml"
    result = runner.invoke(app, ["run", "--scope", str(scope_path)])
    assert result.exit_code == 0, result.stdout
    assert calls["domains"] == ()
    assert "WILDCARD_ANCHOR" in result.stdout
