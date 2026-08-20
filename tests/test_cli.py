from __future__ import annotations

from typer.testing import CliRunner

from recon.cli import app


def test_cli_version_and_help():
    runner = CliRunner()
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert "Night Scout" in version.stdout

    help_result = runner.invoke(app, ["--help"])
    assert help_result.exit_code == 0
    for command in ("setup", "doctor", "run", "status", "explain", "export", "tools", "wordlists"):
        assert command in help_result.stdout


def test_cli_tools_list() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["tools", "list", "--json"])
    assert result.exit_code == 0
    assert '"subfinder"' in result.stdout
    assert '"debian"' in result.stdout or '"kali"' in result.stdout


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
        async def run_domains(self, domains, *, max_steps=None):
            calls["domains"] = tuple(domains)
            calls["max_steps"] = max_steps
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-many",
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
    assert calls["closed"] is True
    assert "seeds:       2" in result.stdout
    assert "a.example.com" in result.stdout
    assert "b.example.com" in result.stdout


def test_cli_run_can_derive_seeds_from_scope_when_no_positional_targets(monkeypatch, tmp_path) -> None:
    from types import SimpleNamespace

    calls: dict[str, object] = {}

    class FakeRuntime:
        async def run_domains(self, domains, *, max_steps=None):
            calls["domains"] = tuple(domains)
            return SimpleNamespace(
                model_dump=lambda mode="json": {
                    "run_id": "run-scope",
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
