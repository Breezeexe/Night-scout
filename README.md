# Night Scout

> Recursive, scope-aware attack-surface intelligence for authorized security research.

[Русская версия](README_RU.md) · [Architecture](docs/ARCHITECTURE.md)

Night Scout coordinates reconnaissance tools around a persistent model of an
authorized target. It discovers assets, records how each fact was obtained,
turns new observations into follow-up tasks, and produces a readable attack
surface instead of a collection of unrelated scanner outputs.

It is designed for bug-bounty and defensive research. It is not an autonomous
exploitation framework.

## What you get

- strict YAML-defined scope, exclusions, restrictions, budgets and shared rate limits;
- recursive discovery across domains, DNS, HTTP, TLS, archives, JavaScript and local mobile artifacts;
- durable SQLite workspaces that can pause, resume and recover interrupted work;
- provenance for observations and a deduplicated semantic surface graph;
- confidence, novelty, expected-yield and convergence signals without policy bypasses;
- bounded parallel execution with per-worker limits and event-ingest backpressure;
- JSONL/TXT/CSV operational exports plus graph JSON, tree JSON and a standalone HTML explorer.

The graph is presented along the path a researcher normally follows:

```text
root domain
└── confirmed or candidate subdomain
    ├── DNS records / IP addresses
    └── HTTP service
        ├── endpoints and nested paths
        ├── parameters and JavaScript
        ├── technologies and fingerprints
        ├── certificate
        └── possible or confirmed findings
```

## Safety model

Night Scout treats scope as authorization, not as a discovery hint. A hostname
found in a certificate, archive, ASN or CNAME is classified again before active
work. Confidence and novelty may affect priority, but can never override scope,
restrictions, review gates, budgets or rate limits. Unknown active targets fail
closed, and sensitive evidence requires an explicit double opt-in to export.

Only run Night Scout against assets you are authorized to test.

## Installation

The supported release targets are Debian 13+ and current Kali Linux on `amd64`
or `arm64`.

Download the matching `.deb` from GitHub Releases and install it with APT:

```bash
sudo apt install ./nightscout_<version>_amd64.deb
nightscout --version
```

To build locally:

```bash
git clone https://github.com/Breezeexe/Night-scout
cd Night-scout
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[release]'
python scripts/build_deb.py
```

## Setup

Run setup as the normal user who will run reconnaissance:

```bash
nightscout setup
nightscout doctor
```

Do not run `nightscout setup` itself with `sudo`. When required, it invokes APT
through `sudo` for an explicit package allow-list. Mutable state follows the XDG
layout:

```text
~/.config/nightscout/       configuration and scopes
~/.local/share/nightscout/  workspaces, tools, wordlists and artifacts
~/.cache/nightscout/        disposable caches
```

Useful variants:

```bash
nightscout setup --skip-tools --skip-wordlists
nightscout setup --optional-tools
nightscout setup --update-tools
```

## First authorized run

Create a scope file that reflects the program rules literally. Exact assets
remain exact, wildcards remain wildcards, and exclusions receive higher
priority. Do not infer authorization from ownership or shared infrastructure.

```yaml
schema_version: 1
target_id: example-program
display_name: Example Bug Bounty Program
gate:
  allow_unknown_passive: false
rules:
  - rule_id: main-wildcard
    kind: DOMAIN
    pattern: "*.example.com"
    state: IN_SCOPE
    priority: 100
    tier: L1
    reason: Explicitly listed by the program

  - rule_id: excluded-admin
    kind: DOMAIN
    pattern: admin.example.com
    state: OUT_OF_SCOPE
    priority: 300
    reason: Explicit program exclusion
```

Then run the scope-derived frontier:

```bash
nightscout doctor --scope ./program.yaml
nightscout run --scope ./program.yaml
```

Several authorized domains may share one program workspace. `target_id` is the
stable workspace identity. For a quick local one-domain flow, `nightscout run
example.com` asks for explicit authorization interactively; automation can use
`--authorize-exact` or `--authorize-subdomains`.

The complete configuration templates are
[`configs/scope.example.yaml`](configs/scope.example.yaml) and
[`configs/pipeline.example.yaml`](configs/pipeline.example.yaml). Copy and
review them: files containing `.example.` are intentionally rejected as live
runtime configuration.

## Everyday commands

```bash
# Run or resume the durable frontier.
nightscout run --scope ./program.yaml --max-steps 100

# Inspect work and explain one persisted observation.
nightscout status --scope ./program.yaml
nightscout explain <event-id-or-exact-value> --scope ./program.yaml

# Resolve policy-sensitive work.
nightscout review list --scope ./program.yaml
nightscout review show <case-id> --scope ./program.yaml
nightscout review approve <case-id> --scope ./program.yaml --reason "authorized"
nightscout review reject <case-id> --scope ./program.yaml --reason "not authorized"

# Export the attack surface.
nightscout export --scope ./program.yaml --format graph-json
nightscout export --scope ./program.yaml --format tree-json --root example.com --max-depth 6
nightscout export --scope ./program.yaml --format html

# Backfill semantic relationships in an older workspace.
nightscout graph rebuild --scope ./program.yaml --dry-run
nightscout graph rebuild --scope ./program.yaml
```

`nightscout export` without `--format` writes every enabled SAFE export.
Sensitive material additionally requires both `--sensitive` and
`--confirm-sensitive`.

Every non-JSON `nightscout run` summary ends with ready-to-copy commands that
export the standalone HTML explorer, open it with `xdg-open`, and write the
canonical graph and rooted tree JSON projections. The commands retain the
exact pipeline and scope selected for that run.

## Documentation

- [Purpose and architecture](docs/ARCHITECTURE.md)
- [Цель и архитектура — по-русски](docs/ARCHITECTURE_RU.md)
- [Pipeline configuration template](configs/pipeline.example.yaml)
- [Scope configuration template](configs/scope.example.yaml)
- [Companion-tool manifest](scripts/tools_manifest.yaml)

The architecture document explains the event and surface graphs, lifecycle,
parallel dispatcher, policy gates, intelligence models, persistence, workers,
exports and extension points.

## Development

Night Scout requires Python 3.12+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
mypy recon
```

Tests use adapters and fake subprocesses; normal unit and integration tests do
not contact reconnaissance targets. Database changes must be delivered through
Alembic migrations.

## Current boundaries

- one Night Scout process owns admission for a workspace;
- SQLite is the source of truth; no external graph database is required;
- companion reconnaissance binaries remain separately managed tools;
- GraphML and distributed dispatch are possible future additions, not current contracts.
