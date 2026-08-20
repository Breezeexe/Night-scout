# Night Scout maintenance scripts

Scripts in this directory are explicit setup/release helpers. They are not part
of the recursive target-contact event loop.

## `wordlists_sync.py`

Synchronizes public wordlist corpora into `wordlists/cache/`, records a local
SHA-256 lock file, and generates a local runtime manifest. Network access occurs
only when this script is explicitly invoked with `sync`.

Examples:

```bash
python scripts/wordlists_sync.py list
python scripts/wordlists_sync.py sync
python scripts/wordlists_sync.py verify
python scripts/wordlists_sync.py sync --all
```


## `install_tools.py` / `tools_manifest.yaml`

Debian/Kali-only external tool management. The same functionality is available
from the packaged CLI, so a standalone `.deb` user does not need a source checkout or system Python:

```bash
nightscout tools list
nightscout tools install
nightscout tools install --optional --install-prerequisites
nightscout tools verify
```

Managed binaries live under `~/.local/share/nightscout/tools/bin` by default.
Night Scout prepends this directory to worker PATH automatically. ProjectDiscovery
tools are installed through official PDTM; Arjun uses pipx; optional mobile tools
use official release assets.

## `build_binary.py`

Builds a Linux `PyInstaller --onedir` standalone distribution and a `.tar.gz`
release archive. Build hosts are intentionally restricted to Debian/Kali.

```bash
python -m pip install -e '.[release]'
python scripts/build_binary.py
```

## `verify_release.py`

Performs no target traffic. It verifies the packaged executable, bundled tool
manifest and user-facing configuration examples.

## `build_deb.py`

Builds the installable Debian/Kali package used by both local developers and
tagged GitHub Releases. If `release/dist/nightscout` is missing, it invokes
`build_binary.py` first.

```bash
python scripts/build_deb.py
sudo apt install ./release/nightscout_0.1.0_amd64.deb
nightscout setup
```

The package installs the one-folder runtime under `/usr/lib/nightscout/` and
exposes `/usr/bin/nightscout`. Mutable user data remains under XDG user
directories, not under `/usr`.
