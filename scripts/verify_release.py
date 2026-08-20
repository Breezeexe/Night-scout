#!/usr/bin/env python3
"""Verify a Night Scout Debian/Kali standalone bundle without target traffic."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


def run(binary: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)

    bundle = args.bundle.expanduser().resolve()
    binary = bundle / "nightscout"
    failures: list[str] = []

    if not binary.is_file() or not os.access(binary, os.X_OK):
        failures.append("nightscout executable missing/not executable")
    else:
        version = run(binary, "--version")
        if version.returncode != 0 or "Night Scout" not in version.stdout:
            failures.append("--version failed")

        tools = run(binary, "tools", "list", "--json")
        if tools.returncode != 0:
            failures.append("tools list failed")
        else:
            try:
                payload = json.loads(tools.stdout)
            except json.JSONDecodeError:
                failures.append("tools list returned invalid JSON")
            else:
                if payload.get("platform", {}).get("os_id") not in {"debian", "kali"}:
                    failures.append("unsupported platform reported")
                if not payload.get("tools"):
                    failures.append("bundled tools manifest is empty")

    for relative in (
        "examples/pipeline.example.yaml",
        "examples/scope.example.yaml",
        "examples/nuclei-templates.example.yaml",
        "README.md",
        "tools_manifest.yaml",
    ):
        if not (bundle / relative).is_file():
            failures.append(f"missing release file: {relative}")

    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1

    print("release bundle verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
