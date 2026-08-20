#!/usr/bin/env python3
"""Explicit Debian/Kali external-tool installer for Night Scout."""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from recon.tooling import tooling_cli


if __name__ == "__main__":
    raise SystemExit(tooling_cli())
