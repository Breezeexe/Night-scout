"""Runtime resource discovery for source and standalone Night Scout builds."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def bundled_resource_root() -> Path:
    """Return the root containing bundled configs/migrations/wordlists.

    In a PyInstaller bundle, data files live under ``sys._MEIPASS``. In a
    source checkout or installed package, the repository/distribution root is
    two parents above this module.
    """

    override = os.environ.get("NIGHTSCOUT_PROJECT_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()

    meipass = getattr(sys, "_MEIPASS", None)
    if isinstance(meipass, str) and meipass:
        return Path(meipass).resolve()

    return Path(__file__).resolve().parents[1]


def resource_path(*parts: str) -> Path:
    return bundled_resource_root().joinpath(*parts)


def default_pipeline_path() -> Path:
    return resource_path("configs", "pipeline.example.yaml")


def default_tools_manifest_path() -> Path:
    return resource_path("scripts", "tools_manifest.yaml")


def is_standalone_bundle() -> bool:
    return bool(getattr(sys, "frozen", False) or getattr(sys, "_MEIPASS", None))
