from __future__ import annotations

import shutil


def detect_container_runtime() -> str | None:
    """Return ``'docker'``, ``'podman'``, or ``None`` depending on availability.

    Checks Docker first so that dual-install environments prefer Docker.
    """
    if shutil.which("docker"):
        return "docker"
    if shutil.which("podman"):
        return "podman"
    return None
