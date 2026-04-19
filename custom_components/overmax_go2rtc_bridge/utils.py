"""Helpers for Overmax/Tuya go2rtc bridge."""

from __future__ import annotations

import re
from typing import Any

from .const import CONF_CAMERA_NAME, CONF_DEVICE_ID, CONF_STREAM_NAME


def slugify_stream_name(value: str) -> str:
    """Build a go2rtc-safe stream name."""
    value = value.strip().lower()
    value = re.sub(r"\s+", "_", value)
    value = re.sub(r"[^a-z0-9_.-]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "camera"


def parse_device_map(device_map_raw: str) -> list[dict[str, str]]:
    """
    Parse lines in format:
    - name=device_id
    - device_id
    """
    cameras: list[dict[str, str]] = []
    used_stream_names: set[str] = set()
    auto_idx = 1

    for raw_line in device_map_raw.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if "=" in line:
            name, device_id = line.split("=", 1)
            camera_name = name.strip() or f"Camera {auto_idx}"
            device_id = device_id.strip()
        else:
            camera_name = f"Camera {auto_idx}"
            device_id = line.strip()

        if not device_id:
            continue

        stream_base = slugify_stream_name(camera_name)
        stream_name = stream_base
        suffix = 2
        while stream_name in used_stream_names:
            stream_name = f"{stream_base}_{suffix}"
            suffix += 1
        used_stream_names.add(stream_name)

        cameras.append(
            {
                CONF_CAMERA_NAME: camera_name,
                CONF_DEVICE_ID: device_id,
                CONF_STREAM_NAME: stream_name,
            }
        )
        auto_idx += 1

    return cameras


def format_device_map(cameras: list[dict[str, Any]]) -> str:
    """Convert camera list back to multiline text."""
    lines: list[str] = []
    for camera in cameras:
        name = str(camera.get(CONF_CAMERA_NAME, "")).strip()
        device_id = str(camera.get(CONF_DEVICE_ID, "")).strip()
        if not device_id:
            continue
        if name:
            lines.append(f"{name}={device_id}")
        else:
            lines.append(device_id)
    return "\n".join(lines)
