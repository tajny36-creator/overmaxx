"""Overmax/Tuya go2rtc bridge integration."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    CONF_CAMERA_NAME,
    CONF_CAMERAS,
    CONF_DEVICE_ID,
    CONF_DEVICE_MAP,
    CONF_STREAM_NAME,
    DEFAULT_CAMERA_NAME,
    DEFAULT_STREAM_NAME,
    DOMAIN,
)
from .go2rtc_client import (
    async_check_go2rtc,
    async_create_or_replace_stream,
    build_tuya_source,
    has_device_id,
    has_tuya_credentials,
)
from .utils import parse_device_map

PLATFORMS: list[Platform] = [Platform.CAMERA]


def _resolve_cameras(merged: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve camera list from modern or legacy config fields."""
    cameras = merged.get(CONF_CAMERAS)
    if isinstance(cameras, list) and cameras:
        return [dict(item) for item in cameras if isinstance(item, dict)]

    raw_map = str(merged.get(CONF_DEVICE_MAP) or "").strip()
    if raw_map:
        parsed = parse_device_map(raw_map)
        if parsed:
            return parsed

    # Legacy fallback (single stream only).
    return [
        {
            CONF_CAMERA_NAME: str(merged.get(CONF_CAMERA_NAME) or DEFAULT_CAMERA_NAME),
            CONF_STREAM_NAME: str(merged.get(CONF_STREAM_NAME) or DEFAULT_STREAM_NAME),
        }
    ]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Overmax go2rtc bridge from a config entry."""
    merged: dict[str, Any] = {**entry.data, **entry.options}
    cameras = _resolve_cameras(merged)

    check = await async_check_go2rtc(hass, merged)
    if not check.ok:
        raise ConfigEntryNotReady(f"go2rtc API not ready: {check.reason}")

    if has_tuya_credentials(merged):
        for camera in cameras:
            if not has_device_id(camera):
                continue
            source_url = build_tuya_source(merged, str(camera[CONF_DEVICE_ID]))
            result = await async_create_or_replace_stream(
                hass=hass,
                config=merged,
                stream_name=str(camera[CONF_STREAM_NAME]),
                source_url=source_url,
            )
            if not result.ok:
                camera["provisioning_error"] = result.reason

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "config": merged,
        "cameras": cameras,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry when options are updated."""
    await hass.config_entries.async_reload(entry.entry_id)
