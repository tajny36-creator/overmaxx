"""Camera entity for Overmax/Tuya go2rtc bridge."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from homeassistant.components import ffmpeg
from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_CAMERA_NAME,
    CONF_DEVICE_ID,
    CONF_RTSP_HOST,
    CONF_RTSP_PASSWORD,
    CONF_RTSP_PORT,
    CONF_RTSP_USERNAME,
    CONF_STREAM_NAME,
    DEFAULT_CAMERA_NAME,
    DEFAULT_RTSP_HOST,
    DEFAULT_RTSP_PORT,
    DEFAULT_STREAM_NAME,
    DOMAIN,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up camera from config entry."""
    runtime = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    merged_data: dict[str, Any] = dict(runtime.get("config") or {**entry.data, **entry.options})
    cameras: list[dict[str, Any]] = list(runtime.get("cameras") or [])

    if not cameras:
        # Legacy fallback
        cameras = [
            {
                CONF_CAMERA_NAME: merged_data.get(CONF_CAMERA_NAME, DEFAULT_CAMERA_NAME),
                CONF_STREAM_NAME: merged_data.get(CONF_STREAM_NAME, DEFAULT_STREAM_NAME),
            }
        ]

    entities = [
        OvermaxGo2RtcBridgeCamera(hass, entry, merged_data, camera_data)
        for camera_data in cameras
    ]
    async_add_entities(entities)


class OvermaxGo2RtcBridgeCamera(Camera):
    """Represent a go2rtc-backed camera."""

    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_should_poll = False
    _attr_brand = "Overmax/Tuya"
    _attr_model = "go2rtc bridge"

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        config: dict[str, Any],
        camera_data: dict[str, Any],
    ) -> None:
        """Initialize the camera."""
        super().__init__()
        self.hass = hass
        self._entry = entry

        self._camera_name = str(camera_data.get(CONF_CAMERA_NAME) or DEFAULT_CAMERA_NAME)
        self._stream_name = str(camera_data.get(CONF_STREAM_NAME) or DEFAULT_STREAM_NAME).lstrip("/")
        self._device_id = str(camera_data.get(CONF_DEVICE_ID) or "")
        self._provisioning_error = str(camera_data.get("provisioning_error") or "")

        self._rtsp_host = str(config.get(CONF_RTSP_HOST) or DEFAULT_RTSP_HOST)
        self._rtsp_port = int(config.get(CONF_RTSP_PORT) or DEFAULT_RTSP_PORT)
        self._rtsp_username = str(config.get(CONF_RTSP_USERNAME) or "")
        self._rtsp_password = str(config.get(CONF_RTSP_PASSWORD) or "")

        self._attr_name = self._camera_name
        self._attr_unique_id = f"{entry.entry_id}_{self._stream_name}"
        self._stream_source_url = self._build_rtsp_url()

    def _build_rtsp_url(self) -> str:
        """Build RTSP URL to a go2rtc stream."""
        auth = ""
        if self._rtsp_username:
            encoded_user = quote(self._rtsp_username, safe="")
            if self._rtsp_password:
                encoded_pass = quote(self._rtsp_password, safe="")
                auth = f"{encoded_user}:{encoded_pass}@"
            else:
                auth = f"{encoded_user}@"

        encoded_stream = quote(self._stream_name, safe="/._-")
        return f"rtsp://{auth}{self._rtsp_host}:{self._rtsp_port}/{encoded_stream}"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        return {
            "device_id": self._device_id or None,
            "go2rtc_stream_name": self._stream_name,
            "go2rtc_rtsp_host": self._rtsp_host,
            "go2rtc_rtsp_port": self._rtsp_port,
            "provisioning_error": self._provisioning_error or None,
        }

    async def stream_source(self) -> str | None:
        """Return the source of the stream."""
        return self._stream_source_url

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image from the RTSP stream."""
        try:
            return await ffmpeg.async_get_image(
                self.hass,
                self._stream_source_url,
                width=width,
                height=height,
            )
        except Exception:
            return None
