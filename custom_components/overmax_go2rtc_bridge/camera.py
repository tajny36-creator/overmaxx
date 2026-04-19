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
    CONF_RTSP_HOST,
    CONF_RTSP_PASSWORD,
    CONF_RTSP_PORT,
    CONF_RTSP_USERNAME,
    CONF_STREAM_NAME,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up camera from config entry."""
    merged_data: dict[str, Any] = {**entry.data, **entry.options}
    async_add_entities([OvermaxGo2RtcBridgeCamera(hass, entry, merged_data)])


class OvermaxGo2RtcBridgeCamera(Camera):
    """Represent a go2rtc-backed camera."""

    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_should_poll = False
    _attr_brand = "Overmax/Tuya"
    _attr_model = "go2rtc bridge"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, data: dict[str, Any]) -> None:
        """Initialize the camera."""
        super().__init__()
        self.hass = hass
        self._entry = entry

        self._camera_name = data[CONF_CAMERA_NAME]
        self._stream_name = str(data[CONF_STREAM_NAME]).lstrip("/")
        self._rtsp_host = data[CONF_RTSP_HOST]
        self._rtsp_port = int(data[CONF_RTSP_PORT])
        self._rtsp_username = data.get(CONF_RTSP_USERNAME) or ""
        self._rtsp_password = data.get(CONF_RTSP_PASSWORD) or ""

        self._attr_name = self._camera_name
        self._attr_unique_id = f"{entry.entry_id}_camera"
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
            "go2rtc_stream_name": self._stream_name,
            "go2rtc_rtsp_host": self._rtsp_host,
            "go2rtc_rtsp_port": self._rtsp_port,
        }

    async def stream_source(self) -> str | None:
        """Return the source of the stream."""
        return self._stream_source_url

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image from the RTSP stream."""
        return await ffmpeg.async_get_image(
            self.hass,
            self._stream_source_url,
            width=width,
            height=height,
        )
