"""Config flow for Overmax/Tuya go2rtc bridge."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_CAMERA_NAME,
    CONF_RTSP_HOST,
    CONF_RTSP_PASSWORD,
    CONF_RTSP_PORT,
    CONF_RTSP_USERNAME,
    CONF_STREAM_NAME,
    DEFAULT_CAMERA_NAME,
    DEFAULT_RTSP_HOST,
    DEFAULT_RTSP_PORT,
    DOMAIN,
)


def _build_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(
                CONF_CAMERA_NAME,
                default=defaults.get(CONF_CAMERA_NAME, DEFAULT_CAMERA_NAME),
            ): str,
            vol.Required(
                CONF_STREAM_NAME,
                default=defaults.get(CONF_STREAM_NAME, "overmax_nvr"),
            ): str,
            vol.Required(
                CONF_RTSP_HOST,
                default=defaults.get(CONF_RTSP_HOST, DEFAULT_RTSP_HOST),
            ): str,
            vol.Required(
                CONF_RTSP_PORT,
                default=defaults.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT),
            ): int,
            vol.Optional(
                CONF_RTSP_USERNAME,
                default=defaults.get(CONF_RTSP_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_RTSP_PASSWORD,
                default=defaults.get(CONF_RTSP_PASSWORD, ""),
            ): str,
        }
    )


class OvermaxGo2RtcBridgeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Overmax/Tuya go2rtc bridge."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return OvermaxGo2RtcBridgeOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle first step."""
        if user_input is not None:
            unique_id = (
                f"{user_input[CONF_RTSP_HOST]}:{user_input[CONF_RTSP_PORT]}/"
                f"{user_input[CONF_STREAM_NAME]}"
            )
            await self.async_set_unique_id(unique_id)
            self._abort_if_unique_id_configured()
            return self.async_create_entry(
                title=user_input[CONF_CAMERA_NAME],
                data=user_input,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(),
            errors={},
        )


class OvermaxGo2RtcBridgeOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle options update."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        defaults = {**self._config_entry.data, **self._config_entry.options}
        return self.async_show_form(
            step_id="init",
            data_schema=_build_schema(defaults),
            errors={},
        )
