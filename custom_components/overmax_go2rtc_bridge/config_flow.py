"""Config flow for Overmax/Tuya go2rtc bridge."""

from __future__ import annotations

from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CONF_CAMERAS,
    CONF_DEVICE_MAP,
    CONF_GO2RTC_API_PASSWORD,
    CONF_GO2RTC_API_URL,
    CONF_GO2RTC_API_USERNAME,
    CONF_RESOLUTION,
    CONF_RTSP_HOST,
    CONF_RTSP_PASSWORD,
    CONF_RTSP_PORT,
    CONF_RTSP_USERNAME,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_REGION_HOST,
    DEFAULT_GO2RTC_API_URL,
    DEFAULT_RESOLUTION,
    DEFAULT_RTSP_HOST,
    DEFAULT_RTSP_PORT,
    DEFAULT_TUYA_REGION_HOST,
    DOMAIN,
    RESOLUTION_OPTIONS,
)
from .go2rtc_client import async_check_go2rtc
from .utils import format_device_map, parse_device_map


def _build_schema(defaults: dict[str, Any] | None = None) -> vol.Schema:
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(
                CONF_DEVICE_MAP,
                default=defaults.get(
                    CONF_DEVICE_MAP,
                    "Salon=<device_id_1>\nKorytarz=<device_id_2>",
                ),
            ): str,
            vol.Required(
                CONF_TUYA_EMAIL,
                default=defaults.get(CONF_TUYA_EMAIL, ""),
            ): str,
            vol.Required(
                CONF_TUYA_PASSWORD,
                default=defaults.get(CONF_TUYA_PASSWORD, ""),
            ): str,
            vol.Required(
                CONF_TUYA_REGION_HOST,
                default=defaults.get(CONF_TUYA_REGION_HOST, DEFAULT_TUYA_REGION_HOST),
            ): str,
            vol.Required(
                CONF_RESOLUTION,
                default=defaults.get(CONF_RESOLUTION, DEFAULT_RESOLUTION),
            ): vol.In(list(RESOLUTION_OPTIONS)),
            vol.Required(
                CONF_GO2RTC_API_URL,
                default=defaults.get(CONF_GO2RTC_API_URL, DEFAULT_GO2RTC_API_URL),
            ): str,
            vol.Optional(
                CONF_GO2RTC_API_USERNAME,
                default=defaults.get(CONF_GO2RTC_API_USERNAME, ""),
            ): str,
            vol.Optional(
                CONF_GO2RTC_API_PASSWORD,
                default=defaults.get(CONF_GO2RTC_API_PASSWORD, ""),
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


def _normalize_user_input(user_input: dict[str, Any]) -> dict[str, Any]:
    data = dict(user_input)
    cameras = parse_device_map(str(user_input.get(CONF_DEVICE_MAP) or ""))
    data[CONF_CAMERAS] = cameras
    return data


class OvermaxGo2RtcBridgeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Overmax/Tuya go2rtc bridge."""

    VERSION = 2

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return OvermaxGo2RtcBridgeOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle first step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            normalized = _normalize_user_input(user_input)
            cameras = normalized.get(CONF_CAMERAS) or []
            if not cameras:
                errors["base"] = "invalid_device_map"
            else:
                check = await async_check_go2rtc(self.hass, normalized)
                if not check.ok:
                    if check.reason == "auth":
                        errors["base"] = "auth"
                    elif check.reason in {"cannot_connect", "timeout"}:
                        errors["base"] = "cannot_connect"
                    else:
                        errors["base"] = "unknown"
                else:
                    unique_id = str(normalized.get(CONF_GO2RTC_API_URL))
                    await self.async_set_unique_id(unique_id)
                    self._abort_if_unique_id_configured()
                    title = f"Overmax Tuya Bridge ({len(cameras)} camera)"
                    if len(cameras) != 1:
                        title = f"Overmax Tuya Bridge ({len(cameras)} cameras)"
                    return self.async_create_entry(
                        title=title,
                        data=normalized,
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(),
            errors=errors,
        )


class OvermaxGo2RtcBridgeOptionsFlow(config_entries.OptionsFlow):
    """Handle options flow."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Handle options update."""
        errors: dict[str, str] = {}
        if user_input is not None:
            normalized = _normalize_user_input(user_input)
            cameras = normalized.get(CONF_CAMERAS) or []
            if not cameras:
                errors["base"] = "invalid_device_map"
            else:
                check = await async_check_go2rtc(self.hass, normalized)
                if not check.ok:
                    if check.reason == "auth":
                        errors["base"] = "auth"
                    elif check.reason in {"cannot_connect", "timeout"}:
                        errors["base"] = "cannot_connect"
                    else:
                        errors["base"] = "unknown"
                else:
                    return self.async_create_entry(title="", data=normalized)

        defaults = {**self._config_entry.data, **self._config_entry.options}
        if CONF_CAMERAS in defaults and not defaults.get(CONF_DEVICE_MAP):
            defaults[CONF_DEVICE_MAP] = format_device_map(defaults.get(CONF_CAMERAS, []))

        return self.async_show_form(
            step_id="init",
            data_schema=_build_schema(defaults),
            errors=errors,
        )
