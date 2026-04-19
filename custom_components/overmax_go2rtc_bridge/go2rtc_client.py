"""go2rtc API helpers for Overmax/Tuya bridge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from aiohttp import BasicAuth, ClientError

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_DEVICE_ID,
    CONF_GO2RTC_API_PASSWORD,
    CONF_GO2RTC_API_URL,
    CONF_GO2RTC_API_USERNAME,
    CONF_RESOLUTION,
    CONF_TUYA_EMAIL,
    CONF_TUYA_PASSWORD,
    CONF_TUYA_REGION_HOST,
    DEFAULT_GO2RTC_API_URL,
    DEFAULT_RESOLUTION,
    DEFAULT_TUYA_REGION_HOST,
)


@dataclass
class Go2RtcCheckResult:
    ok: bool
    reason: str = ""


def _normalize_base_url(value: str) -> str:
    base = (value or "").strip() or DEFAULT_GO2RTC_API_URL
    if not base.startswith("http://") and not base.startswith("https://"):
        base = f"http://{base}"
    return base.rstrip("/")


def _normalize_region_host(value: str) -> str:
    candidate = (value or "").strip() or DEFAULT_TUYA_REGION_HOST
    parsed = urlparse(candidate)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    if candidate.startswith("//"):
        return urlparse(f"http:{candidate}").netloc
    return candidate.strip("/ ")


def _build_auth(config: dict[str, Any]) -> BasicAuth | None:
    username = str(config.get(CONF_GO2RTC_API_USERNAME) or "").strip()
    password = str(config.get(CONF_GO2RTC_API_PASSWORD) or "")
    if not username:
        return None
    return BasicAuth(login=username, password=password)


def build_tuya_source(config: dict[str, Any], device_id: str) -> str:
    """Build tuya:// source URL for go2rtc."""
    region_host = _normalize_region_host(str(config.get(CONF_TUYA_REGION_HOST) or ""))
    email = str(config.get(CONF_TUYA_EMAIL) or "").strip()
    password = str(config.get(CONF_TUYA_PASSWORD) or "")
    resolution = str(config.get(CONF_RESOLUTION) or DEFAULT_RESOLUTION).lower()

    query_data = {
        "device_id": device_id,
        "email": email,
        "password": password,
    }
    if resolution == "sd":
        query_data["resolution"] = "sd"

    return f"tuya://{region_host}?{urlencode(query_data)}"


async def async_check_go2rtc(hass: HomeAssistant, config: dict[str, Any]) -> Go2RtcCheckResult:
    """Check if go2rtc API is reachable."""
    session = async_get_clientsession(hass)
    auth = _build_auth(config)
    base_url = _normalize_base_url(str(config.get(CONF_GO2RTC_API_URL) or ""))
    url = urljoin(f"{base_url}/", "api")

    try:
        async with session.get(url, auth=auth, timeout=10) as resp:
            if resp.status == 401:
                return Go2RtcCheckResult(False, "auth")
            if resp.status >= 400:
                return Go2RtcCheckResult(False, f"http_{resp.status}")
            return Go2RtcCheckResult(True)
    except ClientError:
        return Go2RtcCheckResult(False, "cannot_connect")
    except TimeoutError:
        return Go2RtcCheckResult(False, "timeout")


async def async_create_or_replace_stream(
    hass: HomeAssistant,
    config: dict[str, Any],
    stream_name: str,
    source_url: str,
) -> Go2RtcCheckResult:
    """Create or replace stream in go2rtc and persist config."""
    session = async_get_clientsession(hass)
    auth = _build_auth(config)
    base_url = _normalize_base_url(str(config.get(CONF_GO2RTC_API_URL) or ""))
    url = urljoin(f"{base_url}/", "api/streams")
    params = {"name": stream_name, "src": source_url}

    try:
        async with session.put(url, params=params, auth=auth, timeout=15) as resp:
            if resp.status == 401:
                return Go2RtcCheckResult(False, "auth")
            if resp.status >= 400:
                body = await resp.text()
                if "source not supported" in body:
                    return Go2RtcCheckResult(False, "source_not_supported")
                return Go2RtcCheckResult(False, f"http_{resp.status}")
            return Go2RtcCheckResult(True)
    except ClientError:
        return Go2RtcCheckResult(False, "cannot_connect")
    except TimeoutError:
        return Go2RtcCheckResult(False, "timeout")


def has_tuya_credentials(config: dict[str, Any]) -> bool:
    """Return True when configuration has enough Tuya data for stream provisioning."""
    return bool(
        str(config.get(CONF_TUYA_EMAIL) or "").strip()
        and str(config.get(CONF_TUYA_PASSWORD) or "")
    )


def has_device_id(camera: dict[str, Any]) -> bool:
    """Return True when camera entry contains device id."""
    return bool(str(camera.get(CONF_DEVICE_ID) or "").strip())
