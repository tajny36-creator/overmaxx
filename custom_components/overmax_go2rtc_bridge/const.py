"""Constants for Overmax/Tuya go2rtc bridge."""

from __future__ import annotations

DOMAIN = "overmax_go2rtc_bridge"

CONF_CAMERA_NAME = "camera_name"
CONF_STREAM_NAME = "stream_name"
CONF_RTSP_HOST = "rtsp_host"
CONF_RTSP_PORT = "rtsp_port"
CONF_RTSP_USERNAME = "rtsp_username"
CONF_RTSP_PASSWORD = "rtsp_password"

CONF_GO2RTC_API_URL = "go2rtc_api_url"
CONF_GO2RTC_API_USERNAME = "go2rtc_api_username"
CONF_GO2RTC_API_PASSWORD = "go2rtc_api_password"

CONF_TUYA_REGION_HOST = "tuya_region_host"
CONF_TUYA_EMAIL = "tuya_email"
CONF_TUYA_PASSWORD = "tuya_password"
CONF_RESOLUTION = "resolution"

CONF_DEVICE_MAP = "device_map"
CONF_CAMERAS = "cameras"
CONF_DEVICE_ID = "device_id"

DEFAULT_CAMERA_NAME = "Overmax NVR"
DEFAULT_STREAM_NAME = "overmax_nvr"
DEFAULT_RTSP_HOST = "127.0.0.1"
DEFAULT_RTSP_PORT = 8554
DEFAULT_GO2RTC_API_URL = "http://127.0.0.1:1984"
DEFAULT_TUYA_REGION_HOST = "protect-eu.ismartlife.me"
DEFAULT_RESOLUTION = "hd"

RESOLUTION_OPTIONS = ("hd", "sd")
