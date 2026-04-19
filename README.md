# Smart Home Network Scanner

Local network scanner that estimates smart-home ecosystem compatibility per IP.

Detected ecosystem hints include:
- Tuya
- Apple HomeKit
- Google Home
- Amazon Alexa
- Home Assistant
- Shelly
- Sonoff/eWeLink
- Xiaomi Mi Home
- Matter

## Requirements
- Python 3.9+
- Access to your local network

No third-party Python packages are required.

## Quick start

```powershell
python .\smarthome_scanner.py
```

Default behavior:
- auto-detects local `/24` subnet from your active IP
- performs SSDP discovery
- performs ping sweep
- scans common TCP ports
- fetches lightweight HTTP/HTTPS fingerprints
- prints a table with likely ecosystem matches

## Useful options

```powershell
# Explicit subnet
python .\smarthome_scanner.py --subnet 192.168.1.0/24

# Faster / lighter scan
python .\smarthome_scanner.py --subnet 192.168.1.0/24 --ping-timeout-ms 200 --port-timeout 0.2

# Skip TCP port scan (ARP + SSDP + DNS only)
python .\smarthome_scanner.py --no-port-scan

# Save JSON report
python .\smarthome_scanner.py --json-out .\scan_report.json
```

## Notes
- Results are heuristic, not guaranteed.
- Some devices hide signatures or block discovery traffic.
- MAC vendor hints rely on a compact built-in OUI map and may be incomplete.

## Overmax NVR -> Home Assistant

If your NVR is detected as possible Tuya but has old `hd client` web UI (ActiveX), it may
actually use proprietary streaming ports and **not** native Tuya integration.

Use RTSP probe helper:

```powershell
python .\probe_overmax_rtsp.py --host 192.168.1.136 --user YOUR_USER --password YOUR_PASS
```

If no stream is found:
- enable RTSP/ONVIF in NVR network settings first
- then rerun probe with the same credentials

The helper prints ready-to-paste snippets for Home Assistant (`camera: generic`) and
`go2rtc` when it discovers a working RTSP URL.

## HACS custom integration (GitHub): Overmax Tuya go2rtc Bridge

Repository includes a HACS-ready custom integration:

- Domain: `overmax_go2rtc_bridge`
- Path: `custom_components/overmax_go2rtc_bridge`
- HACS metadata: `hacs.json`

### What this integration does

- Adds multiple camera entities via UI (Config Flow).
- Accepts Tuya/SmartLife login and `name=device_id` map for many cameras.
- Auto-creates go2rtc streams through API (`PUT /api/streams`) for each camera.
- Uses go2rtc RTSP outputs as camera sources (`rtsp://<host>:<port>/<stream_name>`).

### Publish to GitHub

```powershell
cd C:\Users\WERTJ\Documents\GitHub\overmax
git init
git add .
git commit -m "Add HACS custom integration: overmax_go2rtc_bridge"
```

Then create an empty GitHub repository and push:

```powershell
git branch -M main
git remote add origin https://github.com/<your-user>/<your-repo>.git
git push -u origin main
```

### Add in HACS

1. HACS -> Integrations -> three dots -> Custom repositories
2. Paste your GitHub repo URL
3. Category: `Integration`
4. Install `Overmax Tuya go2rtc Bridge`
5. Restart Home Assistant

### Configure in Home Assistant

1. Settings -> Devices & Services -> Add Integration
2. Select `Overmax Tuya go2rtc Bridge`
3. Fill:
- Camera map (`name=device_id`, one camera per line), example:
```text
Salon=bfxxxxxxxxxxxxxxxxxxxx
Korytarz=baxxxxxxxxxxxxxxxxxxxx
Brama=cdxxxxxxxxxxxxxxxxxxxx
```
- Tuya email/password
- Tuya region host (EU example: `protect-eu.ismartlife.me`)
- go2rtc API URL (usually `http://127.0.0.1:1984`)
- Optional go2rtc API auth (if enabled)
- go2rtc RTSP host/port (usually `127.0.0.1:8554`)
- Optional RTSP auth (if enabled in go2rtc)

### Optional: discover `device_id` by QR login (ipc-eu portal)

If you prefer QR login like `https://ipc-eu.ismartlife.me/login`, use helper:

```powershell
python .\tuya_qr_device_discovery.py --host ipc-eu.ismartlife.me --open-qr --device-map-out .\device_map.txt
```

It will:
- generate QR image,
- wait for scan confirmation,
- print and save `name=device_id` lines for all detected cameras.

Then paste resulting lines into the integration field:
- `Camera map (name=device_id)`
