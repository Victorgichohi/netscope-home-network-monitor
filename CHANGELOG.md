# Changelog

## 0.5.0

- Added a read-only `huawei_ont` router adapter for Huawei EchoLife GPON ONTs (tested against HG8546M firmware V5R019C00S100 page formats).
- Reads fibre optical power, module temperature, CPU, uptime, PPPoE session state, DNS, MTU, carrier-grade NAT detection, and 2.4 GHz Wi-Fi configuration.
- Added router health history with configurable polling and retention.
- Added a router configuration audit: fibre signal thresholds, WAN state, PPPoE MTU, open/WEP/WPA1 security, TKIP, regulatory-domain mismatch, narrow channel width, and legacy 802.11b.
- Warning and critical findings raise deduplicated alerts.
- The adapter never reads Wi-Fi passphrases, WEP keys, WPS PINs, PPPoE credentials, serial numbers, or MAC addresses; tests assert this.

## 0.4.0

- Restored the dense network-command-center interface.
- Added bounded download and upload speed tests with latency and jitter history.
- Added rolling ISP availability, outage, latency, and packet-loss analytics.
- Added selectable one-hour, 24-hour, and seven-day traffic windows.
- Added local destination service classification and automatic device-type inference.
- Added cache-versioned PWA assets and responsive technical views.

## 0.3.0

- Added active gateway, internet, and DNS diagnostics with recommendations.
- Added diagnostic history, household insights, activity timeline, and capture-scope labels.
- Added first-run local account setup, a desktop launcher, and PWA installation support.

## 0.2.0

- Added live traffic charts, upload/download accounting, topology, device profiles, trust states, alerts, and security scoring.

## 0.1.0

- Added FastAPI, SQLite inventory, ARP discovery, passive metadata capture, DNS attribution, authentication, audit logging, and router adapters.
