"""Router health polling and configuration audit.

Turns a read-only router snapshot into stored history plus findings that say
whether a problem is the fibre line, the ISP session, or the Wi-Fi setup.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.config import Settings
from app.database import SessionLocal
from app.models import RouterHealthSample
from app.router_control.base import RouterController
from app.router_control.huawei_ont import RouterSnapshot, WifiInfo
from app.services.alerts import raise_alert

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}

# GPON class B+ receive window. ONTs typically report -8 to -27 dBm as in range;
# readings within 2 dB of the floor tend to cause intermittent drops first.
RX_OVERLOAD_DBM = -8.0
RX_MARGINAL_DBM = -25.0
RX_FLOOR_DBM = -27.0
TEMPERATURE_WARNING_C = 70
CPU_WARNING_PERCENT = 85


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    recommendation: str

    def as_dict(self) -> dict:
        return asdict(self)


def _optical_findings(snapshot: RouterSnapshot) -> list[Finding]:
    optical = snapshot.optical
    if optical is None or optical.rx_power_dbm is None:
        return []
    rx = optical.rx_power_dbm
    findings: list[Finding] = []
    if rx < RX_FLOOR_DBM:
        findings.append(
            Finding(
                "critical",
                "optical.rx_low",
                "Fibre signal is below the working range",
                f"Received optical power is {rx:.2f} dBm (floor {RX_FLOOR_DBM:.0f} dBm).",
                "Ask the ISP for a technician visit: check the drop cable, connectors and splitter.",
            )
        )
    elif rx < RX_MARGINAL_DBM:
        findings.append(
            Finding(
                "warning",
                "optical.rx_marginal",
                "Fibre signal is marginal",
                f"Received optical power is {rx:.2f} dBm, within 2 dB of the {RX_FLOOR_DBM:.0f} dBm floor.",
                "Check for tight bends in the fibre patch lead and ask the ISP to clean the connectors.",
            )
        )
    elif rx > RX_OVERLOAD_DBM:
        findings.append(
            Finding(
                "warning",
                "optical.rx_overload",
                "Fibre signal is too strong",
                f"Received optical power is {rx:.2f} dBm, above {RX_OVERLOAD_DBM:.0f} dBm.",
                "The ISP may need to add an attenuator on the line.",
            )
        )
    if optical.temperature_c is not None and optical.temperature_c >= TEMPERATURE_WARNING_C:
        findings.append(
            Finding(
                "warning",
                "optical.temperature",
                "Optical module is running hot",
                f"Module temperature is {optical.temperature_c} °C.",
                "Move the router somewhere ventilated and out of direct sun.",
            )
        )
    return findings


def _device_findings(snapshot: RouterSnapshot) -> list[Finding]:
    device = snapshot.device
    if device is None or device.cpu_percent is None or device.cpu_percent < CPU_WARNING_PERCENT:
        return []
    return [
        Finding(
            "warning",
            "device.cpu_high",
            "Router CPU is saturated",
            f"CPU use is {device.cpu_percent}%.",
            "Sustained high CPU on these units causes stalls; a reboot clears it temporarily.",
        )
    ]


def _wan_findings(snapshot: RouterSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for wan in snapshot.wan:
        if wan.connection_status and wan.connection_status.lower() != "connected":
            findings.append(
                Finding(
                    "critical",
                    "wan.down",
                    "Internet session is down",
                    f"{wan.encapsulation} status is {wan.connection_status}.",
                    "If the fibre signal is healthy, the fault is on the ISP side; report it with this reading.",
                )
            )
        if wan.encapsulation == "PPPoE" and wan.mtu and wan.mtu > 1492:
            findings.append(
                Finding(
                    "warning",
                    "wan.mtu",
                    "PPPoE MTU is too large",
                    f"MTU is {wan.mtu}; PPPoE leaves room for 1492 bytes.",
                    "Set the WAN MTU to 1492 to avoid stalled pages and streams.",
                )
            )
        if wan.behind_cgnat:
            findings.append(
                Finding(
                    "info",
                    "wan.cgnat",
                    "Connection is behind carrier-grade NAT",
                    f"The router's WAN address {wan.external_ip} is not publicly routable.",
                    "Inbound port forwarding will not work; ask the ISP for a public IP if you need it.",
                )
            )
    return findings


def _wifi_findings(wifi: WifiInfo, expected_country: str | None) -> list[Finding]:
    label = wifi.ssid or wifi.band
    findings: list[Finding] = []
    if not wifi.enabled:
        return findings
    if wifi.security_mode in {"open", "wep"}:
        findings.append(
            Finding(
                "critical",
                "wifi.insecure",
                f"{label} uses {wifi.security_mode.upper()} security",
                "Traffic on this network can be read or joined by anyone nearby.",
                "Switch to WPA2-PSK with AES.",
            )
        )
    elif wifi.security_mode in {"wpa-psk", "wpa/wpa2-psk"}:
        findings.append(
            Finding(
                "warning",
                "wifi.wpa1",
                f"{label} still allows WPA (version 1)",
                f"Security mode is {wifi.security_mode}.",
                "Use WPA2-PSK only; every device made in the last decade supports it.",
            )
        )
    if wifi.encryption and "TKIP" in wifi.encryption:
        findings.append(
            Finding(
                "warning",
                "wifi.tkip",
                f"{label} allows TKIP encryption",
                f"Encryption is {wifi.encryption}. 802.11n devices fall back to legacy 54 Mbps rates under TKIP.",
                "Set encryption to AES only.",
            )
        )
    if expected_country and wifi.country and wifi.country.upper() != expected_country.upper():
        findings.append(
            Finding(
                "warning",
                "wifi.country",
                f"{label} radio region is {wifi.country}",
                f"The configured regulatory domain does not match {expected_country.upper()}.",
                f"Set the Wi-Fi country to {expected_country.upper()} so channel and power limits are correct.",
            )
        )
    if wifi.band == "2.4GHz" and wifi.channel_width in {"20", "auto-20/40"}:
        findings.append(
            Finding(
                "info",
                "wifi.narrow_channel",
                f"{label} may be limited to 20 MHz",
                f"Channel width is {wifi.channel_width} MHz; auto mode usually settles on 20 MHz.",
                "If few neighbouring networks share the channel, fix the width at 40 MHz for up to double the speed.",
            )
        )
    if wifi.standard and "b" in wifi.standard.replace("11", "").lower():
        findings.append(
            Finding(
                "info",
                "wifi.legacy_b",
                f"{label} still allows 802.11b clients",
                f"Mode is {wifi.standard}.",
                "Disable 802.11b if no very old devices need it; one 11b client slows the whole channel.",
            )
        )
    return findings


def assess_snapshot(snapshot: RouterSnapshot, settings: Settings) -> list[Finding]:
    findings = _optical_findings(snapshot) + _device_findings(snapshot) + _wan_findings(snapshot)
    for wifi in snapshot.wifi:
        findings.extend(_wifi_findings(wifi, settings.router_expected_country))
    return sorted(findings, key=lambda item: SEVERITY_ORDER[item.severity], reverse=True)


def overall_status(findings: list[Finding]) -> str:
    if any(item.severity == "critical" for item in findings):
        return "critical"
    if any(item.severity == "warning" for item in findings):
        return "warning"
    return "ok"


class RouterHealthService:
    def __init__(self, settings: Settings, controller: RouterController) -> None:
        self.settings = settings
        self.controller = controller

    def run(self) -> int:
        with SessionLocal() as db:
            sample = RouterHealthSample(created_at=datetime.now(timezone.utc))
            try:
                snapshot = self.controller.health_snapshot()
                if snapshot is None:
                    raise RuntimeError("The configured router adapter does not provide health data")
            except Exception as exc:
                logger.warning("Router health poll failed: %s", exc)
                sample.status = "failed"
                sample.error = str(exc)[:1000]
                db.add(sample)
                db.commit()
                return sample.id

            findings = assess_snapshot(snapshot, self.settings)
            sample.status = overall_status(findings)
            sample.model = snapshot.model
            if snapshot.optical:
                sample.rx_power_dbm = snapshot.optical.rx_power_dbm
                sample.tx_power_dbm = snapshot.optical.tx_power_dbm
                sample.temperature_c = snapshot.optical.temperature_c
            if snapshot.device:
                sample.cpu_percent = snapshot.device.cpu_percent
                sample.uptime_seconds = snapshot.device.uptime_seconds
            if snapshot.wan:
                sample.wan_status = snapshot.wan[0].connection_status
            sample.snapshot_json = json.dumps(snapshot.as_dict(), default=str)
            sample.findings_json = json.dumps([item.as_dict() for item in findings])
            db.add(sample)
            for item in findings:
                if item.severity == "info":
                    continue
                raise_alert(
                    db,
                    severity=item.severity,
                    alert_type="router_health",
                    title=item.title,
                    message=f"{item.detail} {item.recommendation}",
                    dedupe_key=f"router:{item.code}",
                )
            db.commit()
            return sample.id
