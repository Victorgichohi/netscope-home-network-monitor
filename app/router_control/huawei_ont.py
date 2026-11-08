"""Read-only health adapter for Huawei EchoLife GPON ONTs (HG8546M and similar).

The HG8xxx web UI does not expose a JSON API. Each admin page embeds its
configuration as JavaScript constructor calls, for example::

    var opticInfos = new Array(new stOpticInfo("...", " 2.29", "-17.03", "3338", "50", "15", ...), null);

The parsers in this module extract those constructor arguments as strings and
map the fields NetScope needs. Field positions were taken from an HG8546M on
firmware V5R019C00S100; other firmware builds may shift positions, so every
parser is defensive and returns ``None`` rather than guessing.

Privacy: the pages also embed the Wi-Fi passphrase, WEP keys, the WPS PIN and
the PPPoE username/password hash. This module never reads those fields, and the
tests assert that they do not appear in parsed output.
"""

from __future__ import annotations

import base64
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network

import httpx

from app.config import Settings
from app.router_control.base import RouterController, RouterStatus

OPTIC_PAGE = "/html/amp/opticinfo/opticinfo.asp"
DEVICE_PAGE = "/html/ssmp/deviceinfo/deviceinfo.asp"
WAN_PAGE = "/html/bbsp/common/wan_list.asp"
WLAN_BASIC_PAGE = "/html/amp/wlanbasic/WlanBasic.asp?2G"
WLAN_INFO_PAGE = "/html/amp/wlaninfo/wlaninfo.asp"

CGNAT_NETWORK = IPv4Network("100.64.0.0/10")
LOGIN_MARKERS = ("loginbutton", "txt_Username", "LoginSubmit(")

# X_HW_HT20 values used by the 2.4 GHz configuration pages.
CHANNEL_WIDTHS = {"0": "auto-20/40", "1": "20", "2": "40", "3": "80", "4": "160"}


# --------------------------------------------------------------------------- #
# JavaScript literal extraction
# --------------------------------------------------------------------------- #

_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def decode_js_string(value: str) -> str:
    """Decode the ``\\xNN`` escapes Huawei uses for every embedded string."""
    value = _HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), value)
    return value.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")


def _read_arguments(text: str, start: int) -> list[str] | None:
    """Read quoted string arguments from ``start`` up to the closing parenthesis."""
    args: list[str] = []
    index = start
    length = len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n,":
            index += 1
            continue
        if char == ")":
            return args
        if char in "\"'":
            quote = char
            index += 1
            buffer: list[str] = []
            while index < length and text[index] != quote:
                if text[index] == "\\" and index + 1 < length:
                    buffer.append(text[index : index + 2])
                    index += 2
                    continue
                buffer.append(text[index])
                index += 1
            args.append(decode_js_string("".join(buffer)))
            index += 1
            continue
        # Bare literal such as a number or null.
        match = re.match(r"[^,)\s]+", text[index:])
        if match is None:
            return None
        args.append(match.group(0))
        index += match.end()
    return None


def extract_constructor_calls(text: str, constructor: str) -> list[list[str]]:
    """Return the argument list of every ``new <constructor>(...)`` call that has arguments."""
    calls: list[list[str]] = []
    for match in re.finditer(rf"new\s+{re.escape(constructor)}\s*\(", text):
        args = _read_arguments(text, match.end())
        if args:
            calls.append(args)
    return calls


def extract_js_var(text: str, name: str) -> str | None:
    """Return the first non-empty quoted value assigned to ``var <name>``."""
    for match in re.finditer(rf"var\s+{re.escape(name)}\s*=\s*(['\"])(.*?)\1\s*;", text):
        if match.group(2) != "":
            return decode_js_string(match.group(2))
    return None


def is_login_page(text: str) -> bool:
    return any(marker in text for marker in LOGIN_MARKERS)


def _float(value: str | None) -> float | None:
    try:
        return float(value.strip()) if value is not None else None
    except ValueError:
        return None


def _int(value: str | None) -> int | None:
    try:
        return int(value.strip().rstrip("%")) if value is not None else None
    except ValueError:
        return None


def _arg(args: list[str], index: int) -> str | None:
    return args[index] if index < len(args) else None


# --------------------------------------------------------------------------- #
# Parsed models
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class OpticalInfo:
    tx_power_dbm: float | None
    rx_power_dbm: float | None
    voltage_mv: int | None
    temperature_c: int | None
    bias_current_ma: int | None


@dataclass(frozen=True)
class DeviceInfo:
    model: str | None
    hardware_version: str | None
    software_version: str | None
    uptime_seconds: int | None
    cpu_percent: int | None


@dataclass(frozen=True)
class WanInfo:
    encapsulation: str
    connection_status: str | None
    external_ip: str | None
    gateway: str | None
    dns_servers: list[str]
    mtu: int | None
    behind_cgnat: bool | None


@dataclass(frozen=True)
class WifiInfo:
    band: str
    enabled: bool
    ssid: str | None
    standard: str | None
    channel_mode: str  # "auto" or "fixed"
    current_channel: int | None
    channel_width: str | None
    country: str | None
    transmit_power_percent: int | None
    security_mode: str | None
    encryption: str | None


@dataclass
class RouterSnapshot:
    fetched_at: datetime
    model: str = "huawei-ont"
    optical: OpticalInfo | None = None
    device: DeviceInfo | None = None
    wan: list[WanInfo] = field(default_factory=list)
    wifi: list[WifiInfo] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Page parsers
# --------------------------------------------------------------------------- #


def parse_optical(text: str) -> OpticalInfo | None:
    """stOpticInfo(domain, txPower, rxPower, voltage, temperature, bias, ...)."""
    calls = extract_constructor_calls(text, "stOpticInfo")
    if not calls:
        return None
    args = calls[0]
    return OpticalInfo(
        tx_power_dbm=_float(_arg(args, 1)),
        rx_power_dbm=_float(_arg(args, 2)),
        voltage_mv=_int(_arg(args, 3)),
        temperature_c=_int(_arg(args, 4)),
        bias_current_ma=_int(_arg(args, 5)),
    )


def parse_device(text: str) -> DeviceInfo | None:
    """stDeviceInfo(domain, serial, hardwareVersion, softwareVersion, model, ...).

    The serial number and MAC address are deliberately skipped.
    """
    calls = extract_constructor_calls(text, "stDeviceInfo")
    args = calls[0] if calls else []
    uptime = extract_js_var(text, "dev_uptime")
    cpu = extract_js_var(text, "cpuUsed")
    if not args and uptime is None and cpu is None:
        return None
    return DeviceInfo(
        model=_arg(args, 4),
        hardware_version=_arg(args, 2),
        software_version=_arg(args, 3),
        uptime_seconds=_int(uptime),
        cpu_percent=_int(cpu),
    )


def _cgnat(address: str | None) -> bool | None:
    if not address:
        return None
    try:
        ip = IPv4Address(address)
    except ValueError:
        return None
    return ip in CGNAT_NETWORK or ip.is_private


def parse_wan(text: str) -> list[WanInfo]:
    """Parse PPPoE WAN entries from wan_list.asp.

    WanPPP positions observed on V5R019C00S100: 10 connection status,
    12 external IP, 13 remote gateway, 16 DNS servers, 35 MRU/MTU. Positions
    17 and 18 hold the PPPoE username and password hash and are never read.
    """
    results: list[WanInfo] = []
    for args in extract_constructor_calls(text, "WanPPP"):
        if len(args) < 17:
            continue
        external_ip = _arg(args, 12) or None
        dns = [server.strip() for server in (_arg(args, 16) or "").split(",") if server.strip()]
        results.append(
            WanInfo(
                encapsulation="PPPoE",
                connection_status=_arg(args, 10) or _arg(args, 3),
                external_ip=external_ip,
                gateway=_arg(args, 13) or None,
                dns_servers=dns,
                mtu=_int(_arg(args, 35)),
                behind_cgnat=_cgnat(external_ip),
            )
        )
    return results


def _security(beacon_type: str | None, wlan_args: list[str]) -> tuple[str | None, str | None]:
    """Map stWlan beacon type to the encryption actually in force.

    stWlan positions: 7 BeaconType, 12 WPA encryption, 14 11i (WPA2) encryption,
    16 mixed WPA/WPA2 encryption.
    """
    mode_map = {
        "None": ("open", None),
        "Basic": ("wep", "WEP"),
        "WPA": ("wpa-psk", _arg(wlan_args, 12)),
        "11i": ("wpa2-psk", _arg(wlan_args, 14)),
        "WPAand11i": ("wpa/wpa2-psk", _arg(wlan_args, 16)),
    }
    if beacon_type not in mode_map:
        return beacon_type, None
    mode, encryption = mode_map[beacon_type]
    if encryption:
        encryption = encryption.replace("Encryption", "").replace("TKIPandAES", "TKIP+AES")
    return mode, encryption


def parse_wifi(basic_text: str, info_text: str | None = None) -> list[WifiInfo]:
    """Combine WlanBasic (configuration) with wlaninfo (live channel).

    stWlanWifi(domain, name, enable, ssid, mode, channel, power, country,
    autoChannelEnable, channelWidth). The passphrase lives in stPreSharedKey and
    is never parsed.
    """
    radios = extract_constructor_calls(basic_text, "stWlanWifi")
    wlans = {args[0]: args for args in extract_constructor_calls(basic_text, "stWlan") if len(args) > 16}
    live_channels: dict[str, int | None] = {}
    if info_text:
        for args in extract_constructor_calls(info_text, "stWlan"):
            if len(args) > 13 and args[0].startswith("InternetGatewayDevice"):
                live_channels[args[0]] = _int(args[13])
    results: list[WifiInfo] = []
    for args in radios:
        if len(args) < 10 or not args[0]:
            continue
        domain = args[0]
        wlan_args = wlans.get(domain, [])
        mode, encryption = _security(_arg(wlan_args, 7), wlan_args)
        configured_channel = _int(args[5])
        auto = args[8] == "1" or configured_channel == 0
        current = live_channels.get(domain) or (None if auto else configured_channel)
        results.append(
            WifiInfo(
                band="2.4GHz",
                enabled=args[2] == "1",
                ssid=args[3].strip() or None,
                standard=args[4] or None,
                channel_mode="auto" if auto else "fixed",
                current_channel=current,
                channel_width=CHANNEL_WIDTHS.get(args[9], args[9] or None),
                country=args[7] or None,
                transmit_power_percent=_int(args[6]),
                security_mode=mode,
                encryption=encryption,
            )
        )
    return results


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #


class HuaweiOntClient:
    """Minimal session client for the HG8xxx V5 web UI.

    The ONT allows a single admin web session at a time, so each poll logs in,
    reads the pages, and logs out again. Polling while someone uses the router
    UI in a browser will sign that browser out.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        scheme: str = "http",
        timeout: float = 8.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.base_url = f"{scheme}://{host}"
        self.timeout = timeout
        self.transport = transport

    def _client(self) -> httpx.Client:
        client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            follow_redirects=True,
            transport=self.transport,
            headers={"User-Agent": "NetScope/0.5"},
        )
        client.cookies.set("Cookie", "body:Language:english:id=-1")
        return client

    def _login(self, client: httpx.Client) -> None:
        token = client.post("/asp/GetRandCount.asp").text.strip().lstrip("﻿")
        if not token:
            raise RuntimeError("Router did not return a login token")
        response = client.post(
            "/login.cgi",
            data={
                "UserName": self.username,
                "PassWord": base64.b64encode(self.password.encode()).decode(),
                "Language": "english",
                "x.X_HW_Token": token,
            },
        )
        response.raise_for_status()
        landing = client.get("/index.asp")
        if is_login_page(landing.text):
            raise RuntimeError("Router rejected the login (check credentials, or another admin session is open)")

    def _logout(self, client: httpx.Client) -> None:
        try:
            client.post("/logout.cgi?RequestFile=html/logout.html")
        except httpx.HTTPError:
            pass

    def _page(self, client: httpx.Client, path: str) -> str:
        response = client.get(path)
        response.raise_for_status()
        if is_login_page(response.text):
            raise RuntimeError("Router session expired while reading pages")
        return response.text

    def snapshot(self) -> RouterSnapshot:
        snapshot = RouterSnapshot(fetched_at=datetime.now(timezone.utc))
        with self._client() as client:
            self._login(client)
            try:
                pages: dict[str, str] = {}
                for name, path in (
                    ("optical", OPTIC_PAGE),
                    ("device", DEVICE_PAGE),
                    ("wan", WAN_PAGE),
                    ("wlan_basic", WLAN_BASIC_PAGE),
                    ("wlan_info", WLAN_INFO_PAGE),
                ):
                    try:
                        pages[name] = self._page(client, path)
                    except Exception as exc:  # one missing page should not sink the snapshot
                        snapshot.errors[name] = str(exc)[:200]
            finally:
                self._logout(client)
        if "optical" in pages:
            snapshot.optical = parse_optical(pages["optical"])
        if "device" in pages:
            snapshot.device = parse_device(pages["device"])
            if snapshot.device and snapshot.device.model:
                snapshot.model = snapshot.device.model
        if "wan" in pages:
            snapshot.wan = parse_wan(pages["wan"])
        if "wlan_basic" in pages:
            snapshot.wifi = parse_wifi(pages["wlan_basic"], pages.get("wlan_info"))
        return snapshot


class HuaweiOntController(RouterController):
    """Read-only Huawei ONT adapter. Reboot is intentionally not implemented."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        if not settings.router_username or not settings.router_password:
            raise ValueError("HNM_ROUTER_USERNAME and HNM_ROUTER_PASSWORD are required for the huawei_ont adapter")
        self.settings = settings
        self.client = HuaweiOntClient(
            settings.router_host,
            settings.router_username,
            settings.router_password,
            transport=transport,
        )

    def status(self) -> RouterStatus:
        try:
            snapshot = self.client.snapshot()
        except Exception as exc:
            return RouterStatus(False, "huawei_ont", self.settings.router_host, str(exc)[:500])
        parts = [snapshot.model]
        if snapshot.optical and snapshot.optical.rx_power_dbm is not None:
            parts.append(f"RX {snapshot.optical.rx_power_dbm:.2f} dBm")
        if snapshot.device and snapshot.device.uptime_seconds is not None:
            parts.append(f"up {snapshot.device.uptime_seconds // 3600}h")
        return RouterStatus(True, "huawei_ont", self.settings.router_host, ", ".join(parts))

    def reboot(self) -> None:
        raise RuntimeError("Reboot is not supported by the read-only huawei_ont adapter")

    def health_snapshot(self) -> RouterSnapshot | None:
        return self.client.snapshot()
