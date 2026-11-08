import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from app.config import Settings
from app.database import SessionLocal
from app.models import Alert, RouterHealthSample
from app.router_control.base import RouterController, RouterStatus
from app.router_control.huawei_ont import (
    DEVICE_PAGE,
    OPTIC_PAGE,
    WAN_PAGE,
    WLAN_BASIC_PAGE,
    WLAN_INFO_PAGE,
    HuaweiOntClient,
    HuaweiOntController,
    OpticalInfo,
    RouterSnapshot,
    WanInfo,
    WifiInfo,
    decode_js_string,
    extract_constructor_calls,
    parse_device,
    parse_optical,
    parse_wan,
    parse_wifi,
)
from app.services.router_health import RouterHealthService, assess_snapshot, overall_status

FIXTURES = Path(__file__).parent / "fixtures" / "huawei_hg8546m"
SECRETS = ("fixture-wifi-passphrase", "fixture-pppoe-user", "fixture-password-hash", "12345670", "FIXTURESERIAL")


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def settings(**overrides) -> Settings:
    values = {"router_adapter": "huawei_ont", "router_username": "admin", "router_password": "pw"}
    values.update(overrides)
    return Settings(**values)


def test_decode_js_string_handles_hex_escapes():
    assert decode_js_string(r"\x2d17\x2e03") == "-17.03"
    assert decode_js_string(r"On\x2dsite\x20") == "On-site "


def test_constructor_calls_skip_definitions_and_empty_calls():
    text = 'function stWlan(a,b){}\nWlan[i] = new stWlan();\nvar x = new stWlan("one", "t\\x77o", 3);'
    assert extract_constructor_calls(text, "stWlan") == [["one", "two", "3"]]


def test_parse_optical():
    optical = parse_optical(fixture("opticinfo.asp"))
    assert optical == OpticalInfo(
        tx_power_dbm=2.29, rx_power_dbm=-17.03, voltage_mv=3338, temperature_c=50, bias_current_ma=15
    )


def test_parse_device_skips_identifiers():
    device = parse_device(fixture("deviceinfo.asp"))
    assert device.model == "HG8546M"
    assert device.software_version == "V5R019C00S100"
    assert device.hardware_version == "16FC.A"
    assert device.uptime_seconds == 31560
    assert device.cpu_percent == 11
    assert "4857544300000000" not in json.dumps(device.__dict__)


def test_parse_wan_flags_cgnat_and_never_reads_credentials():
    (wan,) = parse_wan(fixture("wan_list.asp"))
    assert wan.connection_status == "Connected"
    assert wan.external_ip == "10.14.255.236"
    assert wan.dns_servers == ["8.8.8.8", "8.8.4.4"]
    assert wan.mtu == 1492
    assert wan.behind_cgnat is True
    serialized = json.dumps(wan.__dict__)
    assert "fixture-pppoe-user" not in serialized
    assert "fixture-password-hash" not in serialized


def test_parse_wifi_combines_config_and_live_channel():
    (wifi,) = parse_wifi(fixture("wlanbasic.asp"), fixture("wlaninfo.asp"))
    assert wifi.ssid == "On-site"
    assert wifi.channel_mode == "auto"
    assert wifi.current_channel == 11
    assert wifi.channel_width == "auto-20/40"
    assert wifi.country == "CN"
    assert wifi.security_mode == "wpa/wpa2-psk"
    assert wifi.encryption == "TKIP+AES"
    serialized = json.dumps(wifi.__dict__)
    assert "fixture-wifi-passphrase" not in serialized
    assert "12345670" not in serialized


def test_parse_wifi_reports_hardened_configuration():
    basic = (
        fixture("wlanbasic.asp")
        .replace('"WPAand11i"', '"11i"')
        .replace('"CN","1","0"', '"KE","1","2"')
    )
    (wifi,) = parse_wifi(basic)
    assert wifi.security_mode == "wpa2-psk"
    assert wifi.encryption == "AES"
    assert wifi.channel_width == "40"
    assert wifi.country == "KE"


def fixture_snapshot() -> RouterSnapshot:
    return RouterSnapshot(
        fetched_at=datetime.now(timezone.utc),
        model="HG8546M",
        optical=parse_optical(fixture("opticinfo.asp")),
        device=parse_device(fixture("deviceinfo.asp")),
        wan=parse_wan(fixture("wan_list.asp")),
        wifi=parse_wifi(fixture("wlanbasic.asp"), fixture("wlaninfo.asp")),
    )


def test_assessment_of_factory_wifi_settings():
    findings = assess_snapshot(fixture_snapshot(), settings(router_expected_country="KE"))
    codes = {item.code for item in findings}
    assert {"wifi.wpa1", "wifi.tkip", "wifi.country", "wifi.narrow_channel", "wifi.legacy_b", "wan.cgnat"} <= codes
    assert not any(code.startswith("optical.") for code in codes)
    assert overall_status(findings) == "warning"
    assert findings[0].severity == "warning"


@pytest.mark.parametrize(
    ("rx", "expected"),
    [(-17.0, None), (-25.5, "optical.rx_marginal"), (-28.2, "optical.rx_low"), (-6.0, "optical.rx_overload")],
)
def test_optical_thresholds(rx, expected):
    snapshot = RouterSnapshot(
        fetched_at=datetime.now(timezone.utc),
        optical=OpticalInfo(tx_power_dbm=2.0, rx_power_dbm=rx, voltage_mv=3300, temperature_c=45, bias_current_ma=15),
    )
    codes = [item.code for item in assess_snapshot(snapshot, settings())]
    assert codes == ([expected] if expected else [])


def test_wan_down_and_oversized_pppoe_mtu_are_flagged():
    snapshot = RouterSnapshot(
        fetched_at=datetime.now(timezone.utc),
        wan=[WanInfo("PPPoE", "Disconnected", None, None, [], 1500, None)],
    )
    findings = assess_snapshot(snapshot, settings())
    assert [item.code for item in findings] == ["wan.down", "wan.mtu"]
    assert overall_status(findings) == "critical"


def test_open_wifi_is_critical():
    wifi = WifiInfo("2.4GHz", True, "Cafe", "11n", "fixed", 6, "40", "KE", 100, "open", None)
    snapshot = RouterSnapshot(fetched_at=datetime.now(timezone.utc), wifi=[wifi])
    findings = assess_snapshot(snapshot, settings())
    assert [item.code for item in findings] == ["wifi.insecure"]


def router_transport(pages: dict[str, str], *, accept_login: bool = True) -> httpx.MockTransport:
    state = {"logged_in": False, "logins": [], "logouts": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        if path == "/asp/GetRandCount.asp":
            return httpx.Response(200, text="﻿token-123")
        if path == "/login.cgi":
            state["logins"].append(dict(httpx.QueryParams(request.content.decode())))
            state["logged_in"] = accept_login
            return httpx.Response(200, text="<script>window.location='/index.asp'</script>")
        if path.startswith("/logout.cgi"):
            state["logouts"] += 1
            state["logged_in"] = False
            return httpx.Response(200, text="bye")
        if not state["logged_in"]:
            return httpx.Response(200, text=fixture("login.asp"))
        if path == "/index.asp":
            return httpx.Response(200, text="<frameset></frameset>")
        if path in pages:
            return httpx.Response(200, text=pages[path])
        return httpx.Response(404, text="not found")

    transport = httpx.MockTransport(handler)
    transport.state = state  # type: ignore[attr-defined]
    return transport


ALL_PAGES = {
    OPTIC_PAGE: "opticinfo.asp",
    DEVICE_PAGE: "deviceinfo.asp",
    WAN_PAGE: "wan_list.asp",
    WLAN_BASIC_PAGE: "wlanbasic.asp",
    WLAN_INFO_PAGE: "wlaninfo.asp",
}


def test_client_logs_in_reads_pages_and_logs_out():
    transport = router_transport({path: fixture(name) for path, name in ALL_PAGES.items()})
    client = HuaweiOntClient("192.168.100.1", "telecomadmin", "secret", transport=transport)
    snapshot = client.snapshot()
    assert snapshot.model == "HG8546M"
    assert snapshot.optical.rx_power_dbm == -17.03
    assert snapshot.wifi[0].current_channel == 11
    assert snapshot.errors == {}
    (login,) = transport.state["logins"]
    assert login["x.X_HW_Token"] == "token-123"
    assert login["PassWord"] == "c2VjcmV0"
    assert transport.state["logouts"] == 1
    serialized = json.dumps(snapshot.as_dict(), default=str)
    for secret in SECRETS:
        assert secret not in serialized


def test_client_keeps_partial_snapshot_when_a_page_is_missing():
    pages = {path: fixture(name) for path, name in ALL_PAGES.items() if path != WLAN_INFO_PAGE}
    snapshot = HuaweiOntClient("r", "u", "p", transport=router_transport(pages)).snapshot()
    assert "wlan_info" in snapshot.errors
    assert snapshot.wifi[0].current_channel is None
    assert snapshot.optical is not None


def test_client_reports_rejected_login():
    client = HuaweiOntClient("r", "u", "bad", transport=router_transport({}, accept_login=False))
    with pytest.raises(RuntimeError, match="rejected the login"):
        client.snapshot()


def test_controller_status_and_read_only_reboot():
    transport = router_transport({path: fixture(name) for path, name in ALL_PAGES.items()})
    controller = HuaweiOntController(settings(router_host="192.168.100.1"), transport=transport)
    status = controller.status()
    assert status.available is True
    assert "RX -17.03 dBm" in status.detail
    with pytest.raises(RuntimeError, match="read-only"):
        controller.reboot()


def test_controller_requires_credentials():
    with pytest.raises(ValueError):
        HuaweiOntController(Settings(router_adapter="huawei_ont"))


class FakeController(RouterController):
    def __init__(self, snapshot=None, error=None):
        self.snapshot, self.error = snapshot, error

    def status(self) -> RouterStatus:
        return RouterStatus(True, "fake")

    def reboot(self) -> None:
        raise RuntimeError("no")

    def health_snapshot(self):
        if self.error:
            raise self.error
        return self.snapshot


def test_health_service_stores_sample_and_raises_deduplicated_alerts():
    service = RouterHealthService(settings(router_expected_country="KE"), FakeController(fixture_snapshot()))
    first = service.run()
    service.run()
    with SessionLocal() as db:
        sample = db.get(RouterHealthSample, first)
        assert sample.status == "warning"
        assert sample.rx_power_dbm == -17.03
        assert sample.uptime_seconds == 31560
        assert sample.wan_status == "Connected"
        stored = sample.snapshot_json + sample.findings_json
        for secret in SECRETS:
            assert secret not in stored
        alerts = db.query(Alert).filter(Alert.alert_type == "router_health").all()
        assert {alert.dedupe_key for alert in alerts} == {"router:wifi.wpa1", "router:wifi.tkip", "router:wifi.country"}
        assert db.query(RouterHealthSample).count() == 2


def test_health_service_records_failures():
    sample_id = RouterHealthService(settings(), FakeController(error=RuntimeError("timeout"))).run()
    with SessionLocal() as db:
        sample = db.get(RouterHealthSample, sample_id)
        assert sample.status == "failed"
        assert sample.error == "timeout"


def test_router_health_api(authenticated_client):
    assert authenticated_client.get("/api/router/health/latest").json() is None
    assert authenticated_client.post("/api/router/health/run").status_code == 409

    RouterHealthService(settings(), FakeController(fixture_snapshot())).run()
    latest = authenticated_client.get("/api/router/health/latest").json()
    assert latest["rx_power_dbm"] == -17.03
    assert latest["snapshot"]["optical"]["temperature_c"] == 50
    assert any(item["code"] == "wifi.tkip" for item in latest["findings"])

    history = authenticated_client.get("/api/router/health/history?hours=24").json()
    assert len(history) == 1
    assert "snapshot" not in history[0]


def test_router_health_api_requires_authentication(client):
    assert client.get("/api/router/health/latest").status_code == 401
