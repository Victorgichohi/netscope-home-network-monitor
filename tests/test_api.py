from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import Alert, Device, TrafficFlow, User


def test_health_is_public(client):
    response = client.get("/health")
    assert response.json() == {"status": "ok"}
    assert response.headers["x-frame-options"] == "DENY"


def test_api_requires_authentication(client):
    assert client.get("/api/devices").status_code == 401


def test_login_rejects_bad_password(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert response.status_code == 401


def test_first_run_setup_is_local_and_single_use(client):
    with SessionLocal() as db:
        db.query(User).delete()
        db.commit()
    assert client.get("/api/auth/setup-status").json() == {"required": True}
    response = client.post(
        "/api/auth/setup",
        json={"username": "owner", "password": "a long local password"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "owner"
    assert client.post(
        "/api/auth/setup",
        json={"username": "second", "password": "another long password"},
    ).status_code == 409


def test_device_inventory_and_update(authenticated_client):
    with SessionLocal() as db:
        db.add(Device(ip_address="192.168.1.40", mac_address="00:11:22:33:44:55", hostname="laptop"))
        db.commit()
    devices = authenticated_client.get("/api/devices")
    assert devices.status_code == 200
    device_id = devices.json()[0]["id"]
    updated = authenticated_client.patch(
        f"/api/devices/{device_id}",
        json={"notes": "Trusted workstation", "category": "computer", "trust_status": "trusted"},
    )
    assert updated.status_code == 200
    assert updated.json()["notes"] == "Trusted workstation"
    assert updated.json()["category"] == "computer"
    assert updated.json()["trust_status"] == "trusted"


def test_mutation_requires_csrf(client):
    login = client.post("/api/auth/login", json={"username": "admin", "password": "correct horse battery staple"})
    assert login.status_code == 200
    response = client.post("/api/router/reboot", json={"confirmation": "REBOOT"})
    assert response.status_code == 403


def test_traffic_aggregation(authenticated_client):
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    with SessionLocal() as db:
        device = Device(ip_address="192.168.1.9", mac_address="aa:bb:cc:dd:ee:ff")
        db.add(device)
        db.flush()
        db.add(TrafficFlow(device_id=device.id, bucket_start=now, source_ip=device.ip_address, destination_ip="1.1.1.1", destination_domain="one.one.one.one", protocol="UDP", destination_port=53, packet_count=5, byte_count=500))
        db.commit()
    response = authenticated_client.get("/api/traffic/top-destinations")
    assert response.status_code == 200
    assert response.json()[0] == {
        "destination": "one.one.one.one",
        "packets": 5,
        "bytes": 500,
        "organization": "One",
        "category": "Other",
    }
    top_devices = authenticated_client.get("/api/traffic/top-devices")
    assert top_devices.status_code == 200
    assert top_devices.json()[0]["bytes"] == 500
    protocols = authenticated_client.get("/api/traffic/protocols")
    assert protocols.json()[0]["protocol"] == "UDP"


def test_disabled_router_cannot_reboot(authenticated_client):
    response = authenticated_client.post("/api/router/reboot", json={"confirmation": "REBOOT"})
    assert response.status_code == 502


def test_system_status_reports_disabled_capture(authenticated_client):
    response = authenticated_client.get("/api/system/status")
    assert response.status_code == 200
    assert response.json()["traffic_capture"] == "disabled"


def test_alert_summary_and_read_flow(authenticated_client):
    with SessionLocal() as db:
        db.add(
            Alert(
                severity="warning",
                alert_type="new_device",
                title="New device",
                message="A device appeared.",
                dedupe_key="test:new-device",
            )
        )
        db.commit()
    summary = authenticated_client.get("/api/security/summary")
    assert summary.status_code == 200
    assert summary.json()["unread_alerts"] == 1
    alerts = authenticated_client.get("/api/alerts").json()
    assert len(alerts) == 1
    assert authenticated_client.post(f"/api/alerts/{alerts[0]['id']}/read").status_code == 200
    assert authenticated_client.get("/api/security/summary").json()["unread_alerts"] == 0


def test_topology_contains_gateway_and_devices(authenticated_client):
    with SessionLocal() as db:
        db.add(Device(ip_address="192.168.1.3", mac_address="de:ad:be:ef:00:01", hostname="phone"))
        db.commit()
    response = authenticated_client.get("/api/topology")
    assert response.status_code == 200
    assert response.json()["nodes"][0]["id"] == "router"
    assert len(response.json()["links"]) == 1
