from app.services import network


def test_detect_network_uses_configured_subnet(monkeypatch):
    monkeypatch.setattr(network, "detect_local_ip", lambda: "192.168.50.10")
    monkeypatch.setattr(network, "detect_interface", lambda _: "eth0")
    result = network.detect_network("192.168.50.99/24", None)
    assert result.local_ip == "192.168.50.10"
    assert result.interface == "eth0"
    assert result.subnet == "192.168.50.0/24"
