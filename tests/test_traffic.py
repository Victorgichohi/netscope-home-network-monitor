from ipaddress import ip_network

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import Device, DnsObservation, TrafficFlow
from app.services.traffic import TrafficCollector


def test_collector_aggregates_headers_without_payload_storage():
    with SessionLocal() as db:
        db.add(Device(ip_address="192.168.1.20", mac_address="aa:00:00:00:00:01"))
        db.commit()

    collector = TrafficCollector(get_settings())
    collector._local_subnet = ip_network("192.168.1.0/24")
    packet = IP(src="192.168.1.20", dst="203.0.113.8") / UDP(sport=49152, dport=443) / Raw(b"not retained")
    collector.process_packet(packet)
    collector.process_packet(packet)

    with SessionLocal() as db:
        flow = db.scalar(select(TrafficFlow))
        assert flow.source_ip == "192.168.1.20"
        assert flow.destination_ip == "203.0.113.8"
        assert flow.destination_port == 443
        assert flow.packet_count == 2
        assert flow.byte_count == len(packet) * 2
        assert "payload" not in TrafficFlow.__table__.columns


def test_dns_response_is_used_for_destination_attribution():
    collector = TrafficCollector(get_settings())
    collector._local_subnet = ip_network("192.168.1.0/24")
    dns_response = (
        IP(src="192.168.1.1", dst="192.168.1.20")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1,
            qr=1,
            ancount=1,
            an=DNSRR(rrname="example.net", type="A", rdata="203.0.113.10"),
        )
    )
    collector.process_packet(dns_response)
    collector.process_packet(IP(src="192.168.1.20", dst="203.0.113.10") / UDP(sport=50000, dport=443))

    with SessionLocal() as db:
        observation = db.scalar(select(DnsObservation))
        assert observation.domain == "example.net"
        flow = db.scalar(
            select(TrafficFlow).where(TrafficFlow.destination_ip == "203.0.113.10")
        )
        assert flow.destination_domain == "example.net"


def test_collector_records_inbound_router_traffic():
    collector = TrafficCollector(get_settings())
    collector._local_subnet = ip_network("192.168.1.0/24")
    collector.process_packet(IP(src="203.0.113.5", dst="192.168.1.20") / UDP(sport=443, dport=50000))
    with SessionLocal() as db:
        flow = db.scalar(select(TrafficFlow))
        assert flow.direction == "inbound"
        assert flow.destination_ip == "192.168.1.20"


def test_collector_ignores_traffic_outside_local_network():
    collector = TrafficCollector(get_settings())
    collector._local_subnet = ip_network("192.168.1.0/24")
    collector.process_packet(IP(src="203.0.113.5", dst="198.51.100.8") / UDP(sport=443, dport=50000))
    with SessionLocal() as db:
        assert db.scalar(select(TrafficFlow)) is None


def test_collector_reports_async_start_failure(monkeypatch):
    from scapy import all as scapy_all

    class FailedSniffer:
        def __init__(self, **kwargs):
            self.exception = PermissionError("capture permission denied")
            self.running = False

        def start(self):
            return None

    monkeypatch.setattr(scapy_all, "AsyncSniffer", FailedSniffer)
    monkeypatch.setattr(
        "app.services.traffic.detect_network",
        lambda *_: type("Context", (), {"subnet": "192.168.1.0/24", "interface": "en0"})(),
    )
    settings = get_settings().model_copy(update={"traffic_capture_enabled": True})
    collector = TrafficCollector(settings)
    collector.start()
    assert collector.state == "error"
    assert collector.error == "capture permission denied"
