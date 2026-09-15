from __future__ import annotations

import logging
import ipaddress
from datetime import datetime, timezone
from threading import Event, Lock, Thread

from sqlalchemy import select

from app.config import Settings
from app.database import SessionLocal
from app.models import Device, DnsObservation, TrafficFlow
from app.services.alerts import raise_alert
from app.services.network import detect_network

logger = logging.getLogger(__name__)


def _bucket_start(moment: datetime) -> datetime:
    return moment.replace(second=0, microsecond=0)


class TrafficCollector:
    """Stores packet headers and counters only; packet payloads are never retained."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._sniffer = None
        self._lock = Lock()
        self._local_subnet = None
        self._capture_started = Event()
        self.state = "disabled" if not settings.traffic_capture_enabled else "starting"
        self.error: str | None = None

    def start(self) -> None:
        if not self.settings.traffic_capture_enabled:
            return
        try:
            from scapy.all import AsyncSniffer

            context = detect_network(self.settings.subnet, self.settings.network_interface)
            self._local_subnet = ipaddress.ip_network(context.subnet, strict=False)
            self._sniffer = AsyncSniffer(
                iface=context.interface,
                filter=self.settings.capture_bpf_filter,
                prn=self.process_packet,
                store=False,
                started_callback=self._capture_started.set,
            )
            self._sniffer.start()
            if not self._capture_started.wait(timeout=1):
                if self._sniffer.exception:
                    raise self._sniffer.exception
                raise RuntimeError("Packet capture did not finish starting")
            self.state = "running"
            Thread(target=self._monitor_sniffer, name="capture-health", daemon=True).start()
            logger.info("Passive metadata capture started on %s", context.interface or "default interface")
        except Exception as exc:
            self.state = "error"
            self.error = str(exc)[:500]
            logger.exception("Passive metadata capture could not start")

    def _monitor_sniffer(self) -> None:
        try:
            self._sniffer.join()
        except Exception as exc:
            self.state = "error"
            self.error = str(exc)[:500]
            logger.exception("Passive metadata capture stopped unexpectedly")

    def stop(self) -> None:
        if self._sniffer and self._sniffer.running:
            self._sniffer.stop()
            self.state = "stopped"

    def process_packet(self, packet) -> None:
        try:
            self._record_dns(packet)
            self._record_flow(packet)
        except Exception:
            logger.exception("Failed to process packet metadata")

    def _record_dns(self, packet) -> None:
        from scapy.layers.dns import DNS, DNSRR

        if not packet.haslayer(DNS) or packet[DNS].qr != 1:
            return
        answers = packet[DNS].an
        for index in range(int(packet[DNS].ancount)):
            answer = answers[index]
            if not isinstance(answer, DNSRR) or int(answer.type) not in (1, 28):
                continue
            domain = bytes(answer.rrname).decode(errors="ignore").rstrip(".").lower()
            resolved_ip = str(answer.rdata)
            now = datetime.now(timezone.utc)
            with SessionLocal() as db:
                observation = db.scalar(
                    select(DnsObservation).where(
                        DnsObservation.domain == domain, DnsObservation.resolved_ip == resolved_ip
                    )
                )
                if observation:
                    observation.last_seen = now
                else:
                    db.add(DnsObservation(domain=domain, resolved_ip=resolved_ip, first_seen=now, last_seen=now))
                db.commit()

    def _record_flow(self, packet) -> None:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6

        if packet.haslayer(IP):
            source_ip, destination_ip = str(packet[IP].src), str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            source_ip, destination_ip = str(packet[IPv6].src), str(packet[IPv6].dst)
        else:
            return
        if self._local_subnet is None:
            context = detect_network(self.settings.subnet, self.settings.network_interface)
            self._local_subnet = ipaddress.ip_network(context.subnet, strict=False)
        source_local = ipaddress.ip_address(source_ip) in self._local_subnet
        destination_local = ipaddress.ip_address(destination_ip) in self._local_subnet
        if not source_local and not destination_local:
            return
        protocol = "OTHER"
        source_port = destination_port = None
        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port, destination_port = int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port, destination_port = int(packet[UDP].sport), int(packet[UDP].dport)

        now = datetime.now(timezone.utc)
        bucket = _bucket_start(now)
        with self._lock, SessionLocal() as db:
            direction = "local" if source_local and destination_local else "outbound" if source_local else "inbound"
            device_ip = source_ip if source_local else destination_ip
            device = db.scalar(select(Device).where(Device.ip_address == device_ip))
            domain = None
            if direction == "outbound":
                domain = db.scalar(
                    select(DnsObservation.domain)
                    .where(DnsObservation.resolved_ip == destination_ip)
                    .order_by(DnsObservation.last_seen.desc())
                    .limit(1)
                )
            flow = db.scalar(
                select(TrafficFlow).where(
                    TrafficFlow.bucket_start == bucket,
                    TrafficFlow.source_ip == source_ip,
                    TrafficFlow.destination_ip == destination_ip,
                    TrafficFlow.protocol == protocol,
                    TrafficFlow.destination_port == destination_port,
                )
            )
            if flow:
                flow.packet_count += 1
                flow.byte_count += int(len(packet))
                flow.last_seen = now
                flow.destination_domain = flow.destination_domain or domain
            else:
                db.add(
                    TrafficFlow(
                        device_id=device.id if device else None,
                        bucket_start=bucket,
                        source_ip=source_ip,
                        destination_ip=destination_ip,
                        destination_domain=domain,
                        direction=direction,
                        protocol=protocol,
                        source_port=source_port,
                        destination_port=destination_port,
                        packet_count=1,
                        byte_count=int(len(packet)),
                        first_seen=now,
                        last_seen=now,
                    )
                )
                if direction == "outbound" and destination_port in {23, 2323, 3389, 4444, 5555, 6667}:
                    device_name = device.hostname if device and device.hostname else device_ip
                    raise_alert(
                        db,
                        severity="warning",
                        alert_type="unusual_port",
                        title="Unusual outbound port",
                        message=f"{device_name} connected to {destination_ip}:{destination_port} over {protocol}.",
                        dedupe_key=f"unusual-port:{device.id if device else device_ip}:{destination_port}:{now:%Y%m%d}",
                        device_id=device.id if device else None,
                    )
            db.commit()
