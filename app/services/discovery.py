from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import Settings
from app.database import SessionLocal
from app.models import Device, DiscoveryRun
from app.services.alerts import raise_alert
from app.services.enrichment import infer_device_category
from app.services.network import NetworkContext, detect_network
from app.services.vendors import vendor_for_mac

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredDevice:
    ip_address: str
    mac_address: str
    hostname: str | None


def _hostname(ip_address: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, TimeoutError):
        return None


def arp_scan(context: NetworkContext, timeout: int = 2) -> list[DiscoveredDevice]:
    from scapy.all import ARP, Ether, srp

    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=context.subnet),
        timeout=timeout,
        iface=context.interface,
        verbose=False,
    )
    addresses: dict[str, str] = {}
    for _, response in answered:
        mac = str(response.hwsrc).lower()
        ip = str(response.psrc)
        addresses[mac] = ip
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(addresses)))) as pool:
        hostnames = dict(zip(addresses, pool.map(_hostname, addresses.values())))
    return [
        DiscoveredDevice(ip_address=ip, mac_address=mac, hostname=hostnames[mac])
        for mac, ip in addresses.items()
    ]


class DiscoveryService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self) -> int:
        context = detect_network(self.settings.subnet, self.settings.network_interface)
        with SessionLocal() as db:
            run = DiscoveryRun(subnet=context.subnet, interface=context.interface)
            db.add(run)
            db.commit()
            try:
                discovered = arp_scan(context)
                now = datetime.now(timezone.utc)
                for item in discovered:
                    device = db.scalar(select(Device).where(Device.mac_address == item.mac_address))
                    if device is None:
                        vendor = vendor_for_mac(item.mac_address)
                        device = Device(
                            ip_address=item.ip_address,
                            mac_address=item.mac_address,
                            hostname=item.hostname,
                            vendor=vendor,
                            category=infer_device_category(item.hostname, vendor),
                            first_seen=now,
                        )
                        db.add(device)
                        db.flush()
                        raise_alert(
                            db,
                            severity="warning",
                            alert_type="new_device",
                            title="New device joined",
                            message=f"{item.hostname or item.ip_address} appeared with MAC {item.mac_address}.",
                            dedupe_key=f"new-device:{item.mac_address}",
                            device_id=device.id,
                        )
                    else:
                        was_online = device.is_online
                        device.ip_address = item.ip_address
                        device.hostname = item.hostname or device.hostname
                        if not was_online:
                            raise_alert(
                                db,
                                severity="info",
                                alert_type="device_online",
                                title="Device is back online",
                                message=f"{device.hostname or device.ip_address} reconnected.",
                                dedupe_key=f"device-online:{device.id}",
                                device_id=device.id,
                            )
                    device.last_seen = now
                    device.is_online = True
                cutoff = now - timedelta(seconds=self.settings.device_offline_after_seconds)
                stale_devices = db.scalars(
                    select(Device).where(Device.is_online.is_(True), Device.last_seen < cutoff)
                )
                for stale_device in stale_devices:
                    stale_device.is_online = False
                    raise_alert(
                        db,
                        severity="info",
                        alert_type="device_offline",
                        title="Device went offline",
                        message=f"{stale_device.hostname or stale_device.ip_address} is no longer responding.",
                        dedupe_key=f"device-offline:{stale_device.id}",
                        device_id=stale_device.id,
                    )
                run.completed_at = now
                run.devices_found = len(discovered)
                run.status = "completed"
                db.commit()
                return len(discovered)
            except Exception as exc:
                db.rollback()
                run = db.get(DiscoveryRun, run.id)
                run.completed_at = datetime.now(timezone.utc)
                run.status = "failed"
                run.error = str(exc)[:2000]
                db.commit()
                logger.exception("Network discovery failed")
                raise
