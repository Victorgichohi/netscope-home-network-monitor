from __future__ import annotations

import json
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import median

from app.config import Settings
from app.database import SessionLocal
from app.models import DiagnosticRun
from app.services.network import NetworkContext, detect_network


@dataclass(frozen=True)
class ProbeResult:
    status: str
    latency_ms: int | None = None
    packet_loss_percent: int | None = None


def ping_host(host: str, count: int = 3) -> ProbeResult:
    system = platform.system()
    command = ["ping", "-n", str(count), "-w", "1000", host] if system == "Windows" else ["ping", "-c", str(count), host]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=count + 4, check=False)
    except (OSError, subprocess.SubprocessError):
        return ProbeResult("unknown")
    output = f"{result.stdout}\n{result.stderr}"
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet )?loss", output, re.IGNORECASE)
    latencies = [float(value) for value in re.findall(r"time[=<]\s*(\d+(?:\.\d+)?)\s*ms", output, re.IGNORECASE)]
    loss = round(float(loss_match.group(1))) if loss_match else (0 if result.returncode == 0 else 100)
    latency = round(median(latencies)) if latencies else None
    return ProbeResult("ok" if result.returncode == 0 else "failed", latency, loss)


def tcp_probe(targets: tuple[tuple[str, int], ...]) -> ProbeResult:
    latencies: list[float] = []
    for host, port in targets:
        started = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=2):
                latencies.append((time.perf_counter() - started) * 1000)
        except OSError:
            continue
    return ProbeResult("ok", round(median(latencies))) if latencies else ProbeResult("failed")


def dns_probe(hostname: str) -> ProbeResult:
    started = time.perf_counter()
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, TimeoutError, OSError):
        return ProbeResult("failed")
    latency = round((time.perf_counter() - started) * 1000)
    return ProbeResult("ok", latency) if addresses else ProbeResult("failed")


def recommendations_for(gateway: ProbeResult, internet: ProbeResult, dns: ProbeResult) -> list[str]:
    if internet.status != "ok":
        if gateway.status == "ok":
            return [
                "Your device can reach the router, but the internet is unavailable. Check the router's internet light and your ISP status before restarting anything.",
                "If the ISP reports no outage, restart the router once and wait up to five minutes.",
            ]
        return [
            "Your device cannot reliably reach the router. Move closer to Wi-Fi, reconnect, and check that the router has power.",
            "Try another device. If every device is offline, restart the router once.",
        ]
    if dns.status != "ok":
        return [
            "The internet connection works, but website names are not resolving. Reconnect to Wi-Fi or try a trusted DNS provider.",
            "Avoid restarting the router repeatedly; this looks like a DNS issue rather than a total outage.",
        ]
    if internet.latency_ms is not None and internet.latency_ms >= 250:
        return [
            "The connection works but is responding slowly. Pause large downloads and compare performance near the router.",
            "Run this check again at a quieter time to separate Wi-Fi congestion from an ISP slowdown.",
        ]
    if gateway.packet_loss_percent and gateway.packet_loss_percent >= 20:
        return [
            "The Wi-Fi path to your router is dropping packets. Move closer and reduce obstacles before blaming the ISP.",
            "If the problem affects one room, consider repositioning the router or adding a wired access point.",
        ]
    return [
        "Your basic connection checks look healthy. If an app still feels slow, the issue may be with that service or temporary congestion.",
    ]


class NetworkDiagnosticsService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self) -> int:
        created_at = datetime.now(timezone.utc)
        context: NetworkContext | None = None
        with SessionLocal() as db:
            run = DiagnosticRun(created_at=created_at)
            db.add(run)
            db.commit()
            try:
                context = detect_network(self.settings.subnet, self.settings.network_interface)
                gateway = ping_host(context.gateway_ip) if context.gateway_ip else ProbeResult("unknown")
                internet = tcp_probe((("1.1.1.1", 443), ("8.8.8.8", 53)))
                dns = dns_probe(self.settings.diagnostic_hostname)
                recommendations = recommendations_for(gateway, internet, dns)

                if internet.status != "ok":
                    status, summary = "offline", "Your internet connection appears to be offline"
                elif dns.status != "ok":
                    status, summary = "attention", "Internet is available, but DNS needs attention"
                elif internet.latency_ms is not None and internet.latency_ms >= 250:
                    status, summary = "attention", "Your internet is working, but responding slowly"
                elif gateway.packet_loss_percent and gateway.packet_loss_percent >= 20:
                    status, summary = "attention", "Your Wi-Fi connection may be unstable"
                else:
                    status, summary = "healthy", "Your connection looks healthy"

                run.completed_at = datetime.now(timezone.utc)
                run.status = status
                run.summary = summary
                run.interface = context.interface
                run.local_ip = context.local_ip
                run.gateway_ip = context.gateway_ip
                run.subnet = context.subnet
                run.gateway_status = gateway.status
                run.gateway_latency_ms = gateway.latency_ms
                run.internet_status = internet.status
                run.internet_latency_ms = internet.latency_ms
                run.dns_status = dns.status
                run.dns_latency_ms = dns.latency_ms
                run.packet_loss_percent = gateway.packet_loss_percent
                run.recommendations_json = json.dumps(recommendations)
                db.commit()
                return run.id
            except Exception as exc:
                db.rollback()
                run = db.get(DiagnosticRun, run.id)
                run.completed_at = datetime.now(timezone.utc)
                run.status = "error"
                run.summary = "The health check could not finish"
                run.error = str(exc)[:1000]
                if context:
                    run.interface, run.local_ip, run.gateway_ip, run.subnet = (
                        context.interface, context.local_ip, context.gateway_ip, context.subnet
                    )
                db.commit()
                raise
