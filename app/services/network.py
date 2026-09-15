from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkContext:
    interface: str | None
    local_ip: str
    subnet: str
    gateway_ip: str | None = None


def _run(command: list[str]) -> str:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def detect_local_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("1.1.1.1", 53))
            return str(sock.getsockname()[0])
        except OSError:
            return "127.0.0.1"


def detect_interface(local_ip: str) -> str | None:
    system = platform.system()
    if system == "Linux":
        output = _run(["ip", "-o", "-4", "addr", "show"])
        match = re.search(rf"^\d+:\s+([^\s]+).*\binet\s+{re.escape(local_ip)}/", output, re.MULTILINE)
        return match.group(1) if match else None
    if system == "Darwin":
        output = _run(["ifconfig"])
        current = None
        for line in output.splitlines():
            if line and not line[0].isspace():
                current = line.split(":", 1)[0]
            if re.search(rf"\binet\s+{re.escape(local_ip)}\b", line):
                return current
    return None


def detect_prefix(interface: str | None, local_ip: str) -> int:
    system = platform.system()
    if system == "Linux" and interface:
        output = _run(["ip", "-o", "-4", "addr", "show", "dev", interface])
        match = re.search(rf"\binet\s+{re.escape(local_ip)}/(\d+)", output)
        if match:
            return int(match.group(1))
    if system == "Darwin" and interface:
        output = _run(["ifconfig", interface])
        match = re.search(r"netmask\s+0x([0-9a-fA-F]+)", output)
        if match:
            mask = int(match.group(1), 16)
            return bin(mask).count("1")
    return 24


def detect_gateway() -> str | None:
    system = platform.system()
    if system == "Linux":
        output = _run(["ip", "-4", "route", "show", "default"])
        match = re.search(r"\bvia\s+(\d+(?:\.\d+){3})", output)
        return match.group(1) if match else None
    if system == "Darwin":
        output = _run(["route", "-n", "get", "default"])
        match = re.search(r"^\s*gateway:\s*(\d+(?:\.\d+){3})", output, re.MULTILINE)
        return match.group(1) if match else None
    if system == "Windows":
        output = _run(["route", "print", "-4"])
        match = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+(?:\.\d+){3})", output, re.MULTILINE)
        return match.group(1) if match else None
    return None


def detect_network(configured_subnet: str | None = None, configured_interface: str | None = None) -> NetworkContext:
    local_ip = detect_local_ip()
    interface = configured_interface or detect_interface(local_ip)
    if configured_subnet:
        subnet = str(ipaddress.ip_network(configured_subnet, strict=False))
    else:
        prefix = detect_prefix(interface, local_ip)
        subnet = str(ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False))
    return NetworkContext(interface=interface, local_ip=local_ip, subnet=subnet, gateway_ip=detect_gateway())
