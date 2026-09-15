from __future__ import annotations

import ipaddress


SERVICE_RULES = (
    (("googlevideo.com", "youtube.com", "youtu.be"), "Google / YouTube", "Streaming"),
    (("nflxvideo.net", "netflix.com", "nflximg.net"), "Netflix", "Streaming"),
    (("spotify.com", "scdn.co"), "Spotify", "Audio"),
    (("apple.com", "icloud.com", "mzstatic.com"), "Apple", "Platform"),
    (("microsoft.com", "windows.com", "office.com", "live.com"), "Microsoft", "Platform"),
    (("amazon.com", "amazonaws.com", "cloudfront.net"), "Amazon / AWS", "Cloud"),
    (("cloudflare.com", "cloudflare-dns.com"), "Cloudflare", "Infrastructure"),
    (("facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net"), "Meta", "Social"),
    (("tiktok.com", "tiktokcdn.com", "byteoversea.com"), "TikTok", "Social"),
    (("github.com", "githubusercontent.com"), "GitHub", "Development"),
)


def classify_destination(value: str) -> tuple[str, str]:
    normalized = value.lower().rstrip(".")
    for suffixes, organization, category in SERVICE_RULES:
        if any(normalized == suffix or normalized.endswith(f".{suffix}") for suffix in suffixes):
            return organization, category
    try:
        address = ipaddress.ip_address(normalized)
        if address.is_private:
            return "Local network", "Local"
    except ValueError:
        return normalized.split(".")[-2].title() if "." in normalized else normalized, "Other"
    return "Unresolved IP", "Unclassified"


def infer_device_category(hostname: str | None, vendor: str | None) -> str:
    identity = f"{hostname or ''} {vendor or ''}".lower()
    rules = (
        (("iphone", "android", "pixel", "galaxy phone"), "phone"),
        (("ipad", "tablet"), "tablet"),
        (("tv", "roku", "chromecast", "firestick", "appletv", "bravia"), "media"),
        (("camera", "doorbell", "thermostat", "bulb", "tuya", "smart plug"), "iot"),
        (("router", "gateway", "access point", "deco", "unifi"), "network"),
        (("server", "nas", "synology", "raspberrypi", "proxmox"), "server"),
        (("macbook", "imac", "windows", "desktop", "laptop"), "computer"),
    )
    for terms, category in rules:
        if any(term in identity for term in terms):
            return category
    return "unknown"
