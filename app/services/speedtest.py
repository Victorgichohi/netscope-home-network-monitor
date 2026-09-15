from __future__ import annotations

import math
import time
from datetime import datetime, timezone
from statistics import mean, pstdev
from urllib.parse import urlencode

import httpx

from app.config import Settings
from app.database import SessionLocal
from app.models import SpeedTestRun


def megabits_per_second(byte_count: int, seconds: float) -> float:
    if byte_count <= 0 or seconds <= 0:
        return 0.0
    return round(byte_count * 8 / seconds / 1_000_000, 2)


def _download_url(base_url: str, byte_count: int) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{urlencode({'bytes': byte_count})}"


class SpeedTestService:
    """Runs a bounded HTTP speed sample and records aggregate measurements only."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self) -> int:
        with SessionLocal() as db:
            run = SpeedTestRun(created_at=datetime.now(timezone.utc))
            db.add(run)
            db.commit()
            try:
                with httpx.Client(timeout=httpx.Timeout(20.0), follow_redirects=True) as client:
                    latency_samples = self._latency_samples(client)
                    download_mbps, downloaded = self._download(client)
                    upload_mbps, uploaded = self._upload(client)
                run.completed_at = datetime.now(timezone.utc)
                run.status = "completed"
                run.download_mbps = download_mbps
                run.upload_mbps = upload_mbps
                run.latency_ms = round(mean(latency_samples), 1)
                run.jitter_ms = round(pstdev(latency_samples), 1) if len(latency_samples) > 1 else 0.0
                run.bytes_transferred = downloaded + uploaded
                db.commit()
                return run.id
            except Exception as exc:
                db.rollback()
                run = db.get(SpeedTestRun, run.id)
                run.completed_at = datetime.now(timezone.utc)
                run.status = "failed"
                run.error = str(exc)[:1000]
                db.commit()
                raise

    def _latency_samples(self, client: httpx.Client) -> list[float]:
        samples: list[float] = []
        url = _download_url(self.settings.speedtest_download_url, 0)
        for _ in range(5):
            started = time.perf_counter()
            response = client.get(url)
            response.raise_for_status()
            samples.append((time.perf_counter() - started) * 1000)
        if not samples or not all(math.isfinite(value) for value in samples):
            raise RuntimeError("Latency measurement failed")
        return samples

    def _download(self, client: httpx.Client) -> tuple[float, int]:
        url = _download_url(self.settings.speedtest_download_url, self.settings.speedtest_download_bytes)
        started = time.perf_counter()
        byte_count = 0
        with client.stream("GET", url) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                byte_count += len(chunk)
        duration = time.perf_counter() - started
        if byte_count == 0:
            raise RuntimeError("Speed test returned no download data")
        return megabits_per_second(byte_count, duration), byte_count

    def _upload(self, client: httpx.Client) -> tuple[float, int]:
        payload = bytes(self.settings.speedtest_upload_bytes)
        started = time.perf_counter()
        response = client.post(self.settings.speedtest_upload_url, content=payload)
        response.raise_for_status()
        duration = time.perf_counter() - started
        return megabits_per_second(len(payload), duration), len(payload)
