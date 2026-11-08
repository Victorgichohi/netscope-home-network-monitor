from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RouterStatus:
    available: bool
    adapter: str
    host: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


class RouterController(ABC):
    @abstractmethod
    def status(self) -> RouterStatus:
        raise NotImplementedError

    @abstractmethod
    def reboot(self) -> None:
        raise NotImplementedError

    def health_snapshot(self) -> Any | None:
        """Return a read-only health snapshot when the adapter supports one."""
        return None
