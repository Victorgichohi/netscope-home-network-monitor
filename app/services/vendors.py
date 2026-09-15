from __future__ import annotations

from functools import lru_cache


@lru_cache
def _parser():
    try:
        from manuf import manuf

        return manuf.MacParser(update=False)
    except Exception:
        return None


def vendor_for_mac(mac_address: str) -> str | None:
    parser = _parser()
    if parser is None:
        return None
    try:
        return parser.get_manuf(mac_address)
    except (KeyError, ValueError):
        return None
