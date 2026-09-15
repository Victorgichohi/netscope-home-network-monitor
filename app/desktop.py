from __future__ import annotations

import os
import secrets
import threading
import time
import webbrowser
from pathlib import Path


def configure_local_app() -> None:
    data_dir = Path.home() / ".netscope"
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_path = data_dir / "secret"
    if not secret_path.exists():
        secret_path.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass
    os.environ.setdefault("HNM_SECRET_KEY", secret_path.read_text(encoding="utf-8").strip())
    os.environ.setdefault("HNM_DATABASE_URL", f"sqlite:///{data_dir / 'netscope.db'}")
    os.environ.setdefault("HNM_ENVIRONMENT", "development")


def main() -> None:
    configure_local_app()
    import uvicorn

    from app.main import app

    url = "http://127.0.0.1:8765"
    threading.Thread(target=lambda: (time.sleep(1.2), webbrowser.open(url)), daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")


if __name__ == "__main__":
    main()
