from __future__ import annotations

import shlex

import httpx

from app.config import Settings
from app.router_control.base import RouterController, RouterStatus


class DisabledRouterController(RouterController):
    def status(self) -> RouterStatus:
        return RouterStatus(False, "disabled", detail="Router control is not configured")

    def reboot(self) -> None:
        raise RuntimeError("Router control is disabled")


class SshRouterController(RouterController):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _client(self):
        import paramiko

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=self.settings.router_host,
            port=self.settings.router_port,
            username=self.settings.router_username,
            password=self.settings.router_password,
            key_filename=str(self.settings.router_ssh_key_path) if self.settings.router_ssh_key_path else None,
            look_for_keys=self.settings.router_ssh_key_path is None,
            timeout=5,
            banner_timeout=5,
            auth_timeout=5,
        )
        return client

    def _execute(self, command: str) -> str:
        if not command or len(shlex.split(command)) == 0:
            raise RuntimeError("Router command is empty")
        client = self._client()
        try:
            _, stdout, stderr = client.exec_command(command, timeout=10)
            output = stdout.read().decode(errors="replace").strip()
            error = stderr.read().decode(errors="replace").strip()
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise RuntimeError(error or f"Router command failed with status {exit_status}")
            return output
        finally:
            client.close()

    def status(self) -> RouterStatus:
        try:
            detail = self._execute(self.settings.router_status_command)
            return RouterStatus(True, "ssh", self.settings.router_host, detail[:500])
        except Exception as exc:
            return RouterStatus(False, "ssh", self.settings.router_host, str(exc)[:500])

    def reboot(self) -> None:
        self._execute(self.settings.router_reboot_command)


class HttpRouterController(RouterController):
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _headers(self) -> dict[str, str]:
        if not self.settings.router_http_bearer_token:
            return {}
        return {"Authorization": f"Bearer {self.settings.router_http_bearer_token}"}

    def status(self) -> RouterStatus:
        if not self.settings.router_http_status_url:
            return RouterStatus(False, "http", self.settings.router_host, "Status URL is not configured")
        try:
            response = httpx.get(
                self.settings.router_http_status_url,
                headers=self._headers(),
                verify=self.settings.router_verify_tls,
                timeout=5,
            )
            response.raise_for_status()
            return RouterStatus(
                True, "http", self.settings.router_host, f"Router responded with HTTP {response.status_code}"
            )
        except Exception as exc:
            return RouterStatus(False, "http", self.settings.router_host, str(exc)[:500])

    def reboot(self) -> None:
        if not self.settings.router_http_reboot_url:
            raise RuntimeError("Reboot URL is not configured")
        response = httpx.post(
            self.settings.router_http_reboot_url,
            headers=self._headers(),
            verify=self.settings.router_verify_tls,
            timeout=10,
        )
        response.raise_for_status()


def build_router_controller(settings: Settings) -> RouterController:
    if settings.router_adapter == "ssh":
        if not settings.router_username:
            raise ValueError("HNM_ROUTER_USERNAME is required for the SSH adapter")
        return SshRouterController(settings)
    if settings.router_adapter == "http":
        return HttpRouterController(settings)
    return DisabledRouterController()
