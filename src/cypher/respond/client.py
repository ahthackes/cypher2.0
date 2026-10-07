"""Client used by the unprivileged API and detection processes to send
block/unblock/status requests to the root-privileged responder daemon
over its Unix domain socket. This is the ONLY way the rest of the
system may influence the firewall.
"""
from __future__ import annotations

import json
import socket


class ResponderClient:
    def __init__(self, socket_path: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def _send(self, request: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            data = sock.makefile().readline()
            return json.loads(data)

    def block(self, ip: str, reason: str, alert_id: str | None = None, actor: str = "system") -> dict:
        return self._send({
            "action": "block", "ip": ip, "reason": reason,
            "alert_id": alert_id, "actor": actor,
        })

    def unblock(self, ip: str, reason: str = "manual override", actor: str = "admin") -> dict:
        return self._send({"action": "unblock", "ip": ip, "reason": reason, "actor": actor})

    def status(self) -> dict:
        return self._send({"action": "status"})
