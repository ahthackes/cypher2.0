"""The responder: a small daemon that runs as root (via
deploy/systemd/cypher-responder.service) and is the ONLY process in the
whole system that executes firewall commands.

Everything else — ingestion, detection, the API, the dashboard — runs
unprivileged and talks to this daemon over a Unix domain socket
(respond.socket_path) with a tiny JSON-lines protocol:

    request:  {"action": "block", "ip": "1.2.3.4", "reason": "...", "alert_id": "..."}
    response: {"ok": true, "action": "block", "message": "blocked 1.2.3.4 via nftables"}

Every request passes through respond/safety.py before anything is
executed — the responder trusts the socket's peer credentials (only
members of the `cypher` group may connect) but does NOT trust that the
caller already applied the safety checks; it always re-checks itself.
"""
from __future__ import annotations

import json
import logging
import os
import socketserver
from datetime import datetime, timedelta
from pathlib import Path

from cypher.models import Block, BlockAction
from cypher.respond.audit import AuditLogger
from cypher.respond.backends import get_backend
from cypher.respond.safety import evaluate, load_allowlist
from cypher.settings import Settings
from cypher.storage.db import Database

logger = logging.getLogger("cypher.respond.responder")


class ResponderService:
    """The core logic, separated from the socket-server plumbing so it
    can be unit-tested by calling handle_request() directly."""

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self.backend = get_backend(settings.respond.backend)
        self.audit = AuditLogger(db)
        self.allowlist = load_allowlist(settings.respond.allowlist_file)

    def handle_request(self, request: dict) -> dict:
        action = request.get("action")
        ip = request.get("ip", "")
        reason = request.get("reason", "")
        alert_id = request.get("alert_id")
        actor = request.get("actor", "system")

        if action == "block":
            return self._handle_block(ip, reason, alert_id, actor)
        if action == "unblock":
            return self._handle_unblock(ip, reason, actor)
        if action == "status":
            return {"ok": True, "active_blocks": [dict(r) for r in self.db.active_blocks()]}
        return {"ok": False, "message": f"unknown action '{action}'"}

    def _handle_block(self, ip: str, reason: str, alert_id: str | None, actor: str) -> dict:
        decision = evaluate(
            ip,
            is_dry_run=self.settings.is_dry_run,
            allowlist_networks=self.allowlist,
            blocks_in_last_hour=self.db.blocks_in_last_hour(),
            max_blocks_per_hour=self.settings.respond.max_blocks_per_hour,
        )

        if not decision.allowed:
            self._record_block(ip, decision.action, reason=decision.reason,
                                alert_id=alert_id, actor=actor, ttl=None)
            self.audit.log(actor, f"block_{decision.action.value}", f"{ip}: {decision.reason}")
            return {"ok": True, "action": decision.action.value, "message": decision.reason}

        success, message = self.backend.block(ip)
        if not success:
            self.audit.log(actor, "block_failed", f"{ip}: {message}")
            return {"ok": False, "action": "block_failed", "message": message}

        ttl = self.settings.respond.block_ttl_seconds
        self._record_block(ip, BlockAction.BLOCK, reason=reason, alert_id=alert_id,
                            actor=actor, ttl=ttl)
        self.audit.log(actor, "block", f"{ip}: {reason} (backend={self.backend.name})")
        return {"ok": True, "action": "block", "message": message}

    def _handle_unblock(self, ip: str, reason: str, actor: str) -> dict:
        success, message = self.backend.unblock(ip)
        block = Block(
            src_ip=ip, action=BlockAction.UNBLOCK, reason=reason,
            backend=self.backend.name, actor=actor,
        )
        self.db.insert_block(block)
        self.audit.log(actor, "unblock", f"{ip}: {reason}")
        return {"ok": success, "action": "unblock", "message": message}

    def _record_block(self, ip, action, *, reason, alert_id, actor, ttl) -> None:
        expires_at = datetime.now() + timedelta(seconds=ttl) if ttl else None
        block = Block(
            src_ip=ip, action=action, reason=reason, alert_id=alert_id,
            ttl_seconds=ttl, expires_at=expires_at, backend=self.backend.name, actor=actor,
        )
        self.db.insert_block(block)

    def expire_stale_blocks(self) -> int:
        """Unblock any IP whose TTL has passed. Call periodically from the
        daemon's main loop."""
        expired_count = 0
        now = datetime.now()
        for row in self.db.recent_blocks(limit=500):
            if row["action"] != "block" or not row["expires_at"]:
                continue
            expires = datetime.fromisoformat(row["expires_at"])
            if expires <= now:
                self._handle_unblock(row["src_ip"], "ttl expired", "system")
                expired_count += 1
        return expired_count


class _RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        service: ResponderService = self.server.service  # type: ignore[attr-defined]
        line = self.rfile.readline()
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
            response = service.handle_request(request)
        except Exception as exc:  # noqa: BLE001 — never let a bad request kill the daemon
            logger.exception("Error handling responder request")
            response = {"ok": False, "message": str(exc)}
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class _UnixSocketServer(socketserver.UnixStreamServer):
    pass


def run_responder(settings: Settings, db: Database) -> None:
    """Starts the Unix-socket server. Blocks forever — run this as the
    entry point of the cypher-responder systemd service."""
    socket_path = Path(settings.respond.socket_path)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        socket_path.unlink()

    server = _UnixSocketServer(str(socket_path), _RequestHandler)
    server.service = ResponderService(settings, db)  # type: ignore[attr-defined]
    os.chmod(socket_path, 0o660)  # only owner + group (the `cypher` group) may connect

    logger.info("Responder listening on %s (mode=%s, backend=%s)",
                socket_path, settings.general.mode, settings.respond.backend)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if socket_path.exists():
            socket_path.unlink()
