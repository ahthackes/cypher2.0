from cypher.respond.responder import ResponderService
from cypher.respond.backends.base import FirewallBackend


class FakeBackend(FirewallBackend):
    name = "fake"

    def __init__(self):
        self.blocked: list[str] = []

    def block(self, ip):
        self.blocked.append(ip)
        return True, f"blocked {ip}"

    def unblock(self, ip):
        if ip in self.blocked:
            self.blocked.remove(ip)
        return True, f"unblocked {ip}"

    def list_blocked(self):
        return list(self.blocked)


def _service(settings, db, mode="active"):
    settings.general.mode = mode
    settings.respond.backend = "nftables"  # overridden below
    service = ResponderService(settings, db)
    service.backend = FakeBackend()
    return service


def test_dry_run_mode_does_not_call_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="dry_run")
    result = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    assert result["action"] == "dry_run_skipped"
    assert service.backend.blocked == []


def test_active_mode_blocks_via_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    assert result["action"] == "block"
    assert "203.0.113.5" in service.backend.blocked


def test_allowlisted_ip_never_reaches_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "block", "ip": "127.0.0.1", "reason": "test"})
    assert result["action"] == "allowlisted"
    assert service.backend.blocked == []


def test_unblock_calls_backend(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    service.handle_request({"action": "block", "ip": "203.0.113.5", "reason": "test"})
    result = service.handle_request({"action": "unblock", "ip": "203.0.113.5", "reason": "manual"})
    assert result["ok"] is True
    assert "203.0.113.5" not in service.backend.blocked


def test_unknown_action_returns_error(settings, tmp_db):
    service = _service(settings, tmp_db, mode="active")
    result = service.handle_request({"action": "nonsense"})
    assert result["ok"] is False
