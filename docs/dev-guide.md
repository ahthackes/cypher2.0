# Developer guide

## Running tests

```bash
pip install -e ".[dev]"
pytest -v                    # all 49 tests
pytest tests/unit             # fast, no I/O beyond tmp SQLite files
pytest tests/integration      # pipeline + ML round-trip
pytest --cov=cypher           # coverage report
```

All tests run against real code paths (no network, no root needed) —
`tests/unit/test_responder.py` swaps in a fake firewall backend so the
responder's safety logic is tested without needing `nft`/`iptables`
installed; `tests/unit/test_safety.py` and `test_rule_engine.py` load
the actual shipped `config/` files rather than fixtures, so a config
typo breaks the test suite, not just production.

## Adding a new rule

Add a `[[rule]]` block to any `.toml` file in `config/rules.d/` (or a
new file — anything matching `*.toml` is picked up). See
`detect/rules/loader.py` for the full `Rule` schema. No code change or
restart-of-the-whole-system needed, just a restart of `cypher start`.

## Adding a new log source / parser

1. Add a parser class in `ingest/parsers/` implementing `BaseParser`
   (`parse_line(line) -> Event | None`) — see `ingest/parsers/auth.py`
   for the pattern.
2. Register it in `ingest/parsers/__init__.py`'s `PARSERS_BY_SOURCE`.
3. Add the log path to `[sources]` in `cypher.toml`.
4. Write unit tests following `tests/unit/test_parsers.py`'s pattern:
   one test per message shape, plus a "garbage input doesn't crash"
   test.

## Lab testing (needs two VMs — your own, never someone else's)

1. **Target VM**: Ubuntu/Debian, Cypher installed per
   `user-guide.md`, `general.mode = "dry_run"`.
2. **Attacker VM**: Kali or any distro with `hydra`, `nmap`, `nikto`.
   Both VMs on a host-only/NAT network you control.
3. From the attacker VM:
   ```bash
   hydra -l testuser -P wordlist.txt ssh://<target-ip>
   nmap -sV <target-ip>
   nikto -h http://<target-ip>
   ```
4. On the target, watch `cypher status` / the dashboard. Confirm the
   expected rules fire (`ssh_bruteforce_burst`, `web_404_scan`, etc.)
   and that the fused score and severity match what you'd expect.
5. Once satisfied, flip to `active` mode (see `user-guide.md` §7) and
   repeat — confirm the attacker IP actually gets dropped
   (`nft list set inet cypher_filter cypher_blocklist` or the
   equivalent for your backend) and that it expires after
   `block_ttl_seconds`.
6. Record actual log-to-block latency with a timestamp on both ends —
   this is the number that goes in the FYP report against the ≤2.5s
   requirement, not the synthetic benchmark alone.

## Code style

`ruff` is configured via `pyproject.toml`'s dev dependencies. Run
`ruff check src tests` before committing; `.pre-commit-config.yaml` runs
it automatically if you `pip install pre-commit && pre-commit install`.

## Report-as-you-go

Per the project's working agreement: every new file or significant
change should get a short entry in `docs/fyp-report/parts/` (purpose,
how it works, security considerations, how it's tested) as it's built,
not reconstructed at the end. See `docs/fyp-report/README.md`.
