# Architecture

## Why three processes, not one

The original proposal describes Cypher as a single program. In practice
it needs root to touch the firewall, but a web dashboard with a login
form should never run as root — if the dashboard has a bug, an attacker
who exploits it should not thereby get a root shell. So Cypher is split
into three processes, each with the minimum privilege it needs:

| Process | Runs as | Can do |
|---|---|---|
| **ingest + detect** (`cypher start`) | unprivileged `cypher` user, read access to `/var/log` | tail logs, parse, run rules + ML, write to SQLite |
| **responder** (`cypher.respond.run_responder`) | root, `CAP_NET_ADMIN` | the ONLY process that runs `nft`/`iptables`/`ufw` |
| **API** (`uvicorn cypher.api.app:create_app`) | unprivileged `cypher` user | serves the dashboard, reads SQLite, asks the responder (never the firewall directly) to block/unblock |

This also gives you the fault-tolerance the proposal's non-functional
requirements ask for: if the API or the ML model crashes, log ingestion
keeps running untouched, because it's a different process.

## End-to-end flow

See the flow diagram shared earlier in this project's planning
conversation (log sources → ingestion → rule engine + ML engine → score
fusion → severity policy → event store / active defense / dashboard
API). The code mirrors that diagram directly:

1. `ingest/tailer.py` watches each configured log file, handling
   rotation by inode comparison.
2. `ingest/parsers/*.py` turn a raw line into an `Event`
   (`cypher/models.py`).
3. `ingest/normalizer.py` validates/cleans the event.
4. `bus.py` queues it for the detection loop (`pipeline.py`).
5. `detect/rules/engine.py` checks it against `config/rules.d/*.toml`,
   using `features/windows.py` for "N times in M seconds" rules.
6. `detect/ml/isolation_forest.py` (and, if enabled,
   `detect/ml/autoencoder.py`) score it using
   `features/vectorizer.py`'s feature vector.
7. `detect/fusion.py` combines both into one 0-100 score.
8. `detect/policy.py` maps that score to a severity and decides whether
   it's CRITICAL enough to auto-block.
9. The alert is written to SQLite (`storage/db.py`). If auto-block
   applies, `respond/client.py` asks the responder daemon to act — which
   re-checks `respond/safety.py` itself before doing anything.
10. The dashboard (`web/index.html`) polls/streams `api/routes/*.py` and
    `api/ws.py` to show all of this live.

## What's implemented vs. planned

**Implemented and tested** (see `tests/`, 49 passing):
ingestion + parsing (auth.log, syslog, nginx access log), the rule
engine, feature extraction, Isolation Forest training/scoring, score
fusion + severity policy, MITRE technique mapping, the safety gate
(allowlist/dry-run/rate-limit), all three firewall backends (nftables,
iptables, ufw) with mockable command runners, the responder daemon's
logic, SQLite storage with an append-only audit log, the FastAPI
dashboard backend with session auth, and the dashboard UI itself.

**Deliberately simplified from the original proposal, with reasoning**
(see the planning conversation and `docs/ml-evaluation.md`):
- The autoencoder is a PCA-based reconstruction-error model, not
  TensorFlow/Keras — same interface, swappable later, far lighter on
  the "i5, 8GB RAM, <15% CPU" hardware budget. **Disabled by default.**
- Log templating (`features/templating.py`) is regex-based rather than
  a full Drain3 tree — adequate for the three log families this project
  targets.
- GeoIP (`geo/geoip.py`) and the MITRE ATT&CK JSON lookup degrade
  gracefully to "no data" if you haven't downloaded the (license-
  restricted, so not bundled) database files yourself.

**Not yet built** — real-VM validation, the `.deb` package, and running
the responder against an actual attack in your lab. These need your own
Ubuntu/Debian VM and can't be done inside this chat; `docs/dev-guide.md`
walks through exactly how to do them.
