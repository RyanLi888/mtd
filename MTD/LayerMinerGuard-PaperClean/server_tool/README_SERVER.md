# LayerMinerGuard Server Tool

Manual host-side mining evidence chain detector for server deployment.

## Key Points

- **Manual start only** — does NOT auto-start on boot
- **Alert-only** — does NOT auto-kill suspicious processes
- **Privacy-safe** — does NOT save raw payload, wallet, job_id, nonce, result, or blob
- **On-demand probes** — only launches per-PID short-window probes for confirmed candidates

## Detection Capabilities

| Miner Type | Probe Used | Detection Level | Notes |
|---|---|---|---|
| Plaintext Stratum (TCP) | plaintext_stratum_probe | **Protocol confirmed** | job + submit + association visible |
| TLS with dynamic libssl | tls_openssl_probe | **Protocol confirmed** | SSL_write/SSL_read uprobe hooks |
| TLS with static OpenSSL | plaintext probe only | **Fallback suspicious** | Encrypted traffic, no protocol markers |
| CPU-only (no network) | CPU telemetry only | **Fallback suspicious** | No protocol visibility |

### Verdict Levels

- **confirmed_mining_live** (high confidence): compute evidence + job + submit + association observed
- **protocol_suspicious** (medium): compute evidence + job markers seen, submit/association incomplete
- **fallback_suspicious** (low): compute evidence present, but no protocol markers visible
- **benign_or_unconfirmed** (none): insufficient evidence

### Visibility Boundary

When the probe cannot capture protocol markers, the observation includes a `visibility_boundary` field:

- `no_dynamic_libssl_mapping` — process uses TLS but OpenSSL is statically linked; TLS probe cannot hook SSL_write/SSL_read
- `encrypted_or_no_markers` — both probes ran but found no markers (traffic encrypted or not mining)
- `plaintext_disabled` — plaintext probe was disabled in config
- `tls_probe_disabled` — TLS probe was disabled in config

## Quick Start

```bash
# Dry-run scan (no root required)
python3 server_tool/bin/layerminerd.py --config server_tool/config/server.yaml --once

# Live detection (requires root, launches real probes; live.yaml backgrounds by default)
sudo python3 server_tool/bin/layerminerd.py --config server_tool/config/live.yaml

# Foreground live debugging
sudo python3 server_tool/bin/layerminerd.py --config server_tool/config/live.yaml --foreground

# View recent alerts
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml alerts

# View observation records
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml observations

# Check status
python3 server_tool/bin/lmgctl.py --config server_tool/config/live.yaml status
```

## Configuration

### server.yaml (dry-run)
Default configuration for testing. `agent.dry_run: true` — no real probes launched.

### live.yaml (live detection)
Production configuration. `agent.dry_run: false` — requires root, launches real probes.

Key settings:
- `candidate.min_consecutive_hits: 2` — candidate must appear in 2+ consecutive scans
- `candidate.min_cpu_percent: 70` — minimum CPU usage threshold
- `observer.probe_mode: on_demand` — probes only for confirmed candidates
- `observer.plaintext_probe_duration_sec: 300` — 5-minute observation window
- `alert_policy.emit_confirmed_alerts: true` — only confirmed mining writes formal alerts
- `alert_policy.emit_protocol_suspicious_alerts: false` — suspicious writes observation records only

## Directory Structure

```text
server_tool/
├── README_SERVER.md          # This file
├── config/
│   ├── server.yaml           # Dry-run configuration
│   └── live.yaml             # Live detection configuration
├── bin/
│   ├── layerminerd.py        # Main daemon
│   └── lmgctl.py             # Control utility
├── layerminer_server/
│   ├── process_scanner.py    # Process scanning with CPU double-sampling
│   ├── candidate_selector.py # Candidate filtering and scoring
│   ├── candidate_state.py    # Multi-hit sustained confirmation
│   ├── observer_scheduler.py # Cooldown and observation planning
│   ├── live_observer.py      # On-demand per-PID probe execution
│   ├── live_verdict.py       # Mining verdict decision
│   ├── json_schema.py        # Fixed JSON alert/observation schema
│   ├── alert_store.py        # Alert and observation storage
│   └── manual_agent.py       # Agent orchestration
├── packaging/
│   ├── install.sh
│   ├── uninstall.sh
│   └── layerminerguard.service
└── tests/
```

## Output

### Formal Alerts (`/var/log/layerminer/alerts.jsonl`)
Only `confirmed_mining_live` verdicts write formal alerts by default.

### Observation Records (`/var/lib/layerminer/observations/`)
All non-benign observations are saved as individual JSON files for forensic review.

### Local Results Mirror (`results/`)
The same runtime outputs are also mirrored under the project-local `results/` directory:

```text
results/alerts.jsonl
results/warnings.log
results/candidate_state.json
results/observations/
results/layerminerd.pid
results/layerminerd.log
```

## Privacy

The tool never saves:
- Raw network payloads
- Wallet addresses
- Job IDs, nonces, results, or blobs
- Full command lines (only SHA256 hashes)
- Pool credentials
