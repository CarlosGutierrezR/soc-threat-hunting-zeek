# SEC-HUNT-001 Graphical Evidence Pack

Curated screenshots captured during SEC-HUNT-001 Iteration 1.

## 01_platform
- `01-security-onion-grid-health.png` — Security Onion node `onion`, Evaluation role, address `10.50.10.30`, version `3.3.0`, status `OK`.
- `02-elastic-fleet-agents-healthy.png` — FleetServer and Onion Elastic Agents shown healthy.

## 02_telemetry
- `01-packet-visibility-and-zeek-current-logs.png` — Packet visibility on the sensor plus Zeek current log directory (`conn.log`, `dns.log`, etc.).
- `02-zeek-conn-and-dns-json-events.png` — Raw Zeek `conn.log` and `dns.log` JSON events including traffic from `10.50.20.22`.
- `03-elasticsearch-zeek-data-stream-green.png` — `logs-zeek-so` data stream present and GREEN, with 90-day retention visible.
- `04-elasticsearch-zeek-document-count.png` — Elasticsearch count query showing Zeek documents indexed.
- `05-elasticsearch-latest-zeek-conn-event.png` — Latest indexed Zeek connection event showing `event.dataset: zeek.conn` and source/destination context.

## 03_hunt
- `01-security-onion-hunt-zeek-conn.png` — Security Onion Hunt with the correct `event.dataset:zeek.conn` query.
- `02-security-onion-hunt-win11-source-filter.png` — Hunt filtered to source `10.50.20.22`.
- `03-security-onion-hunt-timeline.png` — Hunt timeline/basic metrics view for the endpoint-filtered dataset.

## 04_implementation
- `01-vscode-zeek-jsonl-loader.png` — Python loader implementation in VS Code.

## 05_git
- `01-github-pr-1-merged.png` — GitHub PR #1 merged into `main`.

## 99_troubleshooting
- `01-elasticsearch-circuit-breaker.png` — Elasticsearch transient circuit breaker encountered during aggregation testing.
- `02-zeek-current-conn-log-size.png` — Validation of current Zeek `conn.log` line count and size.

## Portfolio guidance
Use the screenshots in README/docs only where they support a concrete claim. Keep troubleshooting evidence in a separate section so it demonstrates engineering process without distracting from the main result.
