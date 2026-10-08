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
- `01-security-onion-hunt-zeek-conn.png` — Security Onion Hunt with the `event.dataset:zeek.conn` query (all sources).
- `02-security-onion-hunt-win11-source-filter.png` — Hunt filtered to source `10.50.20.22`.
- `03-security-onion-hunt-timeline.png` — Hunt timeline/basic metrics view for the endpoint-filtered dataset.

> Hunt counts (4,418 / 4,539) are rolling 24-hour values at capture time and are not the frozen dataset (5,541 events).

## 99_troubleshooting
- `01-elasticsearch-circuit-breaker.png` — Elasticsearch transient circuit breaker encountered during aggregation testing.

## Use in the README

Steps 1–4 of the README walkthrough embed `01_platform/*`, `02_telemetry/*`, `03_hunt/02-*` and `03_hunt/03-*`. `99_troubleshooting/01-*` is shown in the collapsible troubleshooting section.

## Portfolio guidance
Use the screenshots in README/docs only where they support a concrete claim. Keep troubleshooting evidence in a separate section so it demonstrates engineering process without distracting from the main result.
