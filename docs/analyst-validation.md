# Analyst Validation

## Dataset results

- Total events: 5,541
- Source events from 10.50.20.22: 5,475
- Connection groups: 13
- Groups meeting minimum event threshold: 7

## Candidate: DHCP

Traffic:

10.50.20.22:68 -> 10.50.20.254:67/udp

Observed Zeek context:

- service: dhcp
- protocol: udp
- event count: 5
- mean interval: approximately 3600 seconds
- coefficient of variation: approximately 0

Verdict:

**Benign periodic**

The statistical model ranked this traffic extremely highly because of its regular timing. Protocol and infrastructure context show that it is legitimate DHCP communication.

This is the principal benign false candidate identified during SEC-HUNT-001.

## Candidate: 224.0.0.22

Observed context:

- destination: 224.0.0.22
- IP protocol: 2
- Zeek transport representation: unknown_transport
- destination port: 0
- event count: 5
- mean interval: approximately 3600 seconds
- coefficient of variation: approximately 0

Verdict:

**Benign periodic**

The traffic is multicast control traffic rather than evidence of command-and-control beaconing.

It also demonstrates a limitation of grouping all network traffic by transport-layer port.

## Candidate: 10.50.30.10:53/udp (DNS)

Observed context:

- destination: `DC01`, Active Directory Domain Services and DNS for `soclab.test`
- the endpoint uses `10.50.30.10` as its configured DNS server
- event count: 3,772; mean interval ≈ 4.3 s; CV ≈ 0.96 (irregular)
- the raw Zeek sample in `evidence/screenshots/02_telemetry/02-zeek-conn-and-dns-json-events.png`
  shows DNS connections with `conn_state: S0`, `resp_bytes: 0`, and repeated
  `dns.log` queries with the same `trans_id` and no answers

Verdict:

**Benign** — expected resolver traffic. Part of the volume is retry traffic:
during the capture window DC01 was at times unavailable and queries timed out.
High volume and low regularity make it a poor beaconing candidate.

## Candidates: 10.50.10.10:1514/tcp and 10.50.10.10:1515/tcp (Wazuh)

Observed context:

- destination: `SOC-WAZUH-01`, the lab Wazuh manager
- 1514/tcp is the Wazuh agent connection port; 1515/tcp is the agent enrolment port
- 1514/tcp: 1,385 events, mean ≈ 11.7 s, CV ≈ 0.66
- 1515/tcp: 276 events, mean ≈ 58.4 s, CV ≈ 1.24
- the raw Zeek sample shows 1514/tcp connections with `conn_state: S0` and
  `history: S` (SYN without a recorded reply)

Verdict:

**Benign periodic** — security tooling traffic from the endpoint's agent.
The unanswered SYNs in the sample suggest the agent was retrying a connection;
this is an operational observation to check on the Wazuh side, not a hunting finding.

## Candidates: multicast name resolution and discovery

- `239.255.255.250:1900/udp` — SSDP; 8 events, CV ≈ 0.76
- `224.0.0.252:5355/udp` — LLMNR; 12 events, CV ≈ 1.31

Verdict:

**Benign periodic** — standard Windows local-network discovery and name
resolution. Neither shows regular timing.

## Final determination

SEC-HUNT-001 did not confirm malicious beaconing in the analyzed dataset.

The hunt demonstrated that highly periodic legitimate network behavior can rank above other traffic when periodicity is used without contextual validation.

A future controlled experiment should introduce known beaconing ground truth and measure whether the ranking method separates it from legitimate periodic protocols.
