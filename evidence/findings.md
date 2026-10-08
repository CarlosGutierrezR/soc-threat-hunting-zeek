# SEC-HUNT-001 Findings

## Hypothesis

A compromised endpoint may be establishing periodic outbound communications consistent with beaconing behavior.

## Dataset

- Source: Security Onion / Zeek `conn.log`
- Endpoint investigated: `WIN11-EP-01` (`10.50.20.22`)
- Snapshot events: 5,541
- Events originating from investigated endpoint: 5,475
- SHA-256:
  `308d4f4e9c27f44f9a7d903e784136cb96d532ea02fa0448a13b2b5fe29c34e0`

The raw dataset is excluded from Git.

## Method

Connections were grouped by:

- destination IP
- destination port
- transport protocol

For each group, timestamps were sorted and inter-arrival times were calculated.

Features:

- event count
- mean inter-arrival time
- population standard deviation
- coefficient of variation (CV)

Candidates were ranked primarily by ascending CV.

A low CV is treated only as a statistical periodicity signal and not as evidence of compromise.

## Results

- Total connection groups: 13
- Groups with at least 5 events: 7

### Candidate 1

`10.50.20.22 -> 224.0.0.22`

- Events: 5
- Mean interval: approximately 3600 seconds
- CV: approximately 0
- IP protocol: 2
- Verdict: benign periodic

The traffic is consistent with IGMPv3 multicast reporting and demonstrates that highly periodic traffic is not inherently malicious.

### Candidate 2

`10.50.20.22:68 -> 10.50.20.254:67/udp`

- Service: DHCP
- Events: 5
- Mean interval: approximately 3600 seconds
- CV: approximately 0
- Verdict: benign periodic

This is expected DHCP communication between the Windows endpoint and the lab DHCP server/gateway.

This candidate is the required benign false candidate: a naive periodicity-only detector would rank it extremely highly despite the traffic being legitimate.

### Other reviewed groups

- `10.50.10.10:1514/tcp` — periodic communication associated with the Wazuh infrastructure; requires context rather than statistical classification alone.
- `10.50.30.10:53/udp` — DNS traffic with high volume and substantially greater timing variance.
- `239.255.255.250:1900/udp` — multicast traffic requiring protocol context before any verdict.
- `224.0.0.252:5355/udp` — multicast name-resolution traffic requiring protocol context.

## Analyst verdict

No candidate in this dataset is confirmed malicious based on the available evidence.

Periodic behavior alone was insufficient to establish command-and-control activity.

The hunt successfully demonstrated that legitimate infrastructure and operating-system protocols can rank above potentially interesting application traffic when using timing regularity alone.

## Hunting conclusion

The hypothesis was investigated but not confirmed.

The statistical method is useful for prioritizing candidates, but analyst context is mandatory.

Future iterations should combine periodicity with:

- destination reputation/context
- DNS context
- connection duration
- byte patterns
- protocol semantics
- asset role
- controlled beaconing ground truth