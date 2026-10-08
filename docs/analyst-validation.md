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

## Other candidates

Additional ranked groups included:

- 10.50.10.10:1514/tcp
- 239.255.255.250:1900/udp
- 10.50.30.10:53/udp
- 10.50.10.10:1515/tcp
- 224.0.0.252:5355/udp

These were not classified as malicious from timing statistics alone.

## Final determination

SEC-HUNT-001 did not confirm malicious beaconing in the analyzed dataset.

The hunt demonstrated that highly periodic legitimate network behavior can rank above other traffic when periodicity is used without contextual validation.

A future controlled experiment should introduce known beaconing ground truth and measure whether the ranking method separates it from legitimate periodic protocols.
