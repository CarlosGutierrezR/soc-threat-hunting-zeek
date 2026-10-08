# SEC-HUNT-001 Methodology

## Hunt hypothesis

A compromised endpoint may be establishing periodic outbound communications consistent with beaconing behavior.

## Scope

Investigated asset:

- WIN11-EP-01
- 10.50.20.22

Telemetry source:

- Security Onion
- Zeek conn telemetry

Frozen dataset:

- 5,541 connection events
- 5,475 events originating from 10.50.20.22

## Processing

Events are loaded from Zeek JSONL telemetry.

Traffic is filtered to the investigated source endpoint and grouped by:

- destination IP
- destination port
- transport protocol

For each group:

1. timestamps are sorted;
2. inter-arrival times are calculated;
3. mean interval is calculated;
4. population standard deviation is calculated;
5. coefficient of variation is calculated.

The coefficient of variation is:

CV = standard deviation / mean interval

Lower CV values indicate more regular timing.

## Candidate ranking

Groups require at least five events.

Candidates are ranked primarily by ascending coefficient of variation.

Statistical ranking does not classify traffic as malicious.

Every candidate requires analyst validation using protocol, destination, asset and infrastructure context.

## Analyst verdict categories

- benign periodic
- suspicious
- confirmed by controlled scenario
- inconclusive
