# SEC-HUNT-001 — Beaconing Hunt Hypothesis

## Problem

There is no conclusive alert proving command-and-control activity, but network telemetry may contain periodic outbound communication patterns that deserve investigation.

## Hypothesis

A compromised endpoint may be establishing periodic outbound communications consistent with beaconing behavior.

## Objective

Analyze Zeek connection telemetry, identify and rank statistically periodic communication candidates, enrich them with contextual evidence, and document an analyst verdict.

## Scope

The initial hunt will focus on Zeek connection telemetry from the authorized SOC lab.

Primary data source:

- Zeek `conn` telemetry.

Additional context may be incorporated when available and useful:

- Zeek DNS data.
- Source/destination asset context.
- Protocol and destination port.
- Connection duration and byte counts.

## Hunt methodology

The hunt will:

1. Define a time window and asset scope.
2. Group connections using relevant source/destination communication keys.
3. Sort events chronologically.
4. Calculate inter-arrival times.
5. Calculate periodicity features such as:
   - connection count;
   - mean inter-arrival time;
   - standard deviation;
   - coefficient of variation.
6. Apply minimum filters to remove trivial groups.
7. Rank candidates by periodicity characteristics.
8. Investigate high-ranking candidates using contextual evidence.
9. Assign an analyst verdict.

## Analyst verdict categories

Possible outcomes:

- `benign_periodic`
- `suspicious`
- `confirmed_by_controlled_scenario`
- `inconclusive`

## Guardrails

- Periodicity alone does not prove malicious activity.
- A statistical candidate is not automatically an incident.
- Legitimate periodic traffic must be included in the analysis.
- At least one benign false candidate must be investigated and documented.
- Ground truth from controlled traffic must be explicitly identified.
- Unknown traffic must not be labeled malicious without supporting evidence.

## Expected result

A reproducible hunt that distinguishes statistical periodicity from analyst-confirmed malicious behavior and documents both findings and limitations.