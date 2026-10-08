# Limitations

## Statistical periodicity is not maliciousness

A low coefficient of variation only indicates regular timing.

DHCP and IGMP traffic in this dataset produced near-perfect periodicity while being legitimate network behavior.

## Small group size

The most periodic groups contained only five observations.

Small samples can produce deceptively strong statistical regularity.

## Protocol semantics

Grouping by destination IP, destination port and transport protocol works well for TCP and UDP but is less meaningful for protocols such as IGMP.

For example, Zeek represented IGMP traffic with:

- `proto = unknown_transport`
- destination port `0`
- IP protocol `2`

Future implementations should incorporate IP protocol semantics.

## Dataset scope

The snapshot represents a limited lab observation window and one primary Windows endpoint.

Results must not be generalized to production environments.

## No malicious ground truth in this iteration

No candidate was confirmed malicious in this dataset.

A controlled beaconing scenario should be introduced in a future experiment to measure whether the ranking method can identify known ground truth while still distinguishing legitimate periodic traffic.

## Lab operational state

Part of the traffic reflects lab conditions rather than normal operation:
DC01 was at times unavailable, which produced DNS retries and timeouts, and
the Wazuh agent sample shows unanswered connection attempts. Timing features
computed on retry traffic describe retry behaviour, not the application.

## Return-traffic visibility

The raw Zeek sample captured in the screenshots shows `S0` connections with
`resp_bytes: 0` for DNS and Wazuh traffic. This is consistent with the
unavailable services above, but one-way sensor visibility would produce the
same pattern. The next iteration should confirm that the sensor sees both
directions (for example, a successful DNS answer appearing in `dns.log`).

## Hunt UI counts versus the frozen dataset

The Security Onion Hunt screenshots show rolling 24-hour counts at the moment
of capture. They are context only; the analysis uses the frozen snapshot
recorded in `evidence/evidence-manifest.md`.

