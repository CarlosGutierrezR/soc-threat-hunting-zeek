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