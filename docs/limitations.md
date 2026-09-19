# Known Limitations and Future Scope

## Current limitations

- Network-only visibility; no process/file/memory telemetry.
- Encrypted application payload content is not inspected.
- JA3 is a supporting indicator and may be shared by unrelated applications using the same TLS library.
- A host on a switched network normally sees traffic that reaches its own interface; wider coverage needs appropriate network placement such as a mirror port/gateway.
- The analyzer must be running while the attack occurs.
- Thresholds need environment-specific tuning.

## Not implemented

Distributed collectors, centralized multi-source analysis, client-server transport, endpoint telemetry, ML, statistical baselining and enterprise SIEM/XDR capabilities are future scope only.
