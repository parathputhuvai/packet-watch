# Packet Watch Requirements Audit

| Requirement | Implementation | Primary module/file | Test evidence |
|---|---|---|---|
| Windows CLI | argparse + Rich terminal app | `packet_watch/cli/` | CLI info smoke run |
| Python 3.10+ | `requires-python >=3.10` | `pyproject.toml` | compile/test run on Python 3.13 container |
| Scapy/Npcap live capture | `sniff(store=False)` | `packet_watch/capture/live.py` | Requires Windows/Npcap; not runnable in this container |
| No Wireshark dependency | No Wireshark imports or workflow | repository-wide | source review |
| Continuous rolling state | timestamp-bounded per-source state | `packet_watch/state/rolling.py` | `tests/unit/test_rolling.py` |
| Reporting interval does not reset state | export path does not clear tracker | `packet_watch/cli/app.py` | state design review + integration pipeline |
| Ten specified detectors | Ten separate detector classes | `packet_watch/detectors/` | `tests/unit/test_detectors.py` + import/compile smoke |
| Explicit rule thresholds | centralized JSON settings | `config/config.json` | detector/severity tests |
| Low/Medium/High/Critical | deterministic mapping | `packet_watch/severity/scoring.py` | `tests/unit/test_severity.py` |
| MITRE metadata | mapping table attached to detector results | `packet_watch/mitre/mapping.py` | detector result structure |
| AbuseIPDB | cached alert-time lookup | `packet_watch/threat_intel/abuseipdb.py` | failure-safe design; live API not invoked in tests |
| SSLBL JA3 feed | refreshable CSV feed | `packet_watch/threat_intel/ja3.py` | JA3 unit test; feed live only |
| JA3 computation | JA3 string + MD5 | `packet_watch/threat_intel/ja3.py` | `tests/unit/test_threat_intel.py` |
| Alert timeline | chronological source grouping | `packet_watch/correlation/timeline.py` | integration design |
| IP/port whitelist | suppress user-facing alerts; retain audit list | `packet_watch/whitelist/filter.py` + engine | `tests/integration/test_pipeline.py` |
| Rich terminal alerts | Panel-based evidence output | `packet_watch/cli/app.py` | CLI smoke run path |
| PDF/CSV reporting | FPDF2 + built-in csv | `packet_watch/reporting/` | `tests/unit/test_reports.py` |
| Configuration separation | JSON + `.env` | `config/`, `.env.example` | config loading tests/path review |
| Error handling | defensive packet/parser and external-service boundaries | parser/capture/threat-intel/reporting | compile + tests |
| Logging | INFO/WARNING/ERROR/DEBUG logger | `packet_watch/utils/logging.py` | application initialization |
| Unit tests | detector/state/severity/JA3/report tests | `tests/unit/` | 8 tests passing |
| Integration tests | pipeline + whitelist | `tests/integration/` | 1 integration test passing |
| Windows docs | Python/Npcap/interface/API steps | `docs/windows-setup.md` | documentation review |
| Detection-rule docs | rules and thresholds | `docs/detection-rules.md` | documentation review |
| Limitations/future scope | explicit constraints | `docs/limitations.md`, README | documentation review |
| No ML/statistical baseline | no ML dependencies/logic | entire implementation | source review |
| No GUI/web/distributed system | CLI-only architecture | entire implementation | source review |

## Environment caveat

The automated suite was run in a Linux container with Python 3.13 and the available local dependencies. Npcap/Windows live capture could not be exercised there. The repository contains the Windows capture implementation and setup documentation; live validation should be performed on the target Windows machine after installing Npcap and the requirements.
