# Scan correctness and resource preview — 6 October 2026

Experimental supplemental protection. Keep Microsoft Defender enabled. These results are not an independent antivirus rating, malware catch rate, production release approval or a claim that every scan problem is resolved.

## Changes and observed causes

- Startup scanning previously collected candidates before analysis and used one analysis worker. Discovery now streams into bounded per-volume queues, with owned global resource permits, fair admission and one result/action consumer. Cancellation waits for the owned work; partial inspection is not a whole-job failure or a clean verdict.
- Duplicate static API features could accumulate across detectors. Canonical feature identities and a shared 25-point capability ceiling separate ordinary capabilities from independent structural anomalies and authoritative malware evidence. A valid signature does not erase independently verified malware evidence.
- A TLS directory was confused with an actual callback table. PE32/PE64 callback addresses, backing data and terminators are now checked within bounds. An ordinary TLS callback has zero malware score by itself.
- An actual Ultron security DLL scored 75 / Suspicious because its `amsiInitFailed` string was treated as an executable malicious script. Literal capability references now remain low-confidence features, without adding a self-folder/name exemption. The same benign DLL scored 25 / Clean after the correction. This does not certify arbitrary files with that string as safe.
- Unknown/incomplete results are no longer promoted to suspicious just because of enum ordering or a numeric score. The UI separates confirmed malware, review findings and inspection gaps.
- Fixed per-volume admission limits and a shared stability counter could prevent resource growth. Admission now reads the live policy; the measurement-driven controller has its own stability state.

## Resource policy: useful work, not artificial usage

Planning budgets are 256 MiB for 2–4 GB systems, 512 MiB at 8 GB, 1 GiB at 12 GB, and **up to 2 GiB** on nominal 16 GB+ systems, subject to available-memory headroom. These are not an OS-enforced process working-set cap or a promise to allocate that much RAM.

The scan-process CPU target is approximately 40% of normalized total CPU capacity. Other applications' measured load, approximately 70% overall CPU pressure, disk latency, battery and memory pressure reduce admission. At 85% memory pressure concurrency contracts; at 92% new heavy work waits cancellably. Missing telemetry stays unknown and uses conservative fallback rather than invented readings.

SSD scanning starts with up to four useful workers when measurements allow. Extra workers are trialled after stable measurements and withdrawn if throughput does not improve by at least 10%. Missing disk latency prevents that experimental expansion. HDD/unknown-volume admission stays conservative; physical mixed-disk and HDD-growth validation is unfinished.

Real-time arrivals take priority over new bulk-scan admission **within the same process**. Existing analysis is not preempted; separate services do not yet share a hard CPU/RAM quota. Content hash and policy revision, not path alone, bind clean-cache reuse.

Measurements report per-volume completed work, logical input MiB/s, files/s, queue/analysis p95 histogram upper bounds, peak active workers, CPU time and observed peak working set. Logical bytes are not physical disk throughput. Separate hash/content timings remain null until instrumented.

## Local evidence before publication

Release Review build and self-contained Windows x64 app publish completed with **0 errors, 0 warnings**.

- Selected harmless Review: **1,218 passed, 0 failed, 1 skipped** (1,219 selected cases). This is a mixed infrastructure, security-unit and temporary-file/vault workflow suite, not 1,218 independent malware integration tests.
- Critical resource/queue/cancellation/startup subset: **63 cases, five repetitions**, all passed. Repetitions are not 315 unique scenarios.
- Two actual benign-file/shared-engine integration tests passed, with no execution, modification, quarantine or upload of their input files. The corpus consisted of a signed Microsoft .NET 8.0.31 installer and three Ultron build files.
- The 58,715,896-byte installer remained **Unknown / Partial, score 25**, because deep inspection budgets limited coverage. Five real-time calls took 1.16–1.28 s; five manual calls took 1.17–1.47 s. No actionable finding was produced. Partial is not fully clean.
- Five alternating one-worker/four-worker runs on the same four files had median **1,633.28 ms versus 1,251.26 ms (23.39% improvement)**, unchanged decisions/coverage, four completed files and no timeout/action per run. Observed process peak working set was 221 MiB. This is a small warm/mixed-cache local benchmark, not a whole-machine or cold-disk claim.

The skipped symbolic-link case requires a privilege not available to the test token. Golden02–05 were selected; the live file-writing EICAR Golden01 case and a separately excluded settings group were not run. Optional local-file probes/benchmarks were run separately with explicit harmless fixtures, not silently counted as successful absent-fixture tests. The unsafe main test DLL was not run. Initial restricted-token ACL/DPAPI failures were retained and rerun with normal user permissions; production ACL checks were not weakened.

Private raw test output, machine paths, backup/checkpoint files, keys, databases and installer binaries are not included in the source PR.

## Publication verification

The candidate was assembled from the exact public `main` commit `862e771275c320299ee365377d75bb5c6c963c62`, with the current app/service dependencies, selected Review sources and required build/pilot source guards overlaid. Existing binary resources were checked against the base (18 files, zero differences). Private local memory and unneeded local test edits were not copied into the public change set.

On this separate candidate, the Review Release build completed with **0 errors, 0 warnings**, and the documented selected filter produced **1,213 passed, 0 failed, 1 skipped** (1,214 selected cases). This filter additionally excludes the five-case legacy `SettingsViewModelRegressionTests` group; it is not the same selection as the 1,218-case local run. No new malware-efficacy claim follows from either result.

The branch upload is checked against the candidate's Git blob hashes. These are local candidate results, not a claim that GitHub Actions has passed, or that a deployed Windows service/driver/installer was validated.

## Remaining gates

Whole-machine GUI quick/full scans, representative 2–4 GB/HDD and mixed-disk hardware, five cold/warm repetitions, the no-more-than-5% slowdown gate, native ETW actor validation, SYSTEM/two-user IPC and vault operations, physical USB/HID/wireless, signed driver/installer and install/uninstall/rollback pilots are not established by these tests. No real-malware corpus was used.

Ultron Filter native identity-bound enforcement and its legacy bridge remain **disabled**. User-mode scans are not kernel pre-access blocking. Independent Guardian actions, isolated RAR/7z analysis, cross-service resource arbitration and legacy Windows support remain unfinished. A newer source branch does not update an old setup download.

**Şu an emin olmadığım / tam doğrulayamadığım nokta şudur:** Full-scope performance and false-positive rates on the user's real machine, prolonged HDD/mixed-disk loads and native minifilter intervention have not been verified by this limited corpus or a Windows VM pilot.
