# Intelligence verification — 5 October 2026

Development evidence, not antivirus certification. This stage builds on the existing draft RT/AI preview, not the old default-branch installer.

## Local-only intelligence

Unsigned embedded/XOR/SQLite records are retained as review metadata; they no longer authorize an exact-malware verdict. SHA-256 fields require exactly 64 ASCII hexadecimal characters. EICAR remains a separately identified **test marker**, not a real-malware efficacy test.

Manual and real-time exact matches share the authenticated catalogue. Caller-supplied hashes, publisher display names and family labels do not certify malicious or clean content. This intentionally reduces the active exact-signature count: the current build has two built-in EICAR hashes and **no activated third-party package**. Content/AMSI/heuristic analysis remains separate.

The endpoint no longer queries MalwareBazaar or sends scanned files/hashes there, even with an old cloud preference. A separate developer tool issues only the documented recent-metadata query, with bounded response size, duration and record count. It cannot download samples or upload endpoint files/hashes. It reports missing intervals, partial results, cancellation and timeout distinctly. Last-hour results do not cover a missed day. [MalwareBazaar API](https://bazaar.abuse.ch/api/)

Developer tool: `tools/Ultron.ThreatIntel.Collector`. Configure `ULTRON_MB_AUTH_KEY` locally, never in a committed setting, command-line argument or chat. Output must end in `.intel-collection.json` and is ignored by Git. No real API credential was used and no live metadata collection was performed in these tests.

Separate RSA-PSS/SHA-256 intelligence manifests bind exact content hash, size, sequence, version, expiry and source metadata. Offline journal replacement/previous-good rollback are implemented and tested in private temporary directories. Legacy SQLite migration takes a consistent backup and keeps old rows review-only. Expired signed history retains the replay floor without blocking a fresh verified update; expired records cannot be used for detection or rollback.

**Production activation remains closed:** a real pinned publisher key, private signing workflow, protected service-owned repository ACL, public redistribution permission/terms review, and VM integration must be completed. A signed label is publisher accountability, not independent malware certification. The application being free does not establish unlimited provider-data redistribution rights. [Provider terms](https://abuse.ch/terms-of-use/)

## Evidence

Review Release build and separate developer-tool Release build: **0 errors, 0 warnings**. Intelligence/privacy focused tests: **31 passed, 0 failed**. These cover inert metadata, generated lab signing keys, disk-backed package rollback/migration and fake HTTP responses—not malware detection rate, live provider access or a deployed SYSTEM service.

```powershell
dotnet build tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-restore -warnaserror
dotnet build tools/Ultron.ThreatIntel.Collector/Ultron.ThreatIntel.Collector.csproj -c Release -warnaserror
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~ThreatIntelProvenanceReviewTests|FullyQualifiedName~MetadataCollectorReviewTests|FullyQualifiedName~CloudAuthenticationSafetyTests"
```

The focused run was taken from the combined intelligence/correlation working tree; it is not an independent build certification of every intermediate PR commit. No release/merge is authorized by these results.

## Unfinished deployment gates

Windows VM testing, multi-user SYSTEM/IPC/vault authorization, production repository ACL/replay isolation, installer signing and installation/uninstallation/rollback are still pending. No real malware or attack firmware was used. Defender, installed protection services and boot configuration were not changed. Current builds are experimental supplemental protection, not a Defender replacement.

## Observation correlation and real-time durability

A bounded shared behavior queue feeds the existing review-only decision engine. Process identity includes PID, reported creation time and the OS-reported boot epoch. Lineage is detached, iterative, generation-bound and capped; stale exit events cannot terminate the newer node in the tracker.

The local correlator has 30-second and five-minute windows, deduplicates repeated features, uses family caps and reports EWMA/median/MAD as review statistics—not malware probability. A watcher or file-lock owner cannot identify the writer. New rules are not connected to a quarantine/termination executor.

A post-operation ETW file/thread/process observer is compiled, with bounded actor maps and explicit queue loss/unattributed writes. It is **disabled by default** behind `EnableExperimentalFileIoObservation`; no native ETW session from this new observer was started in this work. Existing processes without observed creation/thread identity remain unattributed. Native volume/file identity and actor-linked persistence attribution are not yet established; the StartupChanged contract currently has no production actor-verifying producer. The observer is not a pre-access driver.

Real-time cached clean verdicts require a verified content hash and a fresh catalogue check; malformed hash/sentinel output cannot establish a clean or confirmed-malware verdict. Existing bounded/cancellable watcher reconciliation remains, with added historical watcher error counts in service health. Arrival workers remain separate from one-at-a-time background recovery; a unified priority CPU/memory arbiter and low-end hardware validation are still pending.

Correlation/RT focused tests: **70 passed, 0 failed**. Combined safe selected Review: **944 passed, 1 privilege/VM case skipped, 0 failed** (945 total). Focused cases are included, not added to this total. Tests include pure decision/infrastructure fixtures and real temporary disk I/O; there was no real-malware corpus or deployed multi-user service integration. The broad unsafe main suite was not run. Old cloud tests were reframed for the chosen local-only edition; response bounds/gap tests now exercise the separate collector.

Five synthetic 500-event runs measured in-memory review p95 **0.023–0.036 ms**, and per-run testhost CPU deltas **0–15.6 ms**. The testhost's cumulative peak working set was **187,314,176 bytes** in that run; this includes the whole regression host, **not** Ultron/Guardian incremental RAM. These are target smoke measurements, not evidence of faster disk scanning, low-end hardware performance or the one-second native-action target.

```powershell
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-build --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests"
```

Private TRX files are kept outside Git. App/service Release payloads were prepared separately without installing, launching or replacing the desktop-linked app. This work did not replace the existing GitHub setup draft.

### Harmless VM pilot still required

The read-only inventory previously showed Windows 11 Pro, 16 GB RAM, firmware virtualization enabled and no active hypervisor. Hyper-V activation/restart requires separate approval; nothing was enabled. Planned first guest: Generation 2, 2 vCPU, 4 GB RAM, 64 GB disk, Secure Boot/vTPM, no shared host folders/personal account or data. Only harmless temporary fixtures are permitted. [Windows VM requirements](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements)

Pilot checks must cover event loss/recovery, source/consumer failure, PID/thread reuse, two-user vault/IPC authorization, package ownership and replay/rollback, legitimate backup/update/build/game/PowerShell workloads, and five repetitions of latency/CPU/peak-memory measurements. Malicious samples and automatic containment stay out of this pilot.

### Earlier UI/scan investigation

The previous 53,311-file failed scan omitted its engine exception; its exact runtime cause remains unknown. Earlier report/wheel/theme fixes and their tests are inherited from the preview base, not new UI work in this stage. A local-only policy and a passing regression suite do not prove that old runtime exception was fixed.

### Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: gerçek Windows ETW akışındaki aktör eşlemesi, üretim paket deposunun çok kullanıcılı ACL/replay davranışı, MalwareBazaar verilerinin kamuya yeniden dağıtım izni ve düşük donanım sonuçları henüz VM/saha testleriyle doğrulanmadı.

