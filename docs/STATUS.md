# Development verification

## Game/mod and native menu follow-up — 9 October 2026

See [the scoped implementation report](reports/GAME_MOD_SAFETY_2026-10-09.md). Native WPF state fixtures and benign/synthetic pipeline regressions are separate from real corpus efficacy, performance and VM gates, which remain pending. Preview 3.2.3 is not a signed production release and does not activate a third-party tool feed or kernel enforcement.

## Current safety / light-theme preview — 9 October 2026

The [9 October report](reports/GUARD_SCAN_SAFETY_2026-10-09.md) supersedes older current-preview labels below. Selected positive-allowlist regressions: **537 passed, 0 failed, 0 skipped**. No service/driver/firewall deployment or live malware test was performed. Native Guardian actions and independent vault ownership remain gated. Preview source and setup must be treated as development artifacts, not production protection.

## Current scan/resource preview — 6 October 2026

See [the scan/resource evidence report](reports/RESOURCE_CORRECTNESS_2026-10-06.md) for the current implementation, selected tests, measured limits and remaining gates. The consolidated preview includes the earlier dependencies described below. It remains supplemental experimental protection; native minifilter enforcement, deployed multi-user integration and independent malware efficacy are not validated.

The dated sections below preserve earlier evidence. Their test totals and deployment observations describe those stages, not the current preview or installer.

## Intelligence verification — 5 October 2026

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

The tests describe the local combined intelligence/correlation working tree, not independent CI certification of each remote PR. Pre-existing unrelated local edits were preserved and not included in these scoped commits; remote branch builds/regressions must be repeated before merge. No release/merge is authorized by these results.

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

## Browser Defender / passive protection preview — 6 October 2026

This is a local development preview and system-wide source review, **not completion of the full Browser/Filter/AFK plan**. The installed desktop-linked app, Defender configuration, network rules, radios, boot settings and virtual machines were not changed. No live malware, browser credentials, cookies or external intelligence API credentials were used. App/service payloads were published to a separate private preview directory; no setup, GitHub release or merge was produced by this phase.

### Implemented and regression-tested boundaries

- Browser Defender inventories bounded current-user Chromium/Firefox metadata, selected versions, activation, required/optional permissions and source hints. Missing, malformed, unsupported or truncated metadata remains Unknown/Partial. Unsourced extension blacklist decisions were removed; a store URL or permission is not proof of safety or malware. Root/profile gaps remain visible even when the selected profile is readable. The UI refresh is single-flight.
- WFP receipts distinguish a real nonzero native filter ID from RecordedOnly, Failed and Unsupported. Failed add/remove operations remain retryable; history is bounded. The production native backend currently supports x64 IPv4 outbound targets only. Suspicion/periodicity/domain hints no longer authorize IP-wide blocking. Native filter add/remove was **not run** in this phase.
- Typed file, process, remote and network targets avoid fake file identities. Unsupported native-action proposals are denied; UI assertions are not authority. Guardian's emergency-action/vault migration pilot remains unfinished.
- Passive RDP/physical-console AFK and wireless observation services are compiled, with bounded state, freshness, loss and independent failure/retry handling. Type-3/NLA logons are not falsely attributed to RDP; correlated failures generate proposals, not applied blocks. Production Wi-Fi observation does not bypass location permission. Classic Bluetooth inventory is passive; BLE/pairing/new-HID event integration is incomplete. Native host capture was not validated here.
- Ultron Filter remains audit-only. Both driver templates have unassigned altitude, strict timeout/reply checks and no automatic access-denial path. The inactive legacy bridge cannot enable enforcement. Signing scripts require external assignment evidence and an existing certificate, and cannot alter host trust/boot policy. No WDK build, signed driver installation, Driver Verifier or VM crash/rollback test was performed.
- ZIP/JAR members within existing budgets are stream-hashed, including a renamed 11 MiB member, while deep rules retain a bounded buffer. Incomplete/unsupported/empty/encrypted/budget-limited content is not reported clean. Aggregate compression anomalies mean Partial coverage, not a malware verdict. Nested hash counts and bounded summaries include actual successful work. RAR/7z support and an isolated low-privilege archive worker are not implemented.

The final audit also fixed bulk quarantine recovery falling back to deletion/trust on failure, single-operation receipts being overwritten by refresh, old RT analysis entering a newer policy cache, incomplete RT inspection appearing allowed/clean, stale-generation health changes, and late external scan progress overwriting a terminal result. Unit/disk fixtures validate these boundaries, **not** deployed multi-user service actions.

### Test evidence and exclusions

Solution and Review Release builds: **0 errors, 0 warnings**. Separate self-contained App/service publishes: **0 errors, 0 warnings**. Selected harmless Review: **1,142 passed, 1 privilege/VM case skipped, 0 failed** (1,143 total). Current-phase focused fixtures: **193 passed**, included in that total. Critical 87-case subset: five repetitions, all passed; repeated runs are not additional unique cases or hardware performance benchmarks.

| Focused area | Cases | Evidence type |
|---|---:|---|
| Browser metadata, budgets and presentation | 69 | Pure/source/UI fixtures and temporary metadata files; no real cookie access |
| Network correlation and enforcement receipts | 25 | Pure/fake native backend fixtures; no host filter mutation |
| Typed target authority | 3 | Inert decision/broker fixtures |
| RDP/AFK, wireless and observation lifecycle | 45 | XML/pure/fake source fixtures; no native session rejection or radio changes |
| Ultron Filter pilot | 17 | Source/ABI/timeout and inert decision fixtures; no driver runtime |
| Archives | 10 | Harmless temporary disk archives and inspection coverage |
| Quarantine receipts | 10 | Fake service failures/results; no real user vault recovery |
| RT revision/coverage and terminal scan boundary | 12 | Inert detectors/temporary file or deterministic ownership fixtures; no native race stress |
| Laboratory compile/API boundary | 2 | Project XML/reflection fixtures |

These are mixed infrastructure, security-unit and harmless disk-workflow regressions. They are not a malware corpus, detection percentage, native security integration certification or low-end before/after CPU/RAM comparison. The full Golden suite was not run: its file-writing EICAR case was excluded. The privileged vault-redirection case still needs an isolated VM.

The legacy main test project is **not** a certified harmless suite. Source audit found ten files with real process, ETW, DNS-cache or ACL effects; one can actually invoke shadow-backup deletion. They are now excluded from default compilation and require two explicit laboratory opt-ins. This preserves source rather than hiding payload strings or weakening Defender. A target-only check verified that opting in without the separate lab acknowledgement fails before compilation; the acknowledgement itself does not verify that a safe VM exists.

Defender logged `HackTool:Win64/PSWDump.MX!MTB` and quarantined an earlier main test DLL. After the compile gate, the main DLL was flagged again and the selected one-case run still discovered zero tests. **Neither attempt counts as a test pass.** The API boundary was independently tested in Review. The exact embedded fixture behind that provider verdict remains unknown; no exception, quarantine restore or AV-evasion encoding was added. No evidence here establishes that the production app DLL is malware, or independently certifies that it is clean.

Native host initialization for the separate App preview returned `0x00000000` without executing its managed entry point. This checks runtime resolution only—not UI opening, service installation or active protection. The old portable EXE/DLL hashes and EXE timestamp remained unchanged. Driver PowerShell syntax and whitespace diff checks passed; scripts were not executed.

### Remaining gates

Authenticated caller-context IPC still prevents manual quarantine/restore with the current Identification-only UI token; ownership checks were not bypassed. Two-user SYSTEM/IPC/vault tests, native RDP/WFP/ETW/wireless tests, MV3/native messaging and cookie-read attribution, Guardian actions, unified scan-resource arbitration, RAR/7z isolation, physical USB/HID tests, Windows 10/11 pilot/signing and uninstall/rollback remain open. Current projects still target .NET 8; .NET 10 migration and the separate .NET Framework 4.8 Windows 7/8.1 track are not implemented or validated. No old-Windows or Defender-replacement guarantee is made.

The previous 53,311-file runtime scan failure was not reproduced in the installed app and cannot be declared resolved from these tests. Current source tests cover terminal failure/cancellation/late-progress behavior; the old exception still needs its real runtime diagnostic.

### Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: gerçek SYSTEM↔çok kullanıcı kasa/IPC işlemleri, fiziksel aygıt ve ETW aktör eşlemesi, sürücü/RDP engelleme, düşük donanım performansı, eski tarama hatasının runtime nedeni ve ana test DLL'sindeki Defender tespitinin tam tetikleyicisi henüz izole VM/saha koşullarında doğrulanmadı.
