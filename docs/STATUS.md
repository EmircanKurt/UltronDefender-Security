# Current verification — 10 October 2026

Development preview evidence, not antivirus certification. [3.2.4 preview setup and checksums](https://github.com/EmircanKurt/UltronDefender-Security/releases/tag/v3.2.4-preview.20261010) · [final audit](reports/FINAL_AUDIT_2026-10-10.md) · [draft PR12](https://github.com/EmircanKurt/UltronDefender-Security/pull/12).

Source/tag: `b2f10a927147eb9250b844ce1428bf80e777c235`. **655 selected benign regressions passed locally and in clean GitHub CI, 0 failed/skipped; solution and Review Release: 0 warnings/errors.** [CI run](https://github.com/EmircanKurt/UltronDefender-Security/actions/runs/38028063016). The initial independent-Review restore failure was reproduced, corrected and rerun successfully. Regression counts are not malware detection rates; the whole host-mutating lab suite was not run.

The signed-update tests use fake HTTP and temporary keys/files; cache tests use isolated SQLite, and UI checks are off-screen. Real benign game/mod corpus, full scan performance, contained-PE parity, live mouse/DPI, multi-user/native service/driver and VirtualBox gates remain open. L1-only warm cache stress wall time rose 15.3% (~9 ms per 10,000 operations) with defensive copies/ordering; warm peak memory stayed essentially unchanged. This is not a full scan speed measurement.

Installer: **NotSigned**, 126,091,934 bytes, SHA-256 `9F136FB11BEA70852EBC1E247BA006188DD0A46D6C82134EA552693082BAA480`. GitHub setup/checksum downloads matched sealed local bytes. Setup was compiled, not installed or executed. It does not install/start a service, driver or autostart; it does not make missing service protection active. Microsoft Defender remains required.

The maintainer explicitly approved promoting the tested preview source to `main`. Its production files match the immutable setup source tag; delivery documentation is newer. This promotion does not activate native service/driver protection or close unfinished VM/corpus/signing gates.

## Older main CI failure — 10 October 2026

The documentation-only main commit initially still ran the obsolete unfiltered live suite. [Run 38028499108](https://github.com/EmircanKurt/UltronDefender-Security/actions/runs/38028499108) aborted in a legacy native WFP call from `LiveEndpointHardeningTests`; it did not pass. This was not the sealed 3.2.4 source. The promoted preview uses the already verified explicit benign allowlist. Native WFP VM testing remains open; do not describe excluding that live test as proving native correctness.

## Historical evidence — 4 October 2026

The earlier results below describe their own source, not this setup. Historical command excerpts are not instructions to replace the current positive-allowlist test script.

Development evidence, not antivirus certification.

Evaluated development changes are proposed in PR #3, not a claim about the older default-branch binary. Source commit: `7a0a8218dad34eb18df611c14ee594f0c6603062`.

## Current fixes

- The old running process was verified at `AegisPC_App/UltronDefender.exe`. Its managed DLL differed from the tested release artifact. Source changes do not automatically update an old running program.
- Report-table foreground and selection use theme resources. Offscreen WPF tests check dark/light contrast, theme replacement and native logical wheel scrolling. These are infrastructure checks, not live app screenshots/tests.
- The generic red banner is neutral connection information. Disabled/degraded protection remains visible; missing/stale data never means active protection.
- Text export does not invent a year-one start date. JSON preserves structured engine failure stage/reason/correlation independently of per-file counters.
- The old 53,311-file failed report recorded no engine failure cause. Its exact exception remains unknown. Current tests verify preserved results and privacy-safe diagnostics, not resolution of that unrecorded exception.

## Evidence

Current Review Release build: **0 errors, 0 warnings**. Focused regressions: **56 passed, 0 failed**. Wider safe selected Review run: **945 passed, 1 privilege/VM test skipped, 0 failed** (946 total). Focused cases are included in the wider total, not added to it.

```powershell
dotnet build tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-restore -warnaserror
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-build --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests"
```

Local TRX artifacts: `TestResults/ScanUiContinuation2026-10-04/targeted-final.trx` and `review.trx`. Private diagnostics are not committed. These are benign regressions, policy/fault-injection and infrastructure tests, not a measured malware detection rate. The skipped privilege-dependent quarantine symlink test did not pass. Earlier 939/1 results are historical, not additional successes.

## Unfinished gates

Isolated Windows VM deployment testing has **not yet been completed** and is planned next. Physical USB/UASP/HID, multi-user service/quarantine isolation, Guardian continuity, installation/uninstallation/rollback and low-end performance require separate pilots.

No live malware or attack firmware was executed. Defender settings, service installation, boot configuration and production quarantine were not changed. Prepared builds remain unsigned unless a later report verifies signing.

Ultron AI is handwritten local review logic, not an LLM or measured probability. User-mode monitoring is not a signed kernel pre-access driver. Do not claim commercial-product parity from these tests.
