# Current verification — 4 October 2026

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
