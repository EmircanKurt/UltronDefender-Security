# Guard / scan safety preview — 9 October 2026

## Verified locally

Release selected regressions: **537 passed, 0 failed, 0 skipped** using `scripts/Test-BenignPreview.ps1`. This is an explicit positive allowlist, not the unsafe main suite. It includes pure policy/infrastructure tests, off-screen WPF UI, and inert temporary-file/content fixtures. The total is not a malware corpus or an independently measured detection/false-positive rate.

Changes compared with the 6 October preview:

- Light-theme native sidebar selected/hover/pressed colors match the permanently dark sidebar. Actual WPF template rendering and text contrast are checked; different viewport widths/DPIs retain scope/history and readable controls. Fixtures do not launch the installed security app.
- Scan chooser includes scope and target/history; active-route presentation uses lightweight vectors. Startup does not request a new scan; service real-time health is separate. Background scans do not activate the scanner window. These are code/fixture checks, not live service certification.
- Static API/syscall references are neutral capability evidence. Unknown signature verification remains a coverage gap; valid timestamped/OS signatures are not penalized merely by names/dates. No global signer/path immunity was added.
- Findings retain stable rule version and incomplete classification/archive limitations. No static file finding invents an actor PID, calibrated probability or successful remediation receipt. Unavailable vault data is not a verified empty vault.
- Quick scope: active executable/module files (not process memory), autorun/startup files, and content added/modified in the last seven days in Downloads/Desktop/Temp. Unsupported service/task persistence inventory is explicitly reported. Full runs this preflight then fixed-volume discovery. Unknown/reparse/access failures remain visible; custom scans are explicit targets, not automatic trust.
- Shared discovery propagates consumer failures and cancellation, checks cancellation on completion, disposes the entire process snapshot, and uses a cancellable bounded idle wait instead of a busy-yield loop. Process-snapshot cleanup is source/build reviewed; its live OS handle behavior is not measured here.
- Protected-folder allowances bind canonical path and current SHA-256. Missing/legacy hashes, renamed/replaced/deleted content and product-self paths do not grant implicit permission. Five real inert disk fixtures cover content replacement/reload, legacy metadata, deletion/rename, name/self immunity and sibling boundaries. Hashing streams content with a bounded buffer; it adds I/O and is not a performance improvement claim. This is an observation allowance, **not** handle/generation-bound native write authorization or an ACL-protected central policy.
- Guardian health invalidates stale/future core leases and clears observer/vault ownership claims. Recovery reservations are not actual Windows service recovery receipts.

## Measured limits

Five alternating 512 KiB / five-token byte-search comparisons on inert data measured median helper time **51.609 ms before / 0.969 ms after**. This only measures the replaced token-search helper, not whole-machine scanning. Shared benign pipeline fixtures copied four Windows DLLs and inspected each five times without actions: three returned low-score clean fixture verdicts; the larger sampled DLL remained **Unknown/incomplete**. Signature/intelligence providers in those fixtures are inert, so these results do not establish production trust coverage.

Resource values are upper budgets/targets, not promised allocation or fixed CPU/disk percentages. Do not fill RAM just to display 2/4 GiB. Unknown/mixed-volume telemetry remains conservative. Low-end hardware and five complete cold/warm machine scans remain pending.

## Packaging / rollback

Version `3.2.2-preview.20261009`. Preview setup uses a distinct per-user AppId/path, ships a self-contained x64 runtime, does not close existing apps, and does not install/start services, drivers, autostart or firewall rules. It does not automatically launch the application. Historical releases/installation are not removed. Runtime/provider dependencies still require compatible Windows; legacy Windows support is not delivered by this build.

The source snapshot must be frozen, re-tested and hash-verified before upload. A built setup is not evidence that installation, rollback, quarantine or service ownership works. Unsigned pilot assets remain **draft/preview** until isolated VM gates pass. Generated/off-screen previews are not screenshots of an installed protection service.

## Remaining gates

1. Process-isolated native WinTrust/AMSI analysis with hard timeout/crash receipts; cooperative cancellation cannot interrupt every blocked native call.
2. Authenticated Guardian core health, single service vault ownership/migration, identity-bound authorization/receipts, stale PID/file generation and multi-user tests in isolated VMs.
3. Signed/licensed intelligence publication, isolated/budgeted RAR/7z workers, driver signing/assigned altitude and pre-access enforcement validation.
4. Scheduled-task/service persistence coverage, native folder actor attribution, telemetry-driven per-volume expansion and physical device scenarios.
5. Harmless VirtualBox guest deployment with no host shared folders, clipboard/file transfer or drag/drop; install/uninstall/rollback and real service tests. No live malware on the everyday host.

Microsoft Defender remains enabled. No automatic deletion, native containment, network isolation or reboot is enabled by these new observation rules.
