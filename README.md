<p align="center"><img src="docs/screenshots/logo.png" width="96" alt="Ultron Defender shield"></p>

# Ultron Defender

A free, open-source Windows security project focused on understandable file analysis, local monitoring and honest protection status.

**Experimental preview — use alongside Microsoft Defender, not instead of it.** Independent antivirus efficacy testing and isolated Windows VM deployment testing have not yet been completed. VM testing is planned next; no completion date is promised.

## Why I started

I started this project after losing access to gaming and email accounts in an incident I believe was connected to a malicious game mod. I had disabled Windows protection after dismissing earlier warnings. That experience encouraged me to learn more about software development and defensive security, and to build something useful from it.

This is my personal account, not a verified forensic investigation or proof that Ultron would have prevented the incident. My goal is to make security decisions easier to understand, without suggesting that any tool guarantees safety.

— Emircan Kurt · [Writing on Medium](https://medium.com/@kurtemircan118)

## What the current code does

- Quick, full and selected-path scans with findings, counters and reports.
- File structure classification rather than trusting extensions, with bounded archive inspection.
- User-mode monitoring of configured folders and post-start process observations. Background protection depends on a running, compatible Windows service.
- Local Ultron AI review: handwritten rules and mathematical scoring, **not a chatbot, downloaded LLM or calibrated malware probability**.
- USB/storage/HID discovery and notices. A reported keyboard identity is not proof of safe firmware.
- Quarantine infrastructure with ownership and integrity checks. Some UI operations remain deliberately blocked while their authorization path is unfinished.

These are implemented components, not claims of complete coverage. Independent Guardian protection and emergency native actions remain development work. Ultron does not promise pre-access blocking, firmware verification or superiority to Defender, Bitdefender or Kaspersky.

## Free means free

The current edition has no paid activation key, subscription or expiry. The MIT source license is not an activation requirement. A Windows protection service is a technical background component, not a paid feature. Missing service information must not be presented as active protection.

## Testing and limits

See the [current verification report](docs/STATUS.md) for actual results and outstanding gates. Regression totals do **not** measure malware detection or false-positive rates. EICAR is a workflow test, not real-world efficacy evidence.

Windows 10/11 x64 are development targets; this .NET 8 build does not support Windows 7. Antivirus cannot repair operating-system vulnerabilities or replace supported Windows updates. Keep Defender and workplace protection enabled. School/work deployment requires administrator approval and an isolated pilot.

## Build and review

Requirements: Windows and .NET 8 SDK; Inno Setup 6 only for installer generation.

The reviewed development code is currently in [pull request #3](https://github.com/EmircanKurt/UltronDefender-Security/pull/3). The default branch can still contain older code until the staged changes are reviewed and merged. The commands below intentionally select the reviewed preview branch.

```powershell
git clone --branch codex/rt-ai-free-preview-2026-10-04 https://github.com/EmircanKurt/UltronDefender-Security.git
cd UltronDefender-Security
dotnet build tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release -warnaserror
dotnet test tests/AegisPC.Review.Tests/AegisPC.Review.Tests.csproj -c Release --no-build --filter "FullyQualifiedName!~Golden01_&FullyQualifiedName!~SettingsViewModelRegressionTests"
dotnet publish src/AegisPC.App/AegisPC.App.csproj -c Release -o artifacts/preview/app
```

These commands do not install/start a service. The main test project includes live OS/credential/process fixtures: do not run its whole suite on an everyday PC. Building an installer is not installing it or validating a release.

## Downloads and screenshots

### Downloads

- [Releases and available downloads](https://github.com/EmircanKurt/UltronDefender-Security/releases) — older installers may contain older code. No newly validated, signed production installer is available.
- [Latest development preview — 9 October 2026](https://github.com/EmircanKurt/UltronDefender-Security/pull/9) — current interface and scan-safety source changes. The unsigned 3.2.2 preview installer is a maintainer-only draft, not a public recommended release.

Signing, installation/uninstallation, rollback and isolated Windows VM checks remain required before recommending a new setup. Keep Microsoft Defender enabled.

### Current interface previews

The images below were rendered from the actual WPF controls in the [9 October preview source](https://github.com/EmircanKurt/UltronDefender-Security/tree/118e7cd38760ced1060c9b95505e4c0d04fb12bc). They are **off-screen UI previews with synthetic test data**, not screenshots of a deployed protection service. The sidebar is a test shell using the real item style. History, file paths, scan counts, elapsed time and CPU/RAM readings are fixture values, not protection or performance evidence.

**Light theme — scan selection, scope and history**

![Ultron Defender light-theme WPF preview with scan selection, scope and sample history](docs/screenshots/current/scan-light-preview.png)

**Dark theme — the same scan controls**

![Ultron Defender dark-theme WPF preview with scan selection, scope and sample history](docs/screenshots/current/scan-dark-preview.png)

<details>
<summary>Scanning view — file route, controls and sample counters</summary>

The file-route animation is shown as a still frame. Both views use a harmless synthetic path; they do not show a real malware scan.

**Dark theme**

![Ultron Defender dark scanning-view preview with the file route and synthetic counters](docs/screenshots/current/scan-route-dark-preview.png)

**Light theme**

![Ultron Defender light scanning-view preview with the file route and synthetic counters](docs/screenshots/current/scan-route-light-preview.png)

</details>

[Preview gallery and provenance](docs/screenshots/README.md). Legacy images are no longer used here; they do not represent the current preview.

## Help improve Ultron

Useful contributions include reproducible scan failures, benign false-positive cases, readable UI improvements and measured performance reports. Do not attach credentials or live malware to public issues.

[Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [Community standards](CODE_OF_CONDUCT.md) · [MIT license](LICENSE) · [Third-party notices](docs/architecture/THIRD_PARTY_NOTICES.md)
