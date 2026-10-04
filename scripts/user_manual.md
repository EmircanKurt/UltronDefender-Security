# Ultron Defender: preview usage and installation limits

Ultron is a free, experimental Windows security project. Use it alongside Microsoft Defender. Independent antivirus efficacy testing and isolated Windows VM deployment testing have not yet been completed.

## Source and status

The default branch can contain older application code. See [README](../README.md) for the reviewed preview branch and [verification status](../docs/STATUS.md) for measured results and remaining gates.

Current source implements user-mode monitoring. It does not establish that an installed, signed minifilter blocks threats before access. Ultron AI is local handwritten analysis, not a chatbot or a calibrated malware probability.

## Installer

A new, unsigned setup was packaged on 2026-10-04. Packaging is not a successful installation test. Installation, removal, rollback, multi-user isolation and service recovery still require an isolated Windows VM pilot. Do not treat an older release asset as the latest tested code or a production-ready download.

Historical `install.ps1`, `uninstall.ps1` and `verify_install.ps1` scripts are development artifacts, not a validated deployment path. They can change services, scheduled tasks, registry entries or files. Do not run them on everyday, school or workplace computers without an isolated review and administrator approval. A reported PASS from a helper script is not evidence of antivirus efficacy.

Windows 10/11 x64 are development targets. This .NET 8 application does not support Windows 7. Minimum hardware and performance guarantees have not been established.

## Safe review

Follow the selected benign review-test commands in README. Do not run the whole main test suite on an everyday PC: it contains live OS/process/credential fixtures. Do not execute unknown files to inspect them, disable Defender, or attach credentials or live malware to public issues.

File names and extensions are not proof of safety. Unsupported, unreadable or partially inspected content is not necessarily clean. Background monitoring depends on an actually running, compatible service; an enabled UI switch is not proof of protection.

## Reporting a problem

Include the build/branch, scan type, failure stage, error code and correlation ID if available. Remove personal paths and secrets before posting. Distinguish an observation, a confirmed finding and a successful action; do not call a failed operation a successful block.

See [security reporting](../SECURITY.md) for sensitive reports.
