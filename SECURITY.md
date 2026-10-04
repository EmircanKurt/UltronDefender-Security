# Security policy

Ultron is an experimental preview, not a validated replacement for your antivirus. Fixes are best effort; no production support or response-time guarantee is offered.

## Reporting

Check **Security → Advisories** for a private reporting option. If available, use it for privilege escalation, quarantine ownership, IPC authentication, unsafe restoration or update integrity issues. Availability must be checked; this file does not enable private reporting.

If no private channel is available, open a minimal issue requesting a confidential contact **without exploit code, sensitive logs or vulnerability details**. Do not assume an unlisted maintainer email exists. Never attach credentials or live malware.

Include the affected commit/version, Windows build, benign reproduction steps, expected/observed behavior and impact. Privileged testing requires an isolated authorized VM.

## Boundaries

User-mode monitoring cannot guarantee survival against an already privileged SYSTEM/kernel attacker. Missing observers, lost events, partial archives and unavailable service status must remain visible. A heuristic score alone must not authorize process termination or irreversible deletion.

Old setup files can differ from development source. Distribution requires signing and installation/rollback/VM checks; local regressions are not certification. Keep Defender or organizational protection enabled.
