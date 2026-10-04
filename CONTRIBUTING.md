# Contributing

Small, reproducible defensive changes are welcome.

1. Describe the problem, Windows build and source revision. Remove private paths, credentials and account details from logs.
2. Keep pull requests focused. Explain changes to security decisions and authorization.
3. Use bounded queues, explicit partial/unknown results and structured evidence. Names, extensions, CPU usage or remote connections alone do not prove malware.
4. Use isolated unit fixtures for policy and real benign integration where needed. Mocks help fault injection; they do not establish real protection. Privileged tests belong in an authorized VM.
5. Run the safe Review build/tests in the README. Report exact commands, failures, skips and untested boundaries. Test totals are not detection rates.
6. Include rollback for service, quarantine, update and installer changes. Automatic destructive actions require independent safety and VM review.

Do not submit malware, credential theft tools, attack firmware or public exploit payloads. Do not disable Defender to pass a test. Do not run the entire live main suite on a school/work PC.

Use clear commit messages such as `fix(scan): preserve terminal failure details`. Security-sensitive reports should follow [SECURITY.md](SECURITY.md).
