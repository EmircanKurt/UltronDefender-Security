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

### Şüphecilik ve Doğrulama Notu

Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: üretim paket deposunun çok kullanıcılı ACL/replay davranışı ve MalwareBazaar verilerinin kamuya yeniden dağıtım izni henüz doğrulanmadı.
