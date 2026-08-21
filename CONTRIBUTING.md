# 🤝 CONTRIBUTING TO ULTRON DEFENDER TOTAL SECURITY

Thank you for your interest in contributing to Ultron Defender Total Security! We welcome contributions from developers, security researchers, and security practitioners.

---

## 1. Development Principles

1. **Defensive Security Only:** No offensive exploitation tools, payload generators, or malware development scripts will be accepted.
2. **Zero-Mock Policy:** All new detectors and features must include automated xUnit test fixtures verifying behavior against real Win32/filesystem semantics.
3. **No Unbounded Summation:** Scoring rules must respect category caps and evidence confidence.
4. **Never Break Traversal:** Directory walking must use safe queue-based traversal and tolerate junction points and access errors without throwing unhandled exceptions.

---

## 2. Pull Request Workflow

1. Fork the repository.
2. Create a logical feature/fix branch (`git checkout -b fix/desktop-scan-traversal`).
3. Ensure all 202+ tests pass locally (`dotnet test`).
4. Commit using standard semantic commit messages (`security:`, `feat:`, `fix:`, `test:`, `docs:`, `perf:`).
5. Open a Pull Request detailing the technical rationale and test evidence.
