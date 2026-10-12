# Linux graphical preview

This is a separate Avalonia desktop application with a sidebar, manual scan scope,
progress, pause/cancel controls, result rows and explicit JSON export. It does not
change the Windows WPF application or its services. It starts with no selected
scope and does not scan on startup. No root privileges are requested.

## Installation and removal (no sudo)

The x64 archive is a self-contained **manual inspection preview**, not the Windows
protection service. Verify the download SHA-256, extract into a new folder and run:

```bash
python3 -B install.py
```

Python 3.11+ is required for installation/removal (Ubuntu 24.04 provides Python
3.12). Installation verifies every packaged file and creates only
`~/.local/lib/ultron-defender-preview` and two application-menu entries under
`~/.local/share/applications`: **Ultron Defender (Linux Preview)** and
**Uninstall Ultron Defender (Linux Preview)**. It requests no root, service,
autostart, firewall or Defender changes. The fixed default user locations are
deliberate; custom XDG locations are not supported by this initial installer.
Existing installations/shortcuts are not overwritten. Uninstall first to upgrade.

To remove it, close Ultron, select its **Uninstall** menu entry and type `REMOVE`
in the confirmation terminal. Alternatively run `python3 -B uninstall.py` from
the extracted package. Only receipt-listed application files and its two unchanged
shortcuts are removed. Exported reports, downloaded archives and personal files
are retained. Changed/untracked files or symlink ancestors cause a refusal before
deletion, not a recursive force-delete. Move personal files out of the application
folder before trying again. Do not run either script using sudo/root. Home paths
containing control characters, `%` or `=` are refused to avoid desktop Exec ambiguity.
Hashes check package integrity, not a publisher signature; the preview is unsigned.
The unprivileged installer is not a security boundary against another process
already controlling the same user account or changing its files concurrently.

## Build from source

The UI pins MIT-licensed [Avalonia 12.1.4](https://www.nuget.org/packages/Avalonia/12.1.4).
Its package targets .NET 8, but its analyzers need a newer compiler than the
repository's Windows .NET 8 SDK provides. Use a stable .NET 10 SDK to build these
new projects; `global.json` is scoped to their directories. The application targets
`net8.0`, and framework-dependent execution also needs a .NET 8 runtime. This
does not upgrade the Windows projects. [.NET 8 support ends November 10, 2026](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core);
the preview needs a separately reviewed target-framework upgrade before that date.

```bash
cd tools/Ultron.Linux.App
dotnet build -c Release -warnaserror
dotnet run -c Release --no-build
```

The initial verification target is Ubuntu x64 with glibc, a Linux kernel with
`statx` support, and X11/XWayland. Linux arm64 is a packaging candidate, not a
claim of an executed arm64 test. Alpine/musl, native Wayland, sandboxed packaging,
accessibility and all desktop file-picker backends still require separate tests.
Avalonia documents the [Linux desktop requirements](https://docs.avaloniaui.net/docs/deployment/desktop-linux)
and [X11/Xvfb packages](https://docs.avaloniaui.net/docs/deployment/docker).

## Inspection and limitations

| Capability | Preview status |
| --- | --- |
| Manual local file/folder selection | Implemented through desktop storage pickers; backend UX requires desktop validation |
| SHA-256 / content identity | Bounded immutable regular-file snapshot; hash is evidence identity, not trust |
| Text / script candidates | Shared structural classifier; local MiniYARA review only, full script semantics unavailable |
| MiniYARA | Existing managed engine source linked; supported subset only, default string matches are review indicators |
| ZIP members | In-memory bounded decoding, no disk extraction; nested/encrypted/unsupported members incomplete |
| EXE / DLL | Shared PE header/section boundary classification; deep PE, Authenticode and Windows providers unsupported |
| ELF / native Linux malware analysis | Unsupported; unknown coverage, no safety verdict |
| Real-time protection / ETW / Defender / WFP | Unsupported |
| Quarantine / deletion / process termination | Unsupported; no action or containment authority |

The portable project source-links `FileContentClassifier`, `ContentStructureValidator`,
`ZipContentStructureInspector`, `FileContentClassification`, `IFileContentClassifier`,
`ScanStageMeasurements`, the managed MiniYARA files and `DetectionPolicyRevision`.
It does not create a second detection-rule implementation. Its small container-header
adapter supplies only the classifier's routing predicate. The Windows script detector
and decision/policy engine are not ported; this preview deliberately publishes no
Windows risk score, exact malware authority or clean verdict.

Hard budgets: 16 MiB per file, 5,000 visited paths, 32 directory levels, 15 minutes
per scope, 256 MiB of source file data per session, 128 ZIP members and 32 MiB of
expanded member data per outer archive. The expanded-byte cap is per archive;
the separate 256 MiB session cap reserves source-file reads before they begin.
Limits can be reduced through the API but cannot exceed
these caps. Inspection working buffers include one file snapshot, one member
snapshot and decoder buffers. The retained bounded report collection and frozen
UTF-8 JSON export payload require additional memory; this is not a total process
RAM cap. Result rows display at most 500 entries. The JSON retains the
full bounded report collection. Cancellation interrupts admitted operations and
remains effective during pause. Pause takes effect at the next file boundary.
This does not promise interruption of an unresponsive kernel/filesystem I/O call.

Linux input paths are walked with descriptor-relative `openat` and `O_PATH |
O_NOFOLLOW | O_CLOEXEC`, including every ancestor. The captured node's `statx`
type must be a regular file or a directory. Device, FIFO, socket and symbolic-link
nodes are never opened for content. Directories are enumerated through their own
`/proc/self/fd` handle, and content is opened only through a pinned regular-node
descriptor. Cross-device traversal is unsupported. Required inode/size/type/time
metadata must be present; changed/truncated reads and metadata changes discard
the snapshot result. This is a bounded file snapshot, not an exclusive Linux
security lock or a general defense against malicious filesystems/mount changes.

The fixed native structure and flag definitions were checked against the primary
[Linux statx UAPI](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/stat.h),
[Linux open flags](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/fcntl.h),
and [glibc openat/AT_EMPTY_PATH declarations](https://raw.githubusercontent.com/bminor/glibc/master/io/fcntl.h).
The implementation accepts only Linux x64/arm64 and fails closed when required
native entry points or metadata are unavailable. Root filesystem scope is refused.

Scan inputs are never executed, extracted to disk, modified or uploaded. The
existing MiniYARA engine initializes only its three default rule files in a fresh,
private 0700 temporary directory when a scan is explicitly requested. After the
managed snapshot is loaded, that temporary directory is removed. Persistent/custom
rule folders are not loaded by this preview. Failed and unstable read attempts
consume their reserved source-byte budget, and every enumerated entry consumes
the visited-path budget even if opening it fails. Admission reserves the declared
source size plus one byte for a bounded EOF probe. A virtual source whose actual
data exceeds its reported size remains hashless and incomplete. JSON
export writes only to the location chosen by the user and includes local paths;
sharing the report is a separate user decision.

## Evidence gates

```bash
# With the pinned .NET 10 SDK + .NET 8 runtime on actual Ubuntu:
cd tests/Ultron.Linux.Tests
dotnet test -c Release -warnaserror \
  --logger 'trx;LogFileName=linux-preview.trx'
cd ../..

# Real platform window and one inert manual scan, not the headless backend:
xvfb-run -a dotnet tools/Ultron.Linux.App/bin/Release/net8.0/Ultron.Linux.App.dll \
  --gui-smoke artifacts/linux-gui-runtime

# After runtime gates pass, create an unuploaded preview archive:
bash scripts/package-linux-preview.sh linux-x64
```

`IncludeGuiTests=false` is an explicit portable/native-only diagnostic mode for
an older SDK; it does not validate the GUI. The default test project includes GUI
tests. Headless tests use the official [HeadlessUnitTestSession and Skia rendering](https://docs.avaloniaui.net/docs/testing/setting-up-the-headless-platform).
Native Linux fixtures are explicitly skipped on Windows; such a run cannot satisfy
the Linux gate. CI must reject any unexpected skipped native scenario.

The real `--gui-smoke` mode is opt-in. It requires an actual Linux process, creates
a visible native platform window, verifies the native handle, confirms no startup
scan, manually scans one inert temporary file through the actual start button,
saves two rendered PNGs and a runtime JSON receipt, then exits. A nonzero exit,
missing receipt or missing images fails the gate. The temporary inert fixture is
removed afterward. This proves basic X11 GUI creation and manual scan flow only;
it does not prove native picker UX, long-duration behavior, protection efficacy,
or distribution portability. No Linux download is ready until actual Ubuntu
runtime evidence and package verification have been read.

## Verification note

The Windows host's portable unit-test pass and a cross-compilation are not Linux
runtime evidence. Native paths, headless rendering and actual X11 launch are
separate checks. Real malware efficacy, arm64, picker backends and production
Linux security-service integration remain unverified by this preview.
