#!/usr/bin/env python3
"""Exercise the real published Linux package in a disposable, non-root user home."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def run(command, environment, input_text=None):
    """Bound child execution and retain command output for honest failure evidence."""
    result = subprocess.run(command, env=environment, input=input_text, text=True,
                            capture_output=True, timeout=90, check=False)
    print(result.stdout)
    print(result.stderr, file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError("Packaged lifecycle command failed: " + str(command[0]))
    return result


def main():
    """Install, launch the real X11 GUI, cancel removal, then remove only the package."""
    if sys.platform != "linux" or os.geteuid() == 0 or len(sys.argv) != 3:
        raise ValueError("Requires an actual unprivileged Linux host, archive and evidence directory.")
    archive = Path(sys.argv[1]).resolve(strict=True)
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ultron-packaged-lifecycle-") as temporary:
        root = Path(temporary)
        package = root / "extracted"
        package.mkdir()
        with tarfile.open(archive, "r:gz") as stream:
            stream.extractall(package, filter="data")
        test_home = root / "desktop user with spaces"
        test_home.mkdir()
        environment = dict(os.environ, HOME=str(test_home), PYTHONDONTWRITEBYTECODE="1")
        # The HOME override belongs only to these disposable test subprocesses.
        run([sys.executable, "-B", str(package / "install.py")], environment)
        installed = test_home / ".local/lib/ultron-defender-preview"
        desktop = test_home / ".local/share/applications"
        assert installed.is_dir()
        assert installed.stat().st_mode & 0o777 == 0o700
        for name in ("ultron-defender-preview.desktop", "ultron-defender-preview-uninstall.desktop"):
            run(["desktop-file-validate", str(desktop / name)], environment)
        gui_evidence = evidence / "installed-x11"
        run(["xvfb-run", "-a", str(installed / "Ultron.Linux.App"),
             "--gui-smoke", str(gui_evidence)], environment)
        gui = json.loads((gui_evidence / "gui-runtime.json").read_text())
        assert gui["ActualLinuxRuntime"] and gui["VisibleNativeWindow"] and gui["NoStartupScan"]
        assert gui["ManualInertScanReports"] == 1 and gui["Outcome"] == "GuiRuntimeSmokePassed"
        assert not gui["ProtectionVerified"] and not gui["MalwareFreeClaim"]
        for name in ("linux-x11-startup.png", "linux-x11-scan.png"):
            assert (gui_evidence / name).stat().st_size > 1000
        personal = test_home / "exported-report.json"
        personal.write_text("inert user report", encoding="utf-8")
        neighbor = desktop / "unrelated.desktop"
        neighbor.write_text("unrelated user entry", encoding="utf-8")
        run([sys.executable, "-B", str(package / "uninstall.py")], environment, "CANCEL\n")
        assert installed.is_dir()
        run([sys.executable, "-B", str(package / "uninstall.py")], environment, "REMOVE\n")
        assert not installed.exists()
        assert personal.read_text() == "inert user report"
        assert neighbor.read_text() == "unrelated user entry"
        assert not (desktop / "ultron-defender-preview.desktop").exists()
        assert not (desktop / "ultron-defender-preview-uninstall.desktop").exists()
    receipt = {"Outcome": "PackagedInstallGuiUninstallPassed", "ActualLinuxRuntime": True,
               "NoRoot": True, "ConfirmedRemoval": True, "CancelledRemovalPreserved": True,
               "ReportsAndUnrelatedFilesPreserved": True, "ProtectionVerified": False,
               "DesktopFileSyntaxValidated": True, "InteractiveDesktopMenuUxVerified": False}
    (evidence / "lifecycle.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
