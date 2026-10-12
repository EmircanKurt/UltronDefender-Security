#!/usr/bin/env python3
"""Install/remove only the unprivileged Linux manual preview, never user reports."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys

APP_ID = "ultron-defender-preview"
RECEIPT = "INSTALLATION.json"
DESKTOP_NAMES = (APP_ID + ".desktop", APP_ID + "-uninstall.desktop")


def checked_path(path):
    """Refuse symlink ancestors and non-directory existing ancestors."""
    path = Path(path).absolute()
    for part in reversed((path, *path.parents)):
        if part.is_symlink():
            raise ValueError("Symbolic-link installation paths are unsupported: " + str(part))
        if part.exists() and part != path and not part.is_dir():
            raise ValueError("Non-directory installation ancestor: " + str(part))
    return path


def locations(home):
    """Use fixed per-user locations; never accept a caller-provided deletion root."""
    home = checked_path(home)
    if home == Path(home.anchor) or not home.is_dir():
        raise ValueError("A non-root, existing home directory is required.")
    if any(c in str(home) for c in "\r\n\t%="):
        raise ValueError("Home paths containing control characters, percent or equals are unsupported.")
    target = checked_path(home / ".local" / "lib" / APP_ID)
    desktop = checked_path(home / ".local" / "share" / "applications")
    return target, desktop


def relative_name(value):
    """Accept only bounded relative package filenames, not traversal or aliases."""
    path = PurePosixPath(value)
    if (not value or len(value) > 512 or path.is_absolute()
            or any(p in ("", ".", "..") for p in value.split("/"))
            or any(c in value for c in "\\\r\n\t\0") or value == RECEIPT):
        raise ValueError("Invalid package filename.")
    return path


def digest(path):
    """Hash a regular, non-symlink file without admitting device/FIFO inputs."""
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Package member is not a regular file: " + str(path))
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def inventory(root):
    """Collect regular files, rejecting all symlinks and unexpected node types."""
    result = set()
    for node in root.rglob("*"):
        mode = node.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("Unsupported package/installation node: " + str(node))
        result.add(node.relative_to(root).as_posix())
    return result


def package_manifest(package):
    """Check exact package membership and every SHA-256 before any installation."""
    package = checked_path(package)
    manifest = package / "FILE-SHA256SUMS"
    digest(manifest)
    if manifest.stat().st_size > 1024 * 1024:
        raise ValueError("Package manifest exceeds its size limit.")
    members = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        if not match:
            raise ValueError("Invalid SHA-256 manifest record.")
        name = str(relative_name(match[2]))
        if name in members or name == "FILE-SHA256SUMS":
            raise ValueError("Duplicate or self-referencing package member.")
        members[name] = match[1]
    if not {"Ultron.Linux.App", "install.py", "uninstall.py"}.issubset(members):
        raise ValueError("Required preview installation files are missing.")
    if not 3 <= len(members) <= 1500 or inventory(package) != set(members) | {"FILE-SHA256SUMS"}:
        raise ValueError("Unexpected or missing package files.")
    for name, expected in members.items():
        if digest(package / name) != expected:
            raise ValueError("Package hash mismatch: " + name)
    members["FILE-SHA256SUMS"] = digest(manifest)
    return members


def exec_argument(value):
    """Quote desktop Exec arguments using both string and command escape layers."""
    return '"' + str(value).replace("\\", "\\\\\\\\").replace('"', '\\\\"').replace(
        "$", "\\\\$").replace("`", "\\\\`") + '"'


def desktop_entries(target):
    """Generate explicit application and terminal-based, confirming removal entries."""
    common = "[Desktop Entry]\nType=Application\nVersion=1.0\nCategories=Utility;\n"
    return {
        DESKTOP_NAMES[0]: common + "Name=Ultron Defender (Linux Preview)\nTerminal=false\nExec="
        + exec_argument(target / "Ultron.Linux.App") + "\n",
        DESKTOP_NAMES[1]: common + "Name=Uninstall Ultron Defender (Linux Preview)\n"
        + "Name[tr]=Ultron Defender Linux sürümünü kaldır\nTerminal=true\nExec=/usr/bin/python3 -B "
        + exec_argument(target / "install.py") + " --uninstall\n",
    }


def write_new(path, content):
    """Never overwrite a pre-existing installation file or application shortcut."""
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def install(package, home):
    """Copy a fully checked package to an exclusive fixed directory; do not launch it."""
    members = package_manifest(package)
    target, desktop = locations(home)
    if target.exists() or any((desktop / name).exists() or (desktop / name).is_symlink()
                              for name in DESKTOP_NAMES):
        raise ValueError("Preview installation already exists. Remove it before reinstalling.")
    target.parent.mkdir(parents=True, exist_ok=True)
    desktop.mkdir(parents=True, exist_ok=True)
    checked_path(target)
    checked_path(desktop)
    target.mkdir(mode=0o700)
    copied = []
    shortcuts = []
    try:
        for name, expected in members.items():
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with (package / name).open("rb") as source, destination.open("xb") as output:
                copied.append(destination)
                shutil.copyfileobj(source, output, 1024 * 1024)
            if digest(destination) != expected:
                raise ValueError("Package changed while installing: " + name)
        (target / "Ultron.Linux.App").chmod(0o700)
        receipt = {"schema": 1, "app": APP_ID, "files": members,
                   "desktop": desktop_entries(target)}
        write_new(target / RECEIPT, json.dumps(receipt, indent=2) + "\n")
        copied.append(target / RECEIPT)
        for name, text in receipt["desktop"].items():
            write_new(desktop / name, text)
            shortcuts.append(desktop / name)
    except Exception:
        for path in reversed(shortcuts + copied):
            path.unlink()
        remove_empty_directories(target)
        raise
    print("Installed manual preview: " + str(target))
    print("Applications menu: Ultron Defender / Uninstall Ultron Defender.")
    print("No service, autostart, protection settings or user reports were changed.")


def remove_empty_directories(target):
    """Remove only empty directories below the already validated application child."""
    checked_path(target)
    directories = [p for p in target.rglob("*") if p.is_dir() and not p.is_symlink()]
    for directory in sorted(directories, key=lambda p: len(p.parts), reverse=True):
        directory.rmdir()
    target.rmdir()


def validate_removal(home):
    """Preflight the entire removal; preserve altered files and unrelated shortcuts."""
    target, desktop = locations(home)
    receipt_path = target / RECEIPT
    if receipt_path.stat().st_size > 1024 * 1024:
        raise ValueError("Installation receipt exceeds its size limit.")
    digest(receipt_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    files = receipt.get("files")
    if receipt.get("schema") != 1 or receipt.get("app") != APP_ID or not isinstance(files, dict):
        raise ValueError("Unrecognized installation receipt.")
    if not 4 <= len(files) <= 1501:
        raise ValueError("Invalid installation receipt size.")
    for name, expected in files.items():
        relative_name(name)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid installation hash.")
    if inventory(target) != set(files) | {RECEIPT}:
        raise ValueError("Unexpected files found. Nothing removed; preserve/review them first.")
    for name, expected in files.items():
        if digest(target / name) != expected:
            raise ValueError("Changed installation file. Nothing removed: " + name)
    entries = desktop_entries(target)
    if receipt.get("desktop") != entries:
        raise ValueError("Installation shortcut receipt mismatch.")
    for name, text in entries.items():
        path = desktop / name
        if path.exists() or path.is_symlink():
            digest(path)
            if path.read_text(encoding="utf-8") != text:
                raise ValueError("Changed application shortcut. Nothing removed.")
    return target, desktop, files


def uninstall(home, confirm):
    """Remove only validated application files after confirmation; never kill processes."""
    target, desktop, files = validate_removal(home)
    ensure_application_closed(target)
    if not confirm():
        print("Removal cancelled. No files changed.")
        return False
    # Repeat the preflight after user input; no recursive delete or data purge.
    target, desktop, files = validate_removal(home)
    ensure_application_closed(target)
    for name in DESKTOP_NAMES:
        (desktop / name).unlink(missing_ok=True)
    for name in files:
        (target / name).unlink()
    (target / RECEIPT).unlink()
    remove_empty_directories(target)
    print("Ultron Linux preview removed. Exported reports and personal files preserved.")
    return True


def ensure_application_closed(target):
    """On Linux compare executable paths only; never inspect arguments or terminate users."""
    if sys.platform != "linux":
        return
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != os.geteuid():
                continue
            executable = os.readlink(entry / "exe")
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            raise ValueError("Cannot verify running user processes; close Ultron and retry.") from error
        if executable == str(target / "Ultron.Linux.App"):
            raise ValueError("Ultron is running. Close it before uninstalling; no process was stopped.")


def main():
    """Linux-only unprivileged entry point with no hidden deletion switches."""
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("Run as your normal Linux desktop user, without sudo/root.")
    if sys.argv[1:] == ["--uninstall"]:
        uninstall(Path.home(), lambda: input("Close Ultron first. Type REMOVE to uninstall: ") == "REMOVE")
    elif not sys.argv[1:]:
        install(Path(__file__).resolve().parent, Path.home())
    else:
        raise ValueError("Usage: python3 -B install.py [--uninstall]")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, EOFError) as error:
        print("Ultron installation/removal failed: " + str(error), file=sys.stderr)
        sys.exit(1)
