#!/usr/bin/env python3
"""Standalone convenience entry for the installed, unprivileged preview remover."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    """Forward to the fixed installed remover, never accept paths or elevated execution."""
    if sys.platform != "linux" or os.geteuid() == 0 or len(sys.argv) != 1:
        raise ValueError("Run python3 -B uninstall.py as your normal Linux user, without sudo.")
    target = Path.home() / ".local" / "lib" / "ultron-defender-preview" / "install.py"
    for node in (target, *target.parents):
        if node.is_symlink():
            raise ValueError("Symbolic-link installation paths are unsupported.")
    if not target.is_file():
        raise ValueError("Ultron Linux preview is not installed in this user's account.")
    return subprocess.call([sys.executable, "-B", str(target), "--uninstall"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print("Ultron removal failed: " + str(error), file=sys.stderr)
        sys.exit(1)
