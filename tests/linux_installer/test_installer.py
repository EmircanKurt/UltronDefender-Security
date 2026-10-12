"""Benign filesystem installer fixtures; not malware efficacy or desktop certification."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("preview_installer", REPO / "scripts/linux/install.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    """Exercise only explicitly created temporary packages and user directories."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ultron-install-fixture-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "user with spaces"
        self.home.mkdir()
        self.package = self.root / "package"
        self.package.mkdir()
        for name in ("install.py", "uninstall.py"):
            shutil.copyfile(REPO / "scripts/linux" / name, self.package / name)
        (self.package / "Ultron.Linux.App").write_bytes(b"inert preview fixture")
        (self.package / "licenses").mkdir()
        (self.package / "licenses" / "NOTICE.txt").write_text("inert notice", encoding="utf-8")
        self.manifest()

    def tearDown(self):
        self.temporary.cleanup()

    def manifest(self):
        lines = []
        for path in sorted(self.package.rglob("*")):
            if path.is_file() and path.name != "FILE-SHA256SUMS":
                lines.append(hashlib.sha256(path.read_bytes()).hexdigest()
                             + "  ./" + path.relative_to(self.package).as_posix())
        (self.package / "FILE-SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def install(self):
        installer.install(self.package, self.home)
        return installer.locations(self.home)

    def test_install_and_confirmed_remove_preserve_report_and_neighbor(self):
        report = self.home / "report.json"
        report.write_text("user report", encoding="utf-8")
        target, desktop = self.install()
        neighbor = desktop / "unrelated.desktop"
        neighbor.write_text("unrelated", encoding="utf-8")
        self.assertTrue(os.access(target / "Ultron.Linux.App", os.X_OK))
        self.assertIn('Terminal=true', (desktop / installer.DESKTOP_NAMES[1]).read_text())
        self.assertIn('Exec="', (desktop / installer.DESKTOP_NAMES[0]).read_text())
        self.assertTrue(installer.uninstall(self.home, lambda: True))
        self.assertFalse(target.exists())
        self.assertTrue(report.is_file())
        self.assertTrue(neighbor.is_file())

    def test_cancel_removes_nothing(self):
        target, _ = self.install()
        before = installer.inventory(target)
        self.assertFalse(installer.uninstall(self.home, lambda: False))
        self.assertEqual(before, installer.inventory(target))

    def test_existing_install_is_not_overwritten(self):
        target, _ = self.install()
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue((target / installer.RECEIPT).is_file())

    def test_bad_package_hash_leaves_no_install(self):
        (self.package / "Ultron.Linux.App").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.install()
        self.assertFalse(installer.locations(self.home)[0].exists())

    def test_extra_package_file_rejected(self):
        (self.package / "extra.txt").write_text("extra", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.install()

    def test_unsafe_and_duplicate_manifest_rejected(self):
        manifest = self.package / "FILE-SHA256SUMS"
        valid = manifest.read_text()
        for name in ("../outside", "/outside", "dir/../outside", "dir//outside", "INSTALLATION.json"):
            manifest.write_text(valid + "0" * 64 + "  ./" + name + "\n")
            with self.assertRaises(ValueError):
                self.install()
        manifest.write_text(valid + valid.splitlines()[0] + "\n")
        with self.assertRaises(ValueError):
            self.install()

    def test_modified_file_prevents_any_removal(self):
        target, desktop = self.install()
        (target / "licenses/NOTICE.txt").write_text("changed", encoding="utf-8")
        with self.assertRaises(ValueError):
            installer.uninstall(self.home, lambda: True)
        self.assertTrue((desktop / installer.DESKTOP_NAMES[0]).is_file())
        self.assertTrue((target / "Ultron.Linux.App").is_file())

    def test_untracked_personal_file_prevents_removal(self):
        target, _ = self.install()
        (target / "report.json").write_text("personal", encoding="utf-8")
        with self.assertRaises(ValueError):
            installer.uninstall(self.home, lambda: True)
        self.assertTrue((target / "report.json").is_file())

    def test_changed_shortcut_not_deleted(self):
        target, desktop = self.install()
        shortcut = desktop / installer.DESKTOP_NAMES[0]
        shortcut.write_text("unrelated replacement", encoding="utf-8")
        with self.assertRaises(ValueError):
            installer.uninstall(self.home, lambda: True)
        self.assertTrue(target.exists())
        self.assertEqual("unrelated replacement", shortcut.read_text())

    def test_malicious_receipt_path_is_refused(self):
        target, _ = self.install()
        receipt = json.loads((target / installer.RECEIPT).read_text())
        receipt["files"]["../../../outside"] = "0" * 64
        (target / installer.RECEIPT).write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            installer.uninstall(self.home, lambda: True)
        self.assertTrue((target / "Ultron.Linux.App").is_file())

    def test_mutation_during_confirmation_is_rechecked(self):
        target, _ = self.install()
        def change():
            (target / "new-user-file.txt").write_text("retain", encoding="utf-8")
            return True
        with self.assertRaises(ValueError):
            installer.uninstall(self.home, change)
        self.assertTrue((target / "new-user-file.txt").exists())

    @unittest.skipUnless(sys.platform == "linux", "Requires native Linux symlinks; no Windows privilege request.")
    def test_symlink_rejected(self):
        (self.home / ".local").symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.install()
        self.assertTrue((self.package / "Ultron.Linux.App").exists())

    def test_desktop_field_code_and_control_paths_refused(self):
        for name in ("user%f", "user\nnew", "user=other"):
            path = self.root / name
            if sys.platform == "linux" or "\n" not in name:
                path.mkdir()
            with self.assertRaises(ValueError):
                installer.locations(path)

    @unittest.skipUnless(sys.platform == "linux", "Requires native Linux symlinks.")
    def test_package_symlink_rejected_without_following(self):
        outside = self.root / "outside.txt"
        outside.write_text("preserve", encoding="utf-8")
        (self.package / "link.txt").symlink_to(outside)
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual("preserve", outside.read_text())

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux process executable metadata.")
    def test_running_app_refused_without_termination(self):
        shutil.copyfile("/bin/sleep", self.package / "Ultron.Linux.App")
        self.manifest()
        target, _ = self.install()
        process = subprocess.Popen([str(target / "Ultron.Linux.App"), "2"])
        try:
            with self.assertRaisesRegex(ValueError, "Ultron is running"):
                installer.uninstall(self.home, lambda: True)
            self.assertIsNone(process.poll())
            self.assertTrue(target.exists())
        finally:
            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
