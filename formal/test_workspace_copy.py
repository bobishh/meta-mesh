"""Acceptance checks for disposable copies of the complete Cargo workspace."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from formal.copy_workspace import copy_workspace


ROOT = Path(__file__).resolve().parent.parent


class CopyWorkspaceTests(unittest.TestCase):
    def test_copy_contains_every_member_and_has_valid_locked_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "workspace"
            copy_workspace(
                ROOT,
                copied,
                extra_paths=(
                    "vendor/iroh-webrtc-transport",
                    "packages/mesh-replication/fixtures",
                ),
            )

            metadata = subprocess.run(
                ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1", "--manifest-path", str(copied / "Cargo.toml")],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            self.assertEqual(metadata.returncode, 0, metadata.stdout)
            for member in (
                "crates/meta-mesh-core",
                "crates/meta-mesh",
                "crates/meta-mesh-policy",
                "crates/meta-mesh-transport-tests",
            ):
                self.assertTrue((copied / member / "Cargo.toml").is_file(), member)
            for fixture in (
                "history-archive-crypto-v1.json",
                "history-archive-coverage-v1.json",
                "history-archive-v1.json",
                "history-archive-locators-v1.json",
            ):
                relative = Path("packages/mesh-replication/fixtures") / fixture
                self.assertEqual((copied / relative).read_bytes(), (ROOT / relative).read_bytes())

    def test_missing_workspace_member_fails_before_copy_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            (source / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/missing"]\n')

            with self.assertRaisesRegex(RuntimeError, "crates/missing"):
                copy_workspace(source, Path(directory) / "copy")


if __name__ == "__main__":
    unittest.main()
