"""Create a minimal disposable copy of a Rust Cargo workspace."""
import json
from pathlib import Path
import shutil
import subprocess


def _copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("target", ".git", ".DS_Store"),
    )


def copy_workspace(source: Path, destination: Path, extra_paths=()) -> None:
    """Copy the root manifest, lockfile, every workspace member, and extra paths."""
    source = Path(source).resolve()
    destination = Path(destination)
    metadata = subprocess.run(
        [
            "cargo", "metadata", "--locked", "--no-deps", "--format-version", "1",
            "--manifest-path", str(source / "Cargo.toml"),
        ],
        cwd=source,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if metadata.returncode:
        raise RuntimeError(f"cannot inspect Cargo workspace at {source}: {metadata.stderr}")

    data = json.loads(metadata.stdout)
    member_ids = set(data["workspace_members"])
    members = [package for package in data["packages"] if package["id"] in member_ids]
    if not members:
        raise RuntimeError(f"Cargo workspace at {source} has no members")

    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / "Cargo.toml", destination / "Cargo.toml")
    shutil.copy2(source / "Cargo.lock", destination / "Cargo.lock")
    paths = {Path(package["manifest_path"]).parent for package in members}
    paths.update(source / path for path in extra_paths)
    for path in sorted(paths):
        if not path.is_dir():
            raise FileNotFoundError(path)
        relative = path.relative_to(source)
        _copy_tree(path, destination / relative)
