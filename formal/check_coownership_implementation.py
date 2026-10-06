#!/usr/bin/env python3
"""Check that real Rust co-ownership assertions catch representative mutations."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = [
    (
        "quorum-bypass",
        "if approved_people.len() < policy.quorum(owners.len()) {",
        "if false {",
        "one of two current owners cannot approve a majority transition",
    ),
    (
        "stale-parent-epoch",
        "        || epoch != expected_epoch\n",
        "        || false\n",
        "transition epoch must match exact parent epoch",
    ),
    (
        "forget-sibling-history",
        "    for record in &current.transitions {\n",
        "    for record in current.transitions.iter().take(0) {\n",
        "merge must retain both authenticated sibling certificates",
    ),
]


def main():
    graph = os.environ.get("MESH_TLC_COOWNERSHIP_GRAPH")
    if not graph or not Path(graph).is_file():
        raise RuntimeError("MESH_TLC_COOWNERSHIP_GRAPH: fresh TLC graph is required")

    with tempfile.TemporaryDirectory(prefix="meta-mesh-coownership-mutants-") as directory:
        root = Path(directory)
        shutil.copy2(ROOT / "Cargo.toml", root / "Cargo.toml")
        shutil.copy2(ROOT / "Cargo.lock", root / "Cargo.lock")
        shutil.copytree(ROOT / "crates/meta-mesh", root / "crates/meta-mesh")
        shutil.copytree(ROOT / "vendor/iroh-webrtc-transport", root / "vendor/iroh-webrtc-transport")
        core = root / "crates/meta-mesh-core"
        shutil.copytree(ROOT / "crates/meta-mesh-core", core)
        source = core / "src/coownership.rs"

        for name, before, after, expected_assertion in MUTATIONS:
            original = source.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation target changed; review it, do not skip")
            source.write_text(original.replace(before, after))
            try:
                result = subprocess.run(
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--manifest-path",
                        str(root / "Cargo.toml"),
                        "--target-dir",
                        str(root / f"target-{name}"),
                        "-p",
                        "meta-mesh-core",
                        "--test",
                        "tlc_coownership",
                        "coownership_implementation_negative_controls",
                        "--",
                        "--nocapture",
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=os.environ.copy(),
                )
            finally:
                source.write_text(original)
            if (
                result.returncode == 0
                or "test result: FAILED" not in result.stdout
                or "panicked at" not in result.stdout
                or expected_assertion not in result.stdout
            ):
                raise RuntimeError(
                    f"{name}: expected concrete assertion failure, got exit {result.returncode}\n"
                    f"{result.stdout}"
                )
            print(f"Real Rust mutation caught: {name}", flush=True)


if __name__ == "__main__":
    main()
