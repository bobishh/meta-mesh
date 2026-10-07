#!/usr/bin/env python3
"""Require real Rust causal-admission assertions to catch policy mutations."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = [
    (
        "regrant-rebind",
        "crates/meta-mesh-core/src/causal_admission.rs",
        "metadata.authority_grant_hash.as_deref() == Some(grant_hash.as_str())",
        "true",
        "--lib",
        None,
        "regrant_cannot_rebind_existing_editor_change_hash",
        "new grant must not rebind old editor change",
    ),
    (
        "missing-dependency-admission",
        "crates/meta-mesh-core/src/causal_admission.rs",
        'CausalAdmissionStatus::Pending {\n                        reason: "Change dependency is missing".into(),\n                    },',
        'CausalAdmissionStatus::Admitted {\n                        role: roles.get(&node.hash).copied().unwrap_or(WorkspaceRole::Owner),\n                    },',
        "--lib",
        None,
        "pending_raw_change_with_missing_dependency_is_retained_pending",
        "missing dependency must stay pending",
    ),
    (
        "receiver-clock-authority",
        "crates/meta-mesh-core/src/authorization.rs",
        "Self::from_snapshot(raw, i128::MAX / 2)",
        "Self::from_snapshot(raw, 0)",
        "--lib",
        None,
        "regrant_cannot_rebind_existing_editor_change_hash",
        "causal validation must ignore receiver clock",
    ),
    (
        "owner-rebind-legacy-identity",
        "crates/meta-mesh-core/src/causal_admission.rs",
        "if !metadata_identity_matches(record, node) || identityless_legacy_owner_rebind {",
        "if false {",
        "--lib",
        None,
        "owner_proof_cannot_rebind_legacy_editor_change_after_revocation",
        "owner cannot rebind prior editor identity metadata",
    ),
]


def run_test(workspace: Path, target_dir: Path, selector: tuple[str, str | None, str]) -> subprocess.CompletedProcess[str]:
    mode, integration_target, test_name = selector
    command = [
        "cargo",
        "test",
        "--locked",
        "--manifest-path",
        str(workspace / "Cargo.toml"),
        "--target-dir",
        str(target_dir),
        "-p",
        "meta-mesh-core",
    ]
    if mode == "--test":
        command += [mode, integration_target, test_name]
    else:
        command += [mode, test_name]
    command += ["--", "--nocapture"]
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=os.environ.copy(),
    )


def main() -> None:
    graph = os.environ.get("MESH_TLC_CAUSAL_ADMISSION_GRAPH")
    if not graph or not Path(graph).is_file():
        raise RuntimeError("MESH_TLC_CAUSAL_ADMISSION_GRAPH: fresh TLC graph is required")

    with tempfile.TemporaryDirectory(prefix="meta-mesh-causal-admission-mutants-") as directory:
        workspace = Path(directory)
        shutil.copy2(ROOT / "Cargo.toml", workspace / "Cargo.toml")
        shutil.copy2(ROOT / "Cargo.lock", workspace / "Cargo.lock")
        shutil.copytree(ROOT / "crates/meta-mesh", workspace / "crates/meta-mesh")
        shutil.copytree(ROOT / "vendor/iroh-webrtc-transport", workspace / "vendor/iroh-webrtc-transport")
        shutil.copytree(ROOT / "crates/meta-mesh-core", workspace / "crates/meta-mesh-core")

        baseline = run_test(
            workspace,
            workspace / "target",
            ("--lib", None, "causal_admission::tests"),
        )
        if baseline.returncode != 0 or "test result: ok" not in baseline.stdout:
            raise RuntimeError(f"Pristine Rust causal tests failed\n{baseline.stdout}")
        print("Pristine Rust causal tests passed", flush=True)

        for name, relative, before, after, mode, integration_target, test_name, assertion in MUTATIONS:
            source = workspace / relative
            original = source.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f"{name}: mutation target changed; review it, do not skip")
            source.write_text(original.replace(before, after))
            try:
                result = run_test(
                    workspace,
                    workspace / "target",
                    (mode, integration_target, test_name),
                )
            finally:
                source.write_text(original)
            if (
                result.returncode == 0
                or "test result: FAILED" not in result.stdout
                or assertion not in result.stdout
            ):
                raise RuntimeError(
                    f"{name}: expected concrete Rust assertion failure, got exit {result.returncode}\n"
                    f"{result.stdout}"
                )
            print(f"Real Rust mutation caught: {name}", flush=True)


if __name__ == "__main__":
    main()
