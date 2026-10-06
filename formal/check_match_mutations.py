#!/usr/bin/env python3
"""Run the bounded receive contract and require the known Match regression."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile


FORMAL_ROOT = Path(__file__).resolve().parent
TEST_FILE = "src/sync/workspaceSet.test.ts"
TARGET = """        const task = handleLiveWorkspaceStream(stream, incomingContext)
        frameHandlers.add(task)
"""
MUTANT = """        const task = handleLiveWorkspaceStream(stream, incomingContext)
        await Promise.race([task])
        frameHandlers.add(task)
"""


def find_match_root() -> Path:
    configured = os.environ.get("MATCH_ROOT")
    candidates = [Path(configured).expanduser().resolve()] if configured else list(FORMAL_ROOT.parents)
    for candidate in candidates:
        if (candidate / "package.json").is_file() and (candidate / TEST_FILE).is_file():
            return candidate
    raise RuntimeError(
        "Match checkout not found; set MATCH_ROOT or run from inside Match's vendor/meta-mesh checkout"
    )


def run_vitest(root: Path, tool_root: Path) -> subprocess.CompletedProcess[str]:
    vitest = tool_root / "node_modules/vitest/vitest.mjs"
    return subprocess.run(
        ["node", str(vitest), "run", TEST_FILE],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def prepare_copy(match_root: Path, root: Path) -> None:
    shutil.copytree(match_root / "src", root / "src")
    for name in ("package.json", "vitest.config.ts", "tsconfig.app.json"):
        shutil.copy2(match_root / name, root / name)
    (root / "node_modules").symlink_to(match_root / "node_modules")
    (root / "vendor").mkdir()
    (root / "vendor" / "meta-mesh").symlink_to(match_root / "vendor" / "meta-mesh")


def main() -> None:
    match_root = find_match_root()
    positive = run_vitest(match_root, match_root)
    if positive.returncode != 0:
        raise RuntimeError(
            "Match receive contract did not pass before mutation:\n" + positive.stdout
        )
    print("Match receive contract passed", flush=True)

    with tempfile.TemporaryDirectory(prefix="match-receive-mutant-") as directory:
        root = Path(directory)
        prepare_copy(match_root, root)
        source = root / "src/sync/workspaceSet.ts"
        original = source.read_text()
        if original.count(TARGET) != 1:
            raise RuntimeError("receive scheduler mutation target changed; review it, do not skip")
        source.write_text(original.replace(TARGET, MUTANT))
        mutant = run_vitest(root, match_root)
        if mutant.returncode == 0 or "blocked persistence" not in mutant.stdout:
            raise RuntimeError(
                "serialized receive mutation was not caught by the Match contract:\n"
                + mutant.stdout
            )
        print("Match mutation caught: heartbeat waits behind blocked persistence", flush=True)


if __name__ == "__main__":
    main()
