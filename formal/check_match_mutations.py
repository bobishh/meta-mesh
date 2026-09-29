#!/usr/bin/env python3
"""Run the bounded receive contract and require the known Match regression."""

from pathlib import Path
import shutil
import subprocess
import tempfile


FORMAL_ROOT = Path(__file__).resolve().parent
MATCH_ROOT = FORMAL_ROOT.parent.parent
TEST_FILE = "src/sync/workspaceSet.test.ts"
TARGET = """        const task = handleLiveWorkspaceStream(stream, incomingContext)
        frameHandlers.add(task)
"""
MUTANT = """        const task = handleLiveWorkspaceStream(stream, incomingContext)
        await Promise.race([task])
        frameHandlers.add(task)
"""


def run_vitest(root: Path) -> subprocess.CompletedProcess[str]:
    vitest = MATCH_ROOT / "node_modules/vitest/vitest.mjs"
    return subprocess.run(
        ["node", str(vitest), "run", TEST_FILE],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def prepare_copy(root: Path) -> None:
    shutil.copytree(MATCH_ROOT / "src", root / "src")
    for name in ("package.json", "vitest.config.ts", "tsconfig.app.json"):
        shutil.copy2(MATCH_ROOT / name, root / name)
    (root / "vendor").mkdir()
    (root / "vendor" / "meta-mesh").symlink_to(MATCH_ROOT / "vendor" / "meta-mesh")


def main() -> None:
    positive = run_vitest(MATCH_ROOT)
    if positive.returncode != 0:
        raise RuntimeError(
            "Match receive contract did not pass before mutation:\n" + positive.stdout
        )
    print("Match receive contract passed", flush=True)

    with tempfile.TemporaryDirectory(prefix="match-receive-mutant-") as directory:
        root = Path(directory)
        prepare_copy(root)
        source = root / "src/sync/workspaceSet.ts"
        original = source.read_text()
        if original.count(TARGET) != 1:
            raise RuntimeError("receive scheduler mutation target changed; review it, do not skip")
        source.write_text(original.replace(TARGET, MUTANT))
        mutant = run_vitest(root)
        if mutant.returncode == 0 or "blocked persistence" not in mutant.stdout:
            raise RuntimeError(
                "serialized receive mutation was not caught by the Match contract:\n"
                + mutant.stdout
            )
        print("Match mutation caught: heartbeat waits behind blocked persistence", flush=True)


if __name__ == "__main__":
    main()
