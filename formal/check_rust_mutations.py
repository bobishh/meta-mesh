#!/usr/bin/env python3
"""Require conformance failures from real Rust mutations, in disposable copies."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
# Exact substitutions fail closed when production code changes. These mutate
# the actual implementation, never the reference model or test expectations.
MUTATIONS = [
    ('stale-route-completes-new-round', 'delivery_flow.rs',
     '            || round != self.round\n',
     '', 'delivery_implementation'),
    ('partial-or-empty-ack', 'replication.rs',
     'accepted.len() == ack.payload.accepted_hashes.len() && accepted == expected',
     'accepted.len() == ack.payload.accepted_hashes.len() && accepted.is_subset(&expected)',
     'tlc_delivery'),
    ('stale-runtime-cleanup', 'runtime.rs',
     '.is_some_and(|session| session.generation == generation)',
     '.is_some_and(|_session| generation > 0)', 'tlc_sessions'),
    ('stale-lifecycle-cleanup', 'session_lifecycle.rs',
     'let was_current = self.current.get(key) == Some(&generation);',
     'let was_current = self.current.contains_key(key);', 'tlc_sessions'),
    ('same-device-tab-alias', 'runtime.rs',
     '        if let Some(previous) = self.sessions.get(&candidate.key) {',
     '        let mut candidate = candidate;\n        candidate.key.instance_id = "tabA".into();\n        if let Some(previous) = self.sessions.get(&candidate.key) {',
     'tlc_sessions'),
    ('revoked-epoch-regains-access', 'access.rs',
     'revocation.payload.epoch >= grant_epoch',
     'revocation.payload.epoch > grant_epoch', 'tlc_authority'),
    ('ownership-conflict-is-ignored', 'ownership_merge.rs',
     'let mut conflicted = has_conflicting_ownership_transfers(&to_values(&accepted)?);',
     'let mut conflicted = false;', 'tlc_authority'),
]

EXPECTED_FAILURES = {
    'stale-route-completes-new-round': 'effect mismatch',
    'partial-or-empty-ack': 'Rust delivery mismatch',
    'stale-runtime-cleanup': 'runtime mismatch',
    'stale-lifecycle-cleanup': 'runtime mismatch',
    'same-device-tab-alias': 'replacement effect mismatch',
    'revoked-epoch-regains-access': 'access after',
    'ownership-conflict-is-ignored': 'alternative signed successor was not a conflict',
}

def main():
    for variable in (
        'MESH_TLC_AUTHORITY_GRAPH',
        'MESH_TLC_SESSION_GRAPH',
        'MESH_TLC_SESSION_IMPLEMENTATION_GRAPH',
        'MESH_TLC_DELIVERY_GRAPH',
        'MESH_TLC_DELIVERY_IMPLEMENTATION_GRAPH',
    ):
        if not os.environ.get(variable) or not Path(os.environ[variable]).is_file():
            raise RuntimeError(f'{variable}: fresh TLC graph is required')
    with tempfile.TemporaryDirectory(prefix='meta-mesh-rust-mutants-') as directory:
        root = Path(directory)
        shutil.copy2(ROOT / 'Cargo.toml', root / 'Cargo.toml')
        shutil.copytree(ROOT / 'crates/meta-mesh', root / 'crates/meta-mesh')
        shutil.copytree(ROOT / 'vendor/iroh-webrtc-transport', root / 'vendor/iroh-webrtc-transport')
        shutil.copy2(ROOT / 'Cargo.lock', root / 'Cargo.lock')
        core = root / 'crates/meta-mesh-core'
        shutil.copytree(ROOT / 'crates/meta-mesh-core', core)
        for name, filename, before, after, test in MUTATIONS:
            source = core / 'src' / filename
            original = source.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f'{name}: mutation target changed; review it, do not skip')
            source.write_text(original.replace(before, after))
            if test == 'tlc_sessions':
                test_args = [
                    '--lib', 'bounded_actual_session_states_conform_to_tla_transitions',
                ]
            elif test == 'delivery_implementation':
                test_args = ['--lib', 'bounded_actual_delivery_states_conform_to_tla_transitions']
            else:
                test_args = ['--test', test]
            try:
                result = subprocess.run([
                    'cargo', 'test', '--locked', '--manifest-path', str(root / 'Cargo.toml'),
                    '--target-dir', str(root / f'target-{name}'), '-p', 'meta-mesh-core',
                    *test_args, '--', '--ignored', '--nocapture',
                ], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=os.environ)
            finally:
                source.write_text(original)
            if result.returncode == 0 or 'test result: FAILED' not in result.stdout or 'panicked at' not in result.stdout or EXPECTED_FAILURES[name] not in result.stdout:
                raise RuntimeError(f'{name}: expected a Rust assertion failure, got exit {result.returncode}\n{result.stdout}')
            print(f'Real Rust mutation caught: {name}', flush=True)

if __name__ == '__main__':
    main()
