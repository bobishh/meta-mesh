# Identity sign-in readiness

Run this focused bounded check locally:

```sh
sh formal/check_identity_signin.sh
```

An optional first argument selects an external log directory. The runner uses
the shared pinned TLC release and checksum. Syntax/tool failures cannot count as
successful negative controls. Logs include the actual counterexample actions.

## Scenario and ownership

Two enrolled managers belong to one Identity. Its source device has already
approved a Rusty link; the cold phone may retain an older signed profile without
that locator. The Identity provider owns readiness before taking the approval
snapshot. The SDK owns authenticated profile exchange and catalog verification;
the resource owner still owns board permission. No extra storage scope, new
trust decision, recovery key or directory is introduced by this model.

The finite model checks two sign-in attempts and two abstract timeout ticks:

- A cold phone receives the existing signed locator before catalog lookup.
- The source installs persistent authenticated peer acceptance on its existing
  transport after enrollment. A cold phone must not wait for the old connection
  to reach its relay idle timeout. An online source alone is insufficient.
- Missing peer delivery times out as unavailable, rather than a false empty
  catalog. A fresh attempt remains possible.
- A phone which already knows the locator can load its catalog while the other
  Identity device is offline.
- An unavailable Rusty service leaves a retryable result.
- A completed lookup may legitimately find no application catalog.
- Ready sign-in completes only after authorized board contents load.

The required negative controls bypass profile readiness, turn synchronization
timeout into empty, and return success before board loading. Each must violate
`Safety`. A fourth disables source reconnect and must violate eventual board
loading under fair online delivery without timeout. The first reproduces the
missing-readiness-barrier sequence; the fourth catches an online portal which
never makes its transport available for a fresh authenticated connection.

## Limits and implementation evidence

TLC exhaustively explores this finite abstraction, not every production state.
`AttemptSettles` requires weak fairness of enabled operations and timeout ticks.
`BoardEventuallyLoads` additionally assumes eventual delivery without timeout
and a reachable published catalog, or an already-known locator. It does not
promise that a network response arrives before a real deadline.

Cryptographic checks, certificate/revocation semantics, browser persistence,
board authority, service discovery, peer reconnect mechanics and actual CRDT
bytes are assumed interfaces. A TLA+ pass does not prove their implementation.
Reconnect is an abstract action; persistent acceptance, simultaneous-dial
arbitration, backoff, cancellation and transport handshakes still require
implementation tests. The source-side
redirect/delivery race is outside this model.

Implementation coverage belongs at the Tincanban real-provider/native-Rusty
scenario `e2e/identity-phone-board-discovery.spec.ts`: enroll the phone before
linking Rusty, close its Identity tab, withhold its cold reconnect, start ordinary
approval, and require pending state without callback until profile delivery.
After release of the gate, check board contents, owner rights, photo, reload and
edits. Keep runtime evidence separate from model-check results.
