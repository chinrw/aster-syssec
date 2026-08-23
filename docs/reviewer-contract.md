# Reviewer contract

## Trust boundary

The Asterinas checkout is input. Inventory and review commands do not edit it.
Evidence is written only below the selected work root. The checkout and work
root must be disjoint in both directions after resolving symlinks.

The Specula profile and Asterinas `aster-code-review` skill are also inputs.
Their hashes are recorded before a handoff. `aster-syssec` does not rewrite
their configuration or guidance.

Every JSON artifact is validated against its declared schema before it is
registered. Completion revalidates the artifact, records its hash and size,
and fails if the source or an artifact changed during the run. `report` verifies
the same records before consuming evidence.

## Result classes

Static rules, model counterexamples, fuzz crashes, and differential mismatches
start as candidates.

A candidate may be promoted only after all of these are recorded:

- the supported syscall or security contract;
- the exact source event sequence;
- a minimized unprivileged reproducer on the real Asterinas kernel;
- the observed Asterinas result;
- a pinned Linux control or another explicit contract oracle;
- the security impact;
- duplicate and known-issue status;
- SMP evidence for a concurrency claim.

No current command promotes a candidate. Promotion and regression insertion are
deliberately absent until a real-kernel runner is implemented.

## Security finding threshold

Reportable impact includes:

- unauthorized access or privilege;
- cross-process or cross-namespace interference;
- kernel or cross-process information disclosure;
- stale access after revocation or object reuse;
- persistent integrity corruption;
- practical unprivileged resource exhaustion;
- repeatable kernel panic, deadlock, or system-wide denial of service;
- unsafe soundness failure.

These are not security findings by themselves:

- an unimplemented syscall;
- SCML-declared unsupported input;
- an errno-only compatibility difference;
- a TODO, FIXME, static match, or unexecuted reproducer;
- a model counterexample that has not been mapped to source and runtime;
- a provider or environment failure.

## Failure posture

Structural parse errors fail closed. Coverage gaps remain visible warnings
unless `--strict-coverage` or baseline regression policy selects them as
blocking.

Specula preparation refuses tracked-dirty linked-worktree exports. The export
is an independent Git checkout containing exact HEAD history and no object
alternates. Agent and Specula adapters generate scripts but do not execute
them. The preflight invocation is pinned to the reviewer source or installed
entry point that prepared the handoff, not a later PATH lookup. Generated
scripts fail closed unless their recorded source, reviewer, configuration,
guidance, launcher, profile, and target identities still match.
