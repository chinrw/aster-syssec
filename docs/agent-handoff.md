# Agent handoff

Snapshot: 2026-08-25

Use this document when continuing Host Verification, Runtime Foundation,
syscall analysis, or Specula integration. Refresh the repository identities
before relying on the snapshot. Code, schemas, target files, and generated
evidence remain the sources of truth.

## Refresh first

Record current state before changing or reporting it:

```sh
git status --short --branch
git rev-parse HEAD
git log --oneline --decorate -12
git diff --stat origin/main...HEAD
gh pr view 2 --repo chinrw/aster-syssec
gh pr view 3 --repo chinrw/aster-syssec
```

Re-run checks before claiming that a target, runtime case, or PR is current.
Temporary evidence paths under `/tmp` are observations, not durable inputs.

## State labels

Keep these states separate in reports:

| Label | Meaning |
| --- | --- |
| merged | Reachable from the named public branch |
| implemented | Present on the exact branch or PR under review |
| executed | Run against the named revisions with retained result metadata |
| schema-only | Data contract exists, but no producer or consumer completes it |
| candidate | Requires source and runtime confirmation |
| planned | No implementation should be inferred |

A successful static rule, model counterexample, fuzz crash, or differential
mismatch is a candidate. No current command promotes a candidate to a finding.

## Repository snapshot

### aster-syssec

| State | Revision | Scope |
| --- | --- | --- |
| merged `main` | `0c9a1da` | Host Verification baseline from PR #1 |
| signed tag `v0.3.0` | `421c9d9` | v0.3 Host Verification record |
| open PR #2 | `6e35d0016344832b54c07641a62f1ebde13ba56b` | Runtime schemas and strict guest parser |
| open PR #3 | `c11f7530d4f6c6a7094041e19fd59e95592d9970` | Asterinas QEMU adapter, stacked on PR #2 |

PR #2 and PR #3 had successful `validate` and `host-verification` checks at
this snapshot. Integrate them in stack order. Neither PR was merged.

The package version remains `0.3.0`. Runtime work has not changed the release
tag.

### Pinned Asterinas

`flake.lock` and GitHub Actions pin:

```text
490960ace3e15bf74146e406ec11a9425755cfba
sha256-IjQP49RonXGFv0Bg9KagDJ3ml58F8pePM2p0A0ANpsA=
```

The three persistent Asterinas seam PRs are merged in `chinrw/asterinas`:

| PR | Final head | Scope |
| --- | --- | --- |
| #2 `syssec-uapi-seams` | `ecc0059ab3945e02d44342ea9b77eed22c735b30` | production UAPI helpers, Kani, Miri, layout, fuzz |
| #3 `syssec-fd-protocol` | `5eb921ef74cbd397118270c2e27b38bac4103ff8` | reserved FD protocol and Loom model |
| #4 `syssec-runtime-harness` | `da81ae952e245b6bb60229457f090575c4fe97f6` | isolated guest case runner and partial-EFAULT case |

The flake pin is the runtime-harness content commit before the later SPDX fix
was propagated through the stack. Do not silently replace the pin with a PR
head; update `flake.lock`, checkout preflight, validation evidence, and this
snapshot together.

## System map

```text
Asterinas source (read-only, exact revision)
  |
  +-- inventory --> syscall catalog + drift
  |
  +-- static review --> candidate evidence
  |
  +-- target registry --> checkout preflight --> engine adapter
  |                                           --> normalized result
  |
  +-- agent/specula preparation --> hash-bound handoff script
  |
  +-- runtime request --> strict guest protocol --> Asterinas QEMU adapter
                                                  --> runtime-result + logs

All writable state belongs below an evidence/work root disjoint from source.
```

The main implementation areas are:

| Area | Entry points |
| --- | --- |
| CLI and run lifecycle | `src/aster_syssec/cli.py`, `runs.py`, `profile_commands.py` |
| source identity and provenance | `source.py`, `provenance.py`, `handoff.py` |
| inventory and routing | `inventory.py`, `routing.py`, `data/tracks/*.toml` |
| static review | `scanner.py`, `selection.py`, `data/invariants.toml` |
| Host Verification | `targets.py`, `engines/*.py`, `data/targets/*/*.toml` |
| Runtime Foundation | `runtime/protocol.py`, `runtime/asterinas.py`, `schemas/runtime-*.json` |
| external analysis handoffs | `agent_review.py`, `specula.py` |
| CI and pinned environments | `flake.nix`, `flake.lock`, `.github/workflows/ci.yml` |

## Syscall analysis method

Use a funnel. Each step narrows a concrete contract and leaves evidence for
the next step.

### 1. Pin scope and contract

Start with one exact Asterinas revision, one syscall family, one Track, and one
or more properties from `data/invariants.toml`. The registry contains eight
Tracks and twelve properties. The threat model assumes an unprivileged,
multithreaded process controlling syscall arguments and user memory.

Do not start from “find a vulnerability.” Start from a falsifiable contract,
for example:

```text
Track: user-memory-partial-io
Property: PARTIAL-PROGRESS-CONSISTENCY
Contract: reported bytes equal committed bytes after a user-copy fault
```

### 2. Establish inventory and reachability

Run inventory before reviewing changed code:

```sh
syssec inventory \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --check
```

Inventory reconciles three architecture dispatch tables, handler signatures,
SCML declarations, regression-source references, and Track configuration.
Regression references prove only that a source mentions the syscall.

Static handler scope follows `sys_*` functions and direct same-file callees.
It does not resolve methods, macro expansion, or cross-file call graphs.
`--scope selected` scans all functions in selected files without asserting
syscall reachability.

### 3. Produce candidates, not conclusions

The static backend has nine mechanism-shaped rules for ABI casts, range
arithmetic, panic paths, repeated user metadata reads, copy-out ordering,
blocking under guards, and typed copy-out. Read `docs/static-rules.md` before
interpreting a match.

```sh
syssec review \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --track user-memory-partial-io \
  --rule UNCHECKED-RANGE-ARITHMETIC
```

For every candidate, record the source anchor, claimed contract, missing
proof, and the next discriminator. A source pattern is not runtime impact.

### 4. Extract the smallest production seam

Move reusable arithmetic, parsing, layout, or lifecycle logic into a narrow
production helper only when the syscall path consumes the same helper. Match
the engine to the question:

| Question | Engine |
| --- | --- |
| bounded arithmetic and invariants | Kani |
| host UB, initialization, and layout behavior | Miri |
| bare-metal ABI layout | cross-target object-section layout |
| pure parser/helper input space | cargo-fuzz |
| bounded publication/lifecycle interleavings | Loom |

Target preflight must fail closed when a package, harness, test, symbol, fuzz
target, or layout record is absent. Build, cache, and temporary paths stay
under the evidence root; source lock files and dirty state must remain stable.

### 5. Validate the real guest contract

Runtime work uses a marker-delimited JSON result rather than console-text
inference. The parser seam is:

```python
parse_guest_result(output: bytes, *, max_output_bytes: int) -> dict
```

It accepts boot noise and CRLF but requires exactly one begin marker, one end
marker, one UTF-8 JSON object, bounded output, and a schema-valid guest result.
`GuestProtocolError.code` is part of the public contract.

The Asterinas adapter seam is:

```python
AsterinasQemuAdapter(...).execute(request) -> dict
```

Tests drive these public seams. Preserve that boundary when adding binary
export, Linux execution, or comparison.

### 6. Compare a case-specific relation

Differential evidence requires the exact same static binary on Asterinas and a
pinned Linux VM. Pin the binary, source, compiler, linker, Linux revision,
kernel config, rootfs, QEMU version, machine, CPU, memory, and SMP by hash or
exact identity.

The comparator must name fields and relations for one case. Do not compare
every JSON field blindly. A match is a contract baseline. A mismatch remains a
candidate until mapped to source and confirmed on the real kernel.

## Implemented Host Verification

The registry packages eleven targets:

| Engine | Targets | Current executed baseline |
| --- | ---: | --- |
| Kani | 5 | pass, unwind 8 sufficient |
| Miri | 1 | pass |
| layout | 3 | x86-64, RISC-V 64, LoongArch 64 pass |
| cargo-fuzz | 1 | 1000/1000 runs pass |
| Loom | 1 | pass at 1000 branches, 3 preemptions, 10000 permutations |

The targets cover `UserIoVec` validation, truncation, address arithmetic,
layout, the pure iovec helper fuzz surface, and FD reservation visibility.
Stable expected results are in `docs/v0.3-host-results.json`.

PR and push CI run five Kani proofs, Miri, x86-64 layout, and Loom. Scheduled
nightly CI adds both other layouts and the 1000-run fuzz target. SMP regression,
LTP, kselftest, gVisor, and the differential corpus remain explicit external
requirements.

## Implemented Runtime Foundation

PR #2 defines six schemas:

- runtime target;
- runtime request;
- guest result;
- runtime result;
- pinned Linux oracle image;
- oracle comparison.

The oracle image and comparison schemas are contracts only. No Linux image
builder, Linux QEMU adapter, or comparator producer exists.

PR #3 implements the Asterinas adapter. It:

- validates a self-contained request and exact clean source identity;
- requires source and evidence roots to be disjoint;
- creates a local no-hardlink detached clone below the evidence root;
- places Cargo build and temporary paths below evidence;
- sets Cargo offline mode, the source Rust toolchain, and
  `QEMU_HOSTFWD=off`;
- reuses an explicitly supplied or installed cargo-osdk binary;
- writes process output directly to files to avoid pipe backpressure;
- supervises the process group with separate boot and test deadlines;
- bounds QEMU output and stops on panic or a complete guest result;
- hashes the request and every retained artifact;
- validates `runtime-result.json` before atomically writing it.

The result taxonomy is:

| Outcome | Boundary |
| --- | --- |
| `qemu-start-failure` | wrapper cannot start or exits before guest boot |
| `guest-boot-timeout` | init marker is absent at the boot deadline |
| `guest-panic` | QEMU log contains a panic marker |
| `guest-hang` | guest booted but never emitted a begin marker |
| `test-timeout` | begin marker appeared without a complete result |
| `invalid-protocol` | exited output violates the guest protocol |
| `normal` | one complete schema-valid guest result |

Evidence layout:

```text
<evidence-root>/
├── runtime-request.json
├── runtime-result.json
├── checkout/
├── build/cargo-target/
├── tmp/
└── artifacts/
    ├── stdout.log
    ├── stderr.log
    └── qemu.log
```

There is no runtime CLI or runtime profile yet. The request schema requires
binary and oracle identities, but the Asterinas adapter does not export the
initramfs binary or run the Linux oracle.

## Executed evidence

Host Verification was executed on clean aster-syssec `5f8f38c` and Asterinas
`490960ace`. `VALIDATION.md` records the environment and result bounds.

The current QEMU adapter tree passed the locked package gate with 88 tests,
Ruff, formatting, Pyright, schema validation, Actionlint, and ShellCheck. PR #3
passed both remote CI jobs.

One offline, network-disabled TCG smoke ran against Asterinas
`da81ae952e245b6bb60229457f090575c4fe97f6`. It completed in 131.5 seconds and
returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

This is a positive contract baseline, not Linux differential evidence or a
finding. The smoke preceded a final diagnostics-only text change. The exact PR
head passed the full flake gate, but the full TCG smoke was not repeated after
that text change.

## Safety lanes

Keep work in three execution contexts:

| Lane | Repository role | Allowed output |
| --- | --- | --- |
| core | this repository | inventory, proofs, schemas, parsers, VM/process infrastructure, comparison evidence |
| model | separate analysis context | state variables, transitions, invariants, bounds, source anchors, candidate traces |
| lab | authorization-gated local/private environment | fault plans, runtime confirmation, reproducers, impact assessment |

The `core`, `model`, and `lab` safety classification proposed for target
configuration is not implemented. The main CLI does not enforce these lanes.
Treat the table as an operating boundary until configuration and schema support
land.

Specula currently prepares dry-run or analysis handoffs. It does not execute
phase gates, import counterexamples, or generate runtime requests. Keep model
output candidate-only.

## Validation commands

Package and repository gates:

```sh
nix flake check --no-update-lock-file --print-build-logs

export SYSSEC_WORK_ROOT=/tmp/aster-syssec-integration
nix develop .#default --command ./scripts/ci-integration.sh
```

Host target preflight and profile:

```sh
export ASTERINAS_REPO=/absolute/path/to/clean/asterinas
export SYSSEC_WORK_ROOT=/tmp/aster-syssec-host

nix develop .#formal --command syssec targets check \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT"

nix develop .#formal --command syssec run \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --profile pr \
  --changed-from HEAD
```

Focused Runtime Foundation tests:

```sh
nix develop .#default --command python3 -m unittest \
  tests.test_runtime_protocol \
  tests.test_runtime_schemas \
  tests.test_runtime_asterinas
```

Do not reuse a non-empty evidence root for an adapter execution. Do not place
the work root below source or source below the work root.

## Query map for the next agent

| Task | Read first | Completion criterion |
| --- | --- | --- |
| change syscall inventory | `inventory.py`, `routing.py`, track TOML | three architecture tables and drift tests agree |
| add a static rule | `docs/static-rules.md`, `scanner.py`, `selection.py` | reachable and selected-scope semantics are tested separately |
| add a Host target | `verification-target.schema.json`, sibling target TOML, matching engine | source symbol preflight fails red; exact production harness then passes |
| change evidence lifecycle | `docs/reviewer-contract.md`, `runs.py`, relevant schemas | source/artifact mutation is detected before completion and report consumption |
| change guest parsing | `runtime/protocol.py`, parser tests, guest schema | every stable error code and size/encoding boundary remains covered |
| change QEMU supervision | `runtime/asterinas.py`, adapter tests, runtime-result schema | every outcome is distinguishable through `execute()` and no child process survives |
| add binary export | runtime request schema, Asterinas initramfs build path | one exact static binary and build provenance are hashed and reusable by both VMs |
| add Linux oracle | oracle image schema, runtime result schema | pinned image metadata and the same binary produce a validated result |
| add comparator | oracle comparison schema, one runtime case contract | every compared field has an explicit relation; mismatch remains candidate |
| extend Specula | `specula.py`, handoff schema, Track readiness | phase artifacts are hash-bound and imported counterexamples remain candidates |

## Next work

1. Integrate PR #2, then PR #3, without flattening their review boundaries.
2. Export and hash the exact static binary built into the Asterinas initramfs.
3. Add pinned Linux oracle metadata and a Linux QEMU adapter using that binary.
4. Implement the partial-EFAULT field relation and comparison producer.
5. Register runtime targets and expose execution through an explicit CLI/profile.
6. Extend low-risk ABI helpers and targets: message headers, control-message
   alignment/parser progress, timespec ranges, sigset size, and mmap arithmetic.
7. Add phase-specific Specula execution, hash-bound gates, and candidate-only
   result import in the model lane.
8. Add fault, pause, sequence-fuzz, confirmation, and finding-promotion work
   only in the authorization-gated lab.

For the next core slice, stop when one exact binary is exported with source,
compiler, linker, command, and SHA-256 provenance and can be consumed without
rebuilding by both runtime platforms. Linux execution and comparison are
separate slices.
