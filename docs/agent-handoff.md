# Agent handoff

Snapshot: 2026-08-27

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
gh pr list --repo chinrw/aster-syssec --state open --limit 10
gh pr view 5 --repo chinrw/asterinas
gh run list --repo chinrw/aster-syssec --branch main --limit 5
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
| merged `main` | `f2f431c` | PR #1-#9: Host Verification, Runtime Foundation, binary export, pinned Linux oracle, and the first real differential baseline |
| signed tag `v0.3.0` | `421c9d9` | v0.3 Host Verification record |

All nine aster-syssec PRs are merged. PR #9 head
`c47ac40e3ae27c4575a539bc6a3a2bbed41518c6` passed `validate` and
`host-verification`; merge commit `f2f431c47430b308bfec406a54b745fdb89d712b`
is the current public baseline.

Main push run `32953069193` completed successfully on that merge commit. Both
`validate` and the PR-profile `host-verification` job passed.

Scheduled run `33004803564` executed the `nightly` profile on the same merge
commit and passed. The nightly profile contains all 11 packaged Host targets.
The bounded evidence pack remains enabled; the earlier manual validation of
that pack contained 87 files and 1,173,048 uncompressed bytes, compared with
the pre-fix 1,136,398,829-byte artifact that included cache and build trees.

The package version remains `0.3.0`. Runtime work has not changed the release
tag.

### Pinned Asterinas

`flake.lock` and GitHub Actions pin:

```text
d0bddbf56d893221d103a0c3330f379dc59977b9
sha256-eUJRAbB3KLNJTWB20lgIE+YeBSbaV9aNq8Q98w9YJaY=
```

The three persistent Asterinas seam PRs are merged in `chinrw/asterinas`:

| PR | Final head | Scope |
| --- | --- | --- |
| #2 `syssec-uapi-seams` | `ecc0059ab3945e02d44342ea9b77eed22c735b30` | production UAPI helpers, Kani, Miri, layout, fuzz |
| #3 `syssec-fd-protocol` | `5eb921ef74cbd397118270c2e27b38bac4103ff8` | reserved FD protocol and Loom model |
| #4 `syssec-runtime-harness` | `da81ae952e245b6bb60229457f090575c4fe97f6` | isolated guest case runner and partial-EFAULT case |

`chinrw/asterinas` PR #5 merged as
`fdb34332d9de81d39e5a4cb4c5077446018b27bb`. It adds target-specific static
linking for `partial_efault_json`. Its signed content head is
`d0bddbf56d893221d103a0c3330f379dc59977b9`; the aster-syssec flake pins this
revision so the exporter cannot silently consume the earlier dynamic binary.
The content head is the merge commit's second parent and is reachable from
`chinrw/asterinas/main`.

The previous v0.3 pin was the runtime-harness content commit. The current pin
descends from the merged seam stack and adds only target-specific static linking
for the syssec case. Update `flake.lock`, checkout preflight, validation
evidence, and this snapshot together whenever the pin changes.

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
  |                                           --> verified evidence pack
  |
  +-- agent/specula preparation --> hash-bound handoff script
  |
  +-- runtime request --> strict guest protocol --> Asterinas QEMU adapter
                         |                        --> runtime-result + logs
                         +-- pinned oracle ------> Linux QEMU adapter
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
| Runtime Foundation | `runtime/protocol.py`, `runtime/asterinas.py`, `runtime/linux.py`, `runtime/binary.py`, runtime schemas |
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
or explicitly dispatched nightly CI adds both other layouts and the 1000-run
fuzz target. Nightly primes the locked fuzz dependencies, then runs offline.
It does not stop after the first target failure.

CI separates cache, build, and evidence roots. `syssec evidence pack` verifies
every completed or failed run manifest, copies only registered artifacts, and
enforces 50 MiB and 5,000-file upload limits. SMP regression, LTP, kselftest,
gVisor, and the differential corpus remain explicit external requirements.

## Implemented Runtime Foundation

Merged PR #2 defines six schemas:

- runtime target;
- runtime request;
- guest result;
- runtime result;
- pinned Linux oracle image;
- oracle comparison.

`PartialEfaultComparator` now produces the case-specific comparison artifact.
The flake builds the pinned Linux kernel/config/rootfs/packer bundle without
checking VM binaries into Git.

Merged PR #3 implements the Asterinas adapter. It:

- validates a self-contained request and exact clean source identity;
- requires source and evidence roots to be disjoint;
- creates a local no-hardlink detached clone below the evidence root;
- places Cargo build and temporary paths below evidence;
- sets Cargo offline mode, the source Rust toolchain, and
  `QEMU_HOSTFWD=off`;
- reuses an explicitly supplied or installed cargo-osdk binary;
- writes process output directly to files to avoid pipe backpressure;
- supervises the process group with separate boot and test deadlines;
- extracts and verifies the exact case binary from the boot initramfs before a
  normal result records its binary hash;
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

There is no runtime CLI or runtime profile yet. The Asterinas adapter does not
run the Linux oracle.

The Linux adapter seam is:

```python
LinuxOracleAdapter(
    oracle_metadata_path=...,
    initramfs_packer_executable=...,
).execute(request) -> dict
```

It verifies every declared oracle and binary hash before writing evidence,
then calls the supplied packer with the base rootfs, exact exported binary, and
a run-local output path. Packer identity, QEMU identity, commands, isolated
writable environment, input hashes, and the derived initramfs hash are bound by
`linux-execution.schema.json`.

QEMU runs directly with `-nic none` and the metadata-declared machine, CPU,
acceleration, memory, and SMP. The adapter uses separate boot/test deadlines,
bounds retained output, and terminates the entire process group with
SIGTERM-to-SIGKILL escalation. The seven runtime outcomes use the same
taxonomy as the Asterinas adapter.

The base rootfs and packer must emit `SYSSEC_GUEST_READY` before the exact
binary runs. The flake now exports a Linux 6.18.45 kernel/config/rootfs/packer
bundle. `docs/runtime-baseline-2026-08-26.md` records the first real Linux
result and the matching partial-EFAULT baseline.

`PartialEfaultComparator` compares only the seven declared fields. Mismatches
remain candidates; nonnormal results, missing fields, or unequal binary hashes
remain incomplete. Asterinas normal results now verify the exact binary inside
the boot initramfs before recording `tool.binary_sha256`.

The static-binary exporter seam is:

```python
AsterinasStaticBinaryExporter(...).export(request) -> dict
```

It builds the actual initramfs root derivation in an isolated checkout, copies
the selected executable out of its Nix store output, rejects interpreter or
dynamic-library dependencies, and writes `binary-provenance.json`. The reusable
binary descriptor records the exact binary and case-source hashes, compiler,
linker, and build command. Raw derivation, tool-version, ELF, and build logs are
hashed artifacts.

## Executed evidence

The v0.3 Host Verification baseline was executed on clean aster-syssec
`5f8f38c` and Asterinas `490960ace`. `VALIDATION.md` records the environment
and result bounds. The current pinned Asterinas revision is `d0bddbf...`.

The PR #9 tree passed the locked package gate with 132 tests, the packer shell
contract, Ruff, formatting, Pyright, schema validation, Actionlint, and
ShellCheck. PR #9, its main push run, and the next scheduled nightly run passed
both remote CI jobs.

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

The static-binary exporter ran against clean Asterinas
`d0bddbf56d893221d103a0c3330f379dc59977b9`. The Nix store binary and exported
copy were byte-identical at SHA-256
`696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089`.
The case source SHA-256 was
`374f9297db7164ecbc7c8bb2e0f3e5b37478ddd8b16aba1d5c8309619eeeebda`.
Provenance resolved GCC 14.2.1 and GNU ld 2.44 from the Nix derivation. ELF
evidence contained no interpreter or dynamic-library dependency. Export alone
proves provenance only; the later baseline then verified the same binary in
both VMs and produced the matching comparison recorded in
`docs/runtime-baseline-2026-08-26.md`.

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
nix develop .#default --command env PYTHONPATH=src python3 -m unittest \
  tests.test_runtime_protocol \
  tests.test_runtime_schemas \
  tests.test_runtime_asterinas \
  tests.test_runtime_binary \
  tests.test_runtime_linux
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
| change CI evidence packing | `evidence.py`, `evidence-pack.schema.json`, workflow tests | only verified manifest entries are copied and byte/file budgets fail closed |
| change guest parsing | `runtime/protocol.py`, parser tests, guest schema | every stable error code and size/encoding boundary remains covered |
| change QEMU supervision | `runtime/asterinas.py`, `runtime/linux.py`, adapter tests, runtime-result schema | every outcome is distinguishable through `execute()` and no child process survives |
| change binary export | `runtime/binary.py`, binary schemas, Asterinas initramfs build path | exported bytes equal the Nix output; provenance binds source, toolchain, command, and static ELF evidence |
| change Linux oracle | `runtime/linux.py`, Linux execution schema, adapter tests | every input hash is rechecked, derived state stays below evidence, and no QEMU child survives |
| add comparator | oracle comparison schema, one runtime case contract | every compared field has an explicit relation; mismatch remains candidate |
| extend Specula | `specula.py`, handoff schema, Track readiness | phase artifacts are hash-bound and imported counterexamples remain candidates |

## Next work

1. Add `core`, `model`, and `lab` safety classes.
2. Register runtime targets and expose execution through an explicit CLI/profile.
3. Reproduce the runtime baseline in CI and retain a verified evidence pack.
4. Extend low-risk ABI helpers and targets: message headers, control-message
   alignment/parser progress, timespec ranges, sigset size, and mmap arithmetic.
5. Add phase-specific Specula execution, hash-bound gates, and candidate-only
   result import in the model lane.
6. Add fault, pause, sequence-fuzz, confirmation, and finding-promotion work
   only in the authorization-gated lab.
