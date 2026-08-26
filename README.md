# aster-syssec

`aster-syssec` is an evidence-first syscall security reviewer for Asterinas.
It reads an Asterinas checkout without modifying it and provides one CLI seam
for inventory, deterministic candidate review, host verification engines,
Asterinas's own agent reviewer, and gated Specula preparation.

Agents continuing Host Verification, Runtime Foundation, syscall analysis, or
Specula integration should start with the
[current agent handoff](docs/agent-handoff.md). It separates merged, open-PR,
executed, schema-only, and planned work.

Version 0.3 implements:

- three-architecture syscall dispatch inventory;
- handler signature, SCML, regression-source, and track reconciliation;
- one Track router shared by inventory, source selection, and candidate review;
- structural drift checks and baseline comparisons;
- eight syscall security tracks and twelve numbered properties;
- nine static candidate rules over syscall handlers and same-file callees;
- atomically updated run manifests with schema-validated, hashed artifacts;
- read-only adapters for Asterinas `aster-code-review` and Specula;
- preflight-checked handoffs with exact source identities;
- history-preserving exact-HEAD export for linked worktrees;
- pinned GitHub Actions validation against the locked Asterinas source;
- schema-validated verification targets and checkout preflight;
- isolated Kani, Miri, cross-target layout, cargo-fuzz, and Loom adapters;
- normalized engine plans, commands, environments, results, and raw logs;
- bounded CI profile orchestration with per-command and per-target policy;
- strict runtime evidence schemas and marker-delimited guest result parsing;
- isolated Asterinas QEMU execution with normalized runtime results;
- exact initramfs static-binary export with Nix, compiler, and linker provenance;
- verified evidence packing with explicit byte and file budgets;
- manually selectable PR and nightly CI profiles with per-target summaries.

The bundled vertical slice contains five Kani proofs, one Miri test, three
bare-metal layout targets, one cargo-fuzz target, and one Loom model. These
targets require their matching production helper packages in the Asterinas
checkout; `targets check` fails before execution when the package, symbol,
harness, test, or fuzz target is absent.

Version 0.3 does not implement differential VM execution, fault injection,
kernel sequence fuzzing, Specula phase gates, or finding promotion. Engine
results remain candidates and cannot become confirmed findings through the
current CLI.

## Install

Python 3.11 or newer is sufficient. Installing the project supplies its
`jsonschema` and `referencing` runtime dependencies.

The preferred development path is the locked Nix flake:

```sh
nix develop                 # reviewer development
nix develop .#formal        # Rust/Miri/Kani installer/fuzz/Specula prerequisites
nix develop .#kernel-fuzz   # formal shell plus Go/QEMU/syzkaller
```

The default flake input reads the Rust channel, components, and targets from
Asterinas revision `d0bddbf56d893221d103a0c3330f379dc59977b9`. Override it
when reviewing another checkout:

```sh
nix develop \
  --override-input asterinas-src path:/absolute/path/to/asterinas \
  .#formal
```

Kani uses its official two-stage installation. The installer is built and
hash-pinned by Nix; run this once to download the matching release bundle into
the isolated cache configured by the shell:

```sh
nix develop .#formal
syssec-kani-setup
kani tests/fixtures/kani_smoke.rs
```

See [Nix environments](docs/nix-environment.md) for exact shell contents,
update procedures, and host capabilities that remain external.

Without Nix:

```sh
uv tool install --editable .
syssec --help
```

Without installation:

```sh
PYTHONPATH=src python3 -m aster_syssec --help
```

## Quick start

Set explicit source and evidence roots. The tool never writes under the
Asterinas checkout.

```sh
ASTERINAS_REPO=/path/to/asterinas
SYSSEC_WORK_ROOT=/tmp/aster-syssec

syssec doctor \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT"

syssec config-check \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT"

syssec inventory \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --check

syssec review \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --track socket-cmsg-iovec

syssec targets list
syssec targets check \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT"
```

The checkout and work root must not contain each other. Every
evidence-producing command creates `run-manifest.json` before other outputs,
then atomically transitions it to `completed` or `failed`. A run is stored
under:

```text
<work-root>/runs/<revision>/<run-id>/
├── run-manifest.json
├── catalog/
├── review/
├── agent-review/
└── specula/
```

Completed manifest output entries record the artifact path, SHA-256, size,
media type, schema identity, schema hash, and integrity status. The manifest
also records the reviewer Git/content identity, rule hash, schema-set hash, and
`flake.lock` hash. `report` verifies these records before reading artifacts and
counts repeated candidate IDs once while retaining an occurrence count.

## Host verification

Inspect engine availability, validate a target against production source, then
run it:

```sh
syssec engine doctor --engine kani

syssec targets check \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT"

syssec run-target \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --target iovec-entry-address-no-wrap
```

`run-target` fixes all writable build and temporary paths below the run or
work root. Kani concrete playback is printed into evidence and never applied
in place. The layout adapter cross-compiles the production crate and reads a
dedicated object section; it does not infer bare-metal layout from the host.
The fuzz adapter uses a run-local shadow project and verifies that the source
lock file did not change. Loom bounds are part of both the target and result.

Each run registers:

```text
engine/
├── plan.json
├── command.json
├── environment.json
├── stdout.log
├── stderr.log
└── result.json
```

Outcomes use one vocabulary: `pass`, `counterexample`, `mismatch`,
`incomplete`, `unsupported`, `timeout`, `crash`, `hang`, `compile-error`, and
`tool-error`. Incomplete unwind, unsupported Miri operations, and tool failures
are never normalized to `pass`.

Profiles execute implemented reviewer commands and declared verification
targets through the same run lifecycle:

```sh
syssec run \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --profile pr \
  --changed-from origin/main
```

`external_required` entries remain explicit gaps in `profile/result.json`; the
orchestrator does not report them as executed.

## Inventory

`inventory` parses:

- `kernel/core/src/syscall/arch/x86.rs`;
- the generic RISC-V/LoongArch table in `arch/generic.rs` plus arch additions;
- `sys_*` handler signatures;
- SCML call declarations;
- identifier references in Asterinas regression sources;
- bundled track and property configuration.

Handler effects are derived from each function body and its same-file direct
callees. Operations elsewhere in the same Rust file are not attributed to the
handler. `TrackRouter` is the single owner of syscall, source-path, and
candidate Track precedence.

Outputs:

```text
catalog/syscalls.json
catalog/drift.json
catalog/syscall-matrix.md
```

`--check` fails on structural errors. Existing missing SCML or regression
references remain warnings so historical debt does not make the reviewer
unusable. `--strict-coverage` also fails on those warnings.

For PR CI, compare with a catalog generated from the base revision:

```sh
syssec inventory \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --check \
  --baseline base-syscalls.json
```

Baseline comparison fails when:

- a new syscall lacks SCML or a regression reference;
- a handler, architecture number, or argument count changes;
- a baseline syscall disappears;
- baseline SCML or regression evidence is lost.

Regression evidence is an identifier-reference heuristic. It means a test
source mentions the syscall; it does not mean the test was executed or covers a
security property.

## Static review

Review one track, explicit files, or a Git change:

```sh
syssec review --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --track fd-object-lifetime

syssec review --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --path kernel/core/src/syscall/recvmsg.rs

syssec review --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --changed-from origin/main
```

The backend scans syscall handlers and same-file functions reached by direct
calls. It does not resolve Rust methods or cross-file call graphs. The report
separates selected files, files containing scanned code, and functions scanned.
MIR-backed reachability is a later engine.

Use `--scope selected` for an exhaustive source-path pass. It scans every
function in the selected files; a match then proves only that the code lies in
the configured track paths, not that a syscall can reach it.

Use repeatable `--rule` options to isolate one mechanism:

```sh
syssec review --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --track socket-cmsg-iovec \
  --scope selected \
  --rule COPYOUT-AFTER-SIDE-EFFECT \
  --rule FLAGS-TRUNCATE-UNKNOWN
```

Rules are documented in [static-rules.md](docs/static-rules.md). Every match is
written with `status = "candidate"`, `security_impact = null`, and a required
confirmation step. `--fail-on-candidates` is an explicit CI policy; it does not
promote candidates to findings.

## Asterinas agent review

The checkout's own `aster-code-review` skill remains the authority for general
persona-keyed agent review. `aster-syssec` records its hashes and prepares its
headless launcher without starting an agent:

```sh
syssec agent-review \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --path kernel/core/src/syscall/recvmsg.rs \
  --agent-profile codex \
  --per-persona-context=yes
```

The run contains `agent-review/handoff.json` and `command.sh`. Diff mode
resolves `--base <ref>` to an immutable merge-base commit. The script runs
`syssec verify-handoff` before the reviewer and refuses changed source, skill,
launcher, profile, or target inputs.

## Specula handoff

`model` permits only dry-run and analysis in this version. It never starts
Specula. It hashes the agent config and guidance, fixes a unique run ID, and
emits the exact command.

```sh
syssec model \
  --asterinas "$ASTERINAS_REPO" \
  --work-root "$SYSSEC_WORK_ROOT" \
  --specula-profile /path/to/specula-profile \
  --specula-repo /path/to/specula \
  --track fd-object-lifetime \
  --stage dry-run \
  --export-linked
```

`--export-linked` is required when `.git` is a linked-worktree file. It creates
an independent checkout from a Git bundle containing exact HEAD and its
ancestors. The export has its own `.git` directory, no object alternates, a
clean detached HEAD, and enough history for local archaeology. It refuses the
export when tracked working-tree changes would be omitted. Untracked files are
recorded as excluded inputs.

After analysis, inspect `modeling-brief.md`, `analysis-report.md`, and
`review-analysis.md`. Spec generation remains blocked until a human accepts one
shared state machine and one Linux-visible contract.

The files under the supplied `--specula-profile` path are read in place. The
prepared agent config and guidance are not edited or copied back.

Both handoff scripts verify the reviewer, checkout revisions and dirty hashes,
and hashed input files before execution. `verify-handoff` is read-only and does
not start either external tool. The script pins this check to the reviewer
source or installed entry point used during preparation; it does not resolve a
possibly different `syssec` from PATH.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | Command completed and its selected policy passed |
| `1` | Completed evidence reports drift/candidates/blockers selected by CLI policy |
| `2` | Invalid input, missing checkout data, or adapter preparation error |

A status of `1` still leaves a completed run manifest and evidence. An
unexpected exception leaves the manifest marked `failed`.

## Contracts

- [Current agent handoff](docs/agent-handoff.md)
- [Reviewer contract](docs/reviewer-contract.md)
- [Threat model](docs/threat-model.md)
- [Static rules](docs/static-rules.md)
- [Live validation](VALIDATION.md)
- [Catalog schema](schemas/syscall-catalog.schema.json)
- [Finding schema](schemas/finding.schema.json)
- [Run manifest schema](schemas/run-manifest.schema.json)
- [Specula handoff schema](schemas/specula-handoff.schema.json)
- [Asterinas review handoff schema](schemas/agent-review-handoff.schema.json)
- [Trace event schema](schemas/trace-event.schema.json)
