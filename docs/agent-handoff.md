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
gh pr view 9 --repo chinrw/asterinas
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
| merged implementation baseline | `70b3103` | PR #1-#21: v0.4 plus control-message, message-header, and timespec Host Verification |
| signed tag `v0.4.0` | `30b5a4d` | v0.4 Host-to-Runtime verification record |
| signed tag `v0.3.0` | `421c9d9` | v0.3 Host Verification record |

PR #21 is the latest merged implementation PR. aster-syssec PR #9 head
`c47ac40e3ae27c4575a539bc6a3a2bbed41518c6` passed `validate` and
`host-verification`; merge commit `f2f431c47430b308bfec406a54b745fdb89d712b`
is the first real differential baseline. Later merged heads are:

| PR | Head | Scope |
| --- | --- | --- |
| #10 | `a796057` | refresh the Runtime handoff |
| #11 | `fdeb807` | fail-closed core/model/lab target boundaries |
| #12 | `5e64af9` | explicit four-stage Runtime target pipeline |
| #13 | `51f4b96` | pinned manual/weekly Runtime workflow and networkless build wrapper |
| #14 | `bf4cdd4` | fail-closed offline Nix boundary for Runtime and evidence execution |
| #15 | `9ab6b17` | v0.4.0 versions, release record, and version consistency gate |
| #16 | `df15318` | signed v0.4.0 tag receipt and refreshed release handoff |
| #17 | `20336ee` | 16-target control-message Host Verification and workflow pin lock |
| #18 | `cfa7583` | control-message Host and Runtime evidence receipt |
| #19 | `95558d5` | 19-target message-header Host Verification and workflow pin lock |
| #20 | `7c17d3b` | message-header Host and Runtime evidence receipt |
| #21 | `c0e9311` | 22-target timespec Host Verification and workflow pin lock |

Merge commit `70b3103dba44f00e74fb3bdf5baf153d03e56055` is the current public
implementation baseline.

Main push run `32953069193` completed successfully on historical merge commit
`f2f431c`. Both `validate` and the PR-profile `host-verification` job passed.

Scheduled run `33004803564` executed the historical 11-target `nightly`
profile on `f2f431c` and passed. PR #17 run `33054763312` passed `validate` and
the 12-target PR-profile `host-verification` job.

Manual main run `33057517578` executed the then-current 16-target nightly
profile and passed both jobs. Its downloaded Host evidence pack contained 117
files and 1,273,350 bytes; every listed file hash and size matched. The
independently recomputed content SHA-256 is
`04204dcfa82dad651b58e9caa9ba9c42d0698ca05e097112d000bcc556ad9759`.
GitHub artifact `9640644616` is 172,748 compressed bytes with archive digest
`sha256:d68ef3dff462164bb2922c62de986ef9cf2c9abf86f6df73f6089286258c0f26`.
The pre-fix artifact was 1,136,398,829 bytes because it included cache and
build trees.

PR #19 run `33062684112` passed `validate` and the 15-target PR profile. Main
push run `33065312608` then passed both jobs on merge commit `c344f832...`.
Manual main run `33066250182` passed the complete 19-target nightly profile.
Its downloaded Host evidence pack contained 135 files and 1,389,410 bytes;
every listed file hash and size matched. The independently recomputed content
SHA-256 is
`f0fd6aefcb1e15cacaa83dc9c5e0cf592fccadabc1d67d63c957ef24387d2260`.
GitHub artifact `9643932986` is 192,236 compressed bytes with archive digest
`sha256:05ab9198fdb1d797ec2a704f6549e451872844d0d723e611d6cc32730acddefc`.

PR #21 run `33073822346` passed `validate` and the 18-target PR profile. Main
push run `33074303888` then passed both jobs on merge commit `70b3103...`.
Manual main run `33075159362` passed the complete 22-target nightly profile.
Its downloaded Host evidence pack contained 153 files and 1,529,521 bytes;
every listed file hash and size matched. The independently recomputed content
SHA-256 is
`46f18e7e9d7228684981bd6b6b02fcda76206341a3d0645219fcfe093b65240c`.
GitHub artifact `9647707230` is 213,052 compressed bytes with archive digest
`sha256:24dca7e8cdbcf0423539c63b71ea6d4b05f370a77521ef783aec1cd4c2ffdb24`.

Both packages and the runtime version are `0.4.0`. Signed annotated tag object
`a14a73475e56192b499c7470a234bf4c2cc415ae` peels to the v0.4 release
baseline. The historical `v0.3.0` tag remains unchanged.

### Pinned Asterinas

`flake.lock` and GitHub Actions pin:

```text
820ec6464809071779f3c386634befcc83da10bc
sha256-UAenN/jXYpPthwCRWN6ePbbUIKMv7V59ZCOPwk0+BqY=
```

The persistent Asterinas seam PRs are merged in `chinrw/asterinas`:

| PR | Final head | Scope |
| --- | --- | --- |
| #2 `syssec-uapi-seams` | `ecc0059ab3945e02d44342ea9b77eed22c735b30` | production UAPI helpers, Kani, Miri, layout, fuzz |
| #3 `syssec-fd-protocol` | `5eb921ef74cbd397118270c2e27b38bac4103ff8` | reserved FD protocol and Loom model |
| #4 `syssec-runtime-harness` | `da81ae952e245b6bb60229457f090575c4fe97f6` | isolated guest case runner and partial-EFAULT case |
| #6 `syssec-cmsg-uapi` | `5e3f8ef5d4b77d5ec276fe9df3c9aa89af8028cb` | checked `cmsghdr` layout/parser seam, Kani, Miri, and fuzz |
| #8 `syssec-msghdr-uapi` | `974e1bad52e6c6bb9a214c62ff0e16b96c2e6af8` | `user_msghdr` layout, signed name length, iovec bound, Kani, and Miri |
| #9 `syssec-timespec-uapi` | `820ec6464809071779f3c386634befcc83da10bc` | 64-bit userspace timespec layout, duration ranges, Kani, and Miri |

`chinrw/asterinas` PR #5 merged as
`fdb34332d9de81d39e5a4cb4c5077446018b27bb`. It adds target-specific static
linking for `partial_efault_json`. Its signed content head is
`d0bddbf56d893221d103a0c3330f379dc59977b9`; it remains the v0.4 Runtime
content revision.
The content head is the merge commit's second parent and is reachable from
`chinrw/asterinas/main`.

`chinrw/asterinas` PR #6 merged as
`74f1a483962c894f4350967b2c1f0e8d35d7f245`. Its signed content head is the
control-message content revision `5e3f8ef5d4b77d5ec276fe9df3c9aa89af8028cb`
and is reachable from `chinrw/asterinas/main`.

`chinrw/asterinas` PR #8 passed all 42 reported checks and merged as
`d94f69ac8aa62c3b44ee1fc161c6419d6c655b74`. Its signed content head is the
message-header content revision `974e1bad52e6c6bb9a214c62ff0e16b96c2e6af8` and is
reachable from `chinrw/asterinas/main`.

`chinrw/asterinas` PR #9 passed all 42 reported checks and merged as
`2b8472c7673a86fa47c7fa92796228ba739d343e`. Its signed content head is the
current aster-syssec pin `820ec6464809071779f3c386634befcc83da10bc` and is
reachable from `chinrw/asterinas/main`.

The current pin descends from the merged runtime stack and adds the control-
and message-header UAPI seams plus the timespec seam. Update `flake.lock`, both
workflow checkouts, checkout preflight, validation evidence, and this snapshot
together whenever the pin changes. Tests bind both workflow refs to the locked
revision.

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
| CI and pinned environments | `flake.nix`, `flake.lock`, `.github/workflows/ci.yml`, `runtime.yml`, `lab.yml` |

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

The registry packages 22 targets:

| Engine | Targets | Current executed baseline |
| --- | ---: | --- |
| Kani | 12 | pass, unwind 8 sufficient |
| Miri | 4 | pass |
| layout | 3 | x86-64, RISC-V 64, LoongArch 64 pass |
| cargo-fuzz | 2 | 1000/1000 runs pass per target |
| Loom | 1 | pass at 1000 branches, 3 preemptions, 10000 permutations |

The targets cover `UserIoVec` validation, truncation, address arithmetic and
layout; control-message alignment, payload, parser progress, and fuzzing;
message-header signed name length and iovec bounds; timespec range and layout;
and FD reservation visibility. Stable v0.3 expected results remain in
`docs/v0.3-host-results.json`; current results are bound by each profile
artifact.

PR and push CI run 12 Kani proofs, four Miri tests, x86-64 layout, and Loom for
18 blocking targets. Scheduled or explicitly dispatched nightly CI adds both
other layouts and both 1000-run fuzz targets. Nightly primes the locked fuzz
dependencies, then runs offline. It does not stop after the first target
failure.

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

The explicit Runtime CLI provides target listing, checkout preflight, and the
`partial-efault-baseline` opt-in profile. It executes export, Asterinas, Linux,
and comparison as separate hash-bound stages. Runtime is not part of ordinary
PR or nightly profiles.

Merged `.github/workflows/runtime.yml` has only manual and weekly triggers. Nix
resolves the pinned oracle, packer, `cargo-osdk`, Asterinas workspace vendor,
and pinned Rust build-std vendor before the Runtime stage. The build container
then runs with `--network=none`, Cargo offline, `QEMU_HOSTFWD=off`, and no host
device mounts. The workflow uploads only a verified 50 MiB/5,000-file evidence
pack.

The first successful `main` run fetched one Nix store path while entering the
formal dev shell, before `syssec` started. Merged PR #14 now materializes both
dev shells during input resolution and passes `--offline` to Nix during Runtime
and evidence steps. Keep that distinction explicit: Nix may fetch hash-pinned
inputs during resolution; the execution boundary must fail rather than fetch.

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
bundle. `docs/runtime-baseline-2026-08-27.md` records the current Linux result
and matching partial-EFAULT baseline; the 2026-08-26 record remains historical.

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
and result bounds. The current pinned Asterinas revision is `820ec646...`.

The post-v0.4 Host extension passed clean local PR and nightly profiles on
Asterinas `820ec646...`. The current registry contains twelve Kani, four Miri,
three layout, two fuzz, and one Loom target. PR #21 run `33073822346` passed
both remote jobs after the Host and Runtime workflow refs were bound to
`flake.lock`. Main push run `33074303888` passed both jobs. Manual main run
`33075159362` then passed the complete 22-target nightly profile and produced
the independently verified evidence pack recorded above. Its profile SHA-256
is `12fa2368e673eef81ce78b9d4bf9a107eb6fd94b5d85b1e0315c8e9cebf9577f`.

Manual Runtime run `33075155261` passed all four stages on merged main and the
same Asterinas pin. Pipeline `RUNTIME-PIPELINE-6CDABEF04FBB6E5C` produced
normal Asterinas and Linux results for the exact `696ed3...7089` static binary.
Comparison `ORACLE-COMPARISON-F4A8F607F68060FB` matched all seven declared
fields and retained `disposition=baseline`. The verified evidence pack retained
32 files and 16,524,703 bytes with content SHA-256
`b2d2504dc68e1912351370dcfc8a626892cd6efa266e007e28dab08979c8ab65`.
Runtime execution and evidence packing used Nix offline and recorded no
downloads or Nix-store copies. Nine primary Runtime artifacts and the run
manifest passed their pinned schema and integrity checks after download.
`docs/runtime-baseline-2026-08-27.md` binds the inputs, stage results,
provenance, comparison, and downloaded artifact hashes.

The PR #9 tree passed the locked package gate with 132 tests, the packer shell
contract, Ruff, formatting, Pyright, schema validation, Actionlint, and
ShellCheck. PR #9, its main push run, and the next scheduled nightly run passed
both remote CI jobs.

The `runtime-ci-schedule` branch locally reproduced the full workflow contract
against pinned Asterinas `d0bddbf...`. Pipeline
`RUNTIME-PIPELINE-53FB20716090B443` passed export, Asterinas, Linux, and compare;
both normal VM results bound binary SHA-256 `696ed3...7089`, and comparison
`ORACLE-COMPARISON-8E777E1A1927BC98` matched all seven fields. Its verified
evidence pack retained 32 files and 16,307,773 bytes. The Asterinas workspace
vendor hash is `sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`; the
pinned nightly build-std vendor hash is
`sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

Manual `main` workflow run `33046453514` passed in 13 minutes 22 seconds.
Remote pipeline `RUNTIME-PIPELINE-1FFB96559AE63CB4`, both normal VM results,
and comparison `ORACLE-COMPARISON-DC078CD0DA73B598` bound the same
`696ed3...7089` binary and matched all seven fields. Artifact `9636131500`
retained 32 files and 16,524,759 bytes. Every downloaded file hash and aggregate
content hash `959ad3a7962068e26d57c5a9892c9b0582b181083abb4fc024ef2cac970dc448`
were independently recomputed.

After PR #14 merged, final `main` workflow run `33048842078` passed with Nix
offline during Runtime and evidence packing. Pipeline
`RUNTIME-PIPELINE-C10BE1B2CD6BAB1E`, Asterinas result
`RUNTIME-RESULT-290D5E36B00AC2CD`, Linux result
`RUNTIME-RESULT-45872A9E02B6B6F6`, and comparison
`ORACLE-COMPARISON-25B3516F3DEB8BEA` all passed. Artifact `9637034442`
retained 32 files and 16,524,483 bytes; every file and aggregate hash
`d48347099ecbc4a1f2928ae3d6e60fa388f08ff928f47fa60dbc42967583b3da`
matched after download. Runtime and evidence logs contained no Nix cache
download; all downloads occurred during input resolution.

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
| core | main `aster-syssec` package | inventory, proofs, schemas, parsers, VM/process infrastructure, comparison evidence |
| model | explicit model entrypoint | state variables, transitions, invariants, bounds, source anchors, candidate traces |
| lab | same repository, separate `aster-syssec-lab` package | authorization validation; future gated VM-only operations |

Verification and Runtime targets carry a schema-validated safety policy. The
main `syssec` execution paths only accept `core`: model targets require the
explicit model entrypoint and Lab targets fail closed. Profiles declare one
safety class and cannot select targets from another class.

The separately packaged `syssec-lab` command validates authorization documents
and reports its fixed VM-only, network-off, manual-only boundary. It does not
yet execute Lab cases. `.github/workflows/lab.yml` is manual-only and verifies
that package boundary; ordinary PR, push, scheduled, and release profiles
cannot invoke it.

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

1. Extend low-risk ABI helpers and targets: sigset size, then mmap/mremap range
   arithmetic. The timespec range/layout seam is complete at the current pin.
2. Add phase-specific Specula execution, hash-bound gates, and candidate-only
   result import in the model lane.
3. Add fault, pause, sequence-fuzz, confirmation, and finding-promotion work
   only in the authorization-gated lab.
