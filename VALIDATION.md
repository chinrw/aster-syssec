# Validation

## Current runtime baseline

The 2026-08-26 baseline pins Asterinas
`d0bddbf56d893221d103a0c3330f379dc59977b9` with NAR hash
`sha256-eUJRAbB3KLNJTWB20lgIE+YeBSbaV9aNq8Q98w9YJaY=`. That revision adds
target-specific static linking for `partial_efault_json` on top of the merged
verification seams.

A real initramfs export produced byte-identical Nix-store and evidence copies
at SHA-256
`696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089`.
The source SHA-256 was
`374f9297db7164ecbc7c8bb2e0f3e5b37478ddd8b16aba1d5c8309619eeeebda`.
The derivation resolved GCC 14.2.1 and GNU ld 2.44. `readelf` reported no
interpreter and no dynamic-library dependencies. The same binary was then
verified and executed in Asterinas and the pinned Linux oracle. The seven-field
partial-EFAULT comparison produced `status=match` and
`disposition=baseline`.

The final PR #9 tree passed:

```text
nix flake check: passed
unit tests: 132 passed
packer shell contract: passed
Ruff lint and format: passed
Pyright: passed
JSON Schema metaschema validation: passed
Actionlint: passed
ShellCheck: passed
```

## Current CI and nightly baseline

aster-syssec PR #9 merged as
`f2f431c47430b308bfec406a54b745fdb89d712b`. Its PR checks passed against
head `c47ac40e3ae27c4575a539bc6a3a2bbed41518c6`. Main push run `32953069193`
then passed both `validate` and `host-verification` on the merge commit.

Scheduled run `33004803564` selected the `nightly` profile on the same merge
commit and passed. The profile executed all 11 packaged targets against pinned
Asterinas `d0bddbf56d893221d103a0c3330f379dc59977b9`.

The earlier manual pack validation contained 87 files and 1,173,048
uncompressed bytes. GitHub stored it as a 142,523-byte artifact. The previous
scheduled run `32880127358` uploaded 1,136,398,829 bytes and 99,903 ZIP entries
because the whole work root included cache and build trees.

The old scheduled run failed before artifact upload. `iovec-host-fuzz` returned
`tool-error` because offline Cargo could not find `libfuzzer-sys` in a fresh
runner cache; fail-fast then skipped Loom. Nightly now primes the locked fuzz
dependencies before offline execution and reports the complete target matrix.

## Linux oracle adapter validation

The Linux adapter was validated through 18 public-seam fixture tests. They
cover:

- the exact exported-binary hash and all oracle input hashes;
- QEMU semantic version and full tool identity;
- a run-local derived initramfs and schema-validated execution provenance;
- `-nic none`, TCG machine parameters, and evidence-root writable paths;
- QEMU start failure, boot timeout, panic, guest hang, test timeout, invalid
  protocol, and normal completion;
- combined output bounds and SIGTERM-to-SIGKILL process-group cleanup;
- packer input mutation, output overflow, and derived-rootfs symlink rejection.

The flake now supplies a Linux 6.18.45 kernel/config/base-rootfs bundle and a
hash-bound initramfs packer. A real TCG run executed the exact exported static
binary and produced `RUNTIME-RESULT-8DC8AF20C2D95236` with `outcome=normal`.

The same binary was verified inside the Asterinas boot initramfs before its
normal result was written. `partial-efault-pipe-read-v1` compared seven fields
and produced `ORACLE-COMPARISON-820CA758EBA9EB43` with `status=match` and
`disposition=baseline`. Exact input, result, and artifact hashes are recorded
in `docs/runtime-baseline-2026-08-26.md`.

The final tree passed the locked flake gate with 132 tests, the packer shell
contract, Ruff lint and format, Pyright, JSON Schema validation, Actionlint,
and ShellCheck.

## Safety and Lab boundary validation

The target safety change makes `core`, `model`, and `lab` explicit and
fail-closed. All 11 packaged Host targets and the partial-EFAULT Runtime target
declare `core`. PR, nightly, and release profiles are core-only; the weekly
profile is model-only. A profile cannot select a target from another class.

The main `syssec` execution path rejects model targets in favor of the explicit
model entrypoint and rejects Lab targets before creating a run. The separate
`aster-syssec-lab` package has a one-way dependency on the core package. Its
initial CLI validates an expiring authorization document and reports a
VM-only, network-off, manual-only boundary with `execution_available=false`.

`.github/workflows/lab.yml` has only a manual trigger and only builds and checks
the boundary package. It does not execute a Lab case. The locked flake gate
passed with 145 tests, the Lab package and boundary contract, Ruff, formatting,
Pyright, JSON Schema validation, Actionlint, and ShellCheck.

## Runtime target pipeline validation

The explicit `partial-efault-baseline` profile was executed on 2026-08-27
against clean Asterinas revision
`d0bddbf56d893221d103a0c3330f379dc59977b9` and pinned oracle
`linux-x86-64-6-18-45`. Runtime target checkout preflight reported one target,
zero issues, and registry hash
`62fb3df191be6b81eca1251a7215f9015ed27108b928abea115fbc9d16b76494`.

Pipeline `RUNTIME-PIPELINE-AAE838C5F22FF91A` retained four schema-bound stages:

| Stage | Result SHA-256 |
| --- | --- |
| export-binary | `94b4a9bb76fd69133a9eb865cb350833275e01c9427983b5700860bd40e071d3` |
| run-asterinas | `6b0d7a5811f46d7d04c19f0c713eb2b61502d98277756b503588d655a2e1ee57` |
| run-linux | `0ec22a0ba7b142a8aa9b16b4dbb7ddbe992905bfabd825bef164e48fdfc9e86b` |
| compare | `386cfed29e6940809273a07b6615159c3cfd571f4e8fa0374f622235907e085b` |

Both VM stages consumed binary SHA-256
`696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089`.
Asterinas produced `RUNTIME-RESULT-DF09262766E6DFF6`; Linux produced
`RUNTIME-RESULT-92FEA0C5BEBF956D`. Comparator
`ORACLE-COMPARISON-FC6D76B2585101B9` matched all seven fields and retained
`disposition=baseline`.

The completed run directory occupied 3.4 GiB because it contained the isolated
Asterinas checkout and build tree. `syssec evidence pack` verified the manifest
and retained only 32 files totaling 16,298,975 bytes. The upload tree remained
below the 50 MiB and 5,000-file limits.

The final tree passed the locked flake gate with 154 tests, the Lab package and
boundary contract, the initramfs packer contract, Ruff, formatting, Pyright,
JSON Schema validation, Actionlint, and ShellCheck.

## v0.3 Host Verification baseline

Observed on 2026-08-24 against clean revisions:

- aster-syssec `5f8f38cfd8a05397e1ac17a777d985102ef81dbc`;
- Asterinas `490960ace3e15bf74146e406ec11a9425755cfba`;
- Rust `nightly-2026-07-21` for Miri, layout, fuzz, and Loom;
- Kani `0.67.0` with CBMC `6.8.0`.

At that baseline, the flake locked `chinrw/asterinas` with NAR hash
`sha256-IjQP49RonXGFv0Bg9KagDJ3ml58F8pePM2p0A0ANpsA=`.

## Package and checkout gates

```sh
nix flake check --no-update-lock-file --print-build-logs
```

Result:

```text
55 unit tests passed
Ruff lint and format passed
Pyright passed
JSON Schema metaschema validation passed
Actionlint passed
ShellCheck passed
all checks passed
```

`scripts/ci-integration.sh` ran `config-check`, `inventory --check`, and
`targets check` against the flake-locked source. Target preflight reported:

```text
targets: 11
issues: 0
status: ok
```

## Host verification profile

The clean nightly run is stored at:

```text
/tmp/asterinas-syssec-v03.cIgpRt/work/runs/490960ace3e1/20260824T075618Z-run-profile-417f4e9c
```

The run manifest records clean source and reviewer dirty hashes, reviewer
commit `5f8f38c...`, Asterinas commit `490960ace...`, and verified integrity for
`profile/result.json`.

| Engine | Targets | Result |
| --- | ---: | --- |
| Kani | 5 | pass |
| Miri | 1 | pass |
| bare-metal layout | 3 | pass |
| cargo-fuzz | 1 | pass, 1000/1000 runs |
| Loom | 1 | pass |

All Kani proofs used unwind 8 and reported sufficient unwind. Layout matched
the expected 16-byte, 8-byte-aligned `UserIoVec` on x86-64, RISC-V 64, and
LoongArch 64. Loom used 1000 max branches, 3 max preemptions, and 10000 max
permutations.

Stable expected outcomes are recorded in
`docs/v0.3-host-results.json`. Run-local result IDs are excluded because the
fuzz adapter intentionally places a shadow manifest below each run root.

## Asterinas integration

The original mixed commits were split and replayed onto upstream Asterinas
`2bcd1ae127794d2d5c49019cd8ace1ff4dbf8e98`:

| Branch | Commit | Scope |
| --- | --- | --- |
| `syssec-uapi-seams` | `bb2c0f5e236b7b38478b4961565350716bcfe5d4` | UAPI helper, production iovec integration, Kani, Miri, layout, fuzz |
| `syssec-fd-protocol` | `13cf3c95ae0be904ef1e1729e9e379b66f0964c7` | reserved FD protocol, FileTable/pipe2/pidfd integration, Loom |
| `syssec-runtime-harness` | `490960ace3e15bf74146e406ec11a9425755cfba` | isolated initramfs runner, hostfwd disable, partial-EFAULT case |
| `syssec-static-runtime-binary` | `d0bddbf56d893221d103a0c3330f379dc59977b9` | target-specific static link for the partial-EFAULT case |

All four content heads exist on `chinrw/asterinas`. PR #5 merged as
`fdb34332d9de81d39e5a4cb4c5077446018b27bb`, with `d0bddbf...` as its second
parent. Each content commit has a
`Signed-off-by` trailer. The temporary clone could not reach the SSH signing
agent, so the original three seam commits are unsigned. The PR #5 content head
is signed.

Validation on the final stack included:

```text
aster-uapi host tests: 5 passed
aster-fd-protocol host tests: 2 passed
workspace Rust format and clippy: passed
non-default workspace members: passed
partial_efault_json clang-format: passed
run_syssec_case.sh ShellCheck: passed
changed-file typos check: passed
```

The development image lacks `nixfmt`, so its monolithic `make check` exited
127 after the Rust checks. Host `nixfmt --check distro` also reports formatting
differences already present at upstream base `2bcd1ae...`; no Nix file changed
in this stack. This is not recorded as a full `make check` pass.

## TCG runtime smoke

The final runtime stack was built and booted with:

```sh
make run_kernel \
  AUTO_TEST=syssec \
  SYSSEC_CASE=io/file_io/partial_efault_json \
  TARGET_ARCH=x86_64 \
  ENABLE_KVM=0 \
  QEMU_HOSTFWD=off
```

The guest emitted exactly one marker-delimited object, and the Makefile marker
postcondition exited zero:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

This is a contract-baseline smoke result. It is not differential evidence and
is not a finding.

## CI profiles

Pull requests and pushes run five Kani targets, Miri, x86-64 layout, and the
bounded Loom model. Scheduled and manually dispatched nightly jobs run all 11
targets, adding both other layouts and the 1000-run fuzz campaign. Nightly uses
`fail_fast = false`.

Host CI keeps cache and build trees outside the evidence root. It uploads only
manifest-registered, hash-verified artifacts through `syssec evidence pack`.
The pack fails above 50 MiB or 5,000 files and still accepts a failed run after
revalidating its recorded artifacts.

SMP regression, LTP, kselftest, gVisor, and the differential corpus remain
explicit external requirements.
