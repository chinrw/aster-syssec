# Validation

## Current static-binary candidate

The 2026-08-26 candidate pins Asterinas
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
interpreter and no dynamic-library dependencies.

This validates binary export and provenance only. It does not supply Linux VM
execution or differential comparison.

The candidate passed:

```text
nix flake check: 21 checks passed
unit tests: 95 passed
focused Runtime Foundation tests: 40 passed
Ruff lint and format: passed
Pyright: passed
JSON Schema metaschema validation: passed
Actionlint: passed
ShellCheck: passed
config-check: 0 issues
inventory --check: 250 syscalls, 0 errors
targets check: 11 targets, 0 issues
```

## Current CI and nightly baseline

aster-syssec PR #6 merged as
`b26364a64b9ee9009e4765981eb3aacefc9d40c5`. Its PR checks passed against
head `51ab61366c43f060193d47452e7ef48e09871189`. Main push run `32936798988`
then passed both `validate` and `host-verification` on the merge commit.

Manual workflow run `32930891820` selected the `nightly` profile and executed
all 11 targets against pinned Asterinas
`d0bddbf56d893221d103a0c3330f379dc59977b9`. Every expected outcome was met;
`failed_targets` was empty.

The run's verified evidence pack contained 87 files and 1,173,048
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

These fixtures do not supply a pinned Linux kernel/rootfs bundle and do not
establish a real Linux runtime result or differential baseline.

The final adapter tree passed the locked flake gate with 123 tests, Ruff lint
and format, Pyright, JSON Schema validation, Actionlint, and ShellCheck.

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
