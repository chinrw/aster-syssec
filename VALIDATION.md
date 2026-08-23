# Validation

Observed on 2026-08-23 against:

- Asterinas `604948581512d83734377974d4c34adb4530f2d7`;
- branch `main`, tracking official `upstream/main`;
- only pre-existing dirt: `?? asterinas-onboarding.html`;
- Rust `nightly-2026-07-21`;
- Specula profile config SHA-256
  `295387706ec59d368272c771e6a9404f2e246321d64c141d6fc11a395c95ac42`.

## Automated tests

```text
PYTHONPATH=src python3 -m unittest discover -v
12 tests passed
```

The tests cover dispatch merging, structural/coverage drift separation,
baseline regression policy, comment/string masking, handler versus selected
scope, rule filtering, candidate-only semantics, run-manifest ordering,
linked-worktree blocking, and non-executing agent-review handoffs.

## Live inventory

```text
250 catalog entries
x86_64: 245
riscv64: 208
loongarch64: 208
structural errors: 0
coverage warnings: 61
inventory --check exit: 0
```

The 61 warnings are 59 missing regression-source references and 2 missing SCML
declarations. They are not reported as security findings.

## Live static review

`socket-cmsg-iovec`:

```text
selected files: 134
files with scanned handler/local-callee code: 14
functions scanned: 18
candidates after same-file reachability: 28
confirmed findings: 0
```

The results include the `recvmsg` message-consumption/copy-out ordering path,
`sendmmsg` address arithmetic and post-send copy-out, flag truncation, typed
copy-out, and low-confidence guard-lifetime questions. They remain candidates.

The explicit `--scope selected` pass scanned all 134 files and 851 functions,
producing 156 track-scoped candidates. It does not claim those functions are
syscall reachable; `--rule` can narrow that exhaustive pass by mechanism.

`abi-integer-layout`:

```text
selected files: 182
files with scanned code: 177
functions scanned: 426
candidates: 238
confirmed findings: 0
```

The central dispatcher's repeated `as _` macro pattern is represented by one
systemic candidate rather than one candidate per argument expansion.

## Adapter validation

The linked-worktree export completed without editing the authoritative checkout:

```text
kind: git-archive
revision: 604948581512d83734377974d4c34adb4530f2d7
archive SHA-256: 8b85718d9c7f6cdd35c50016382fe1f2cffd612c9fabdb24eacfde4e2827f479
```

The exported `kernel/core/src/syscall/recvmsg.rs` is byte-identical to HEAD.
The generated Specula command contains `--dry-run`; it was not executed.

The generated Asterinas agent-review target passed the checkout's deterministic
`resolve_target.sh --meta` parser in files mode. No review agent was started.

Raw validation runs are under `/tmp/aster-syssec-validation` on the validation
host and are not source-controlled artifacts.

## Nix flake

Locked inputs:

```text
nixpkgs:       2c423e03bbafcff28bfadc6781a4a8257f205cb5
rust-overlay:  f60c1b57ff805a46b5175c76fc981fb4f81efbcc
asterinas-src: 604948581512d83734377974d4c34adb4530f2d7
syzkaller-src: 1e72964b0111319984575e60f266d1fa0a98abb5
```

`nix flake check` passes. The package check runs the Python tests, Pyright, and
JSON metaschema validation in the Nix sandbox.

The toolchain contract built and checked:

```text
rustc 1.99.0-nightly (87e5904f5 2026-07-20)
miri 0.1.0 (87e5904f5e 2026-07-20)
x86_64-unknown-none
riscv64imac-unknown-none-elf
loongarch64-unknown-none-softfloat
```

Formal-shell smoke results:

```text
cargo-fuzz 0.13.2
OpenJDK 21.0.12
Maven 3.9.16
LLVM/Clang 21.1.8
Kani installer 0.67.0
```

The Kani bundle was installed into an isolated `/tmp` cache and verified
`tests/fixtures/kani_smoke.rs` with CBMC 6.8.0:

```text
VERIFICATION:- SUCCESSFUL
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
```

The custom syzkaller derivation builds the source and Go module closure pinned
by the lock. Manager, executor, and execprog are executable; the manager embeds
revision `1e72964b0111319984575e60f266d1fa0a98abb5`. The kernel-fuzz shell also
reports Go 1.26.5 and QEMU 11.1.0.

During the first Kani setup validation, before the final `RUSTUP_HOME`
isolation was added, the installer placed `nightly-2025-11-21` in the user's
default rustup home. It was not removed. The final shell supplies Nix rustup and
sets Kani's `RUSTUP_HOME` below the aster-syssec cache; a fresh-cache rerun
confirmed the corrected location.
