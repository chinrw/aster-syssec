# Validation

Observed on 2026-08-23 against:

- the flake-locked Asterinas source at
  `604948581512d83734377974d4c34adb4530f2d7`;
- reviewer version `0.2.0`, developed from
  `c7c9511194b11bea7d9965f7851b59dd57b434bd` with the changes in this
  working tree recorded by the manifest dirty hash;
- Rust `nightly-2026-07-21`;
- Specula profile config SHA-256
  `295387706ec59d368272c771e6a9404f2e246321d64c141d6fc11a395c95ac42`.

## Automated tests

```text
PYTHONPATH=src python3 -m unittest discover -v
37 tests passed
```

The tests cover:

- disjoint source/evidence roots in both containment directions;
- rejection of Git revision inheritance from a source directory's parent;
- function-local inventory effects and same-file helper propagation;
- Rust comments, strings, character literals, lifetimes, and `pub(super)`
  parameter parsing;
- one Track-routing contract for catalog, selection, and candidates;
- strict engine, source-root, guidance, syscall, and Specula config checks;
- schema validation, artifact hashes, source stability, terminal run states,
  tamper detection, and candidate deduplication;
- exact merge-base agent handoffs and changed-input rejection;
- unique Specula run IDs and history-preserving linked-worktree export.

The evidence-integrity tests start from controls that reproduced each reported
failure: overlapping roots created source-side output, handler effects leaked
between functions, invalid Track configuration was accepted, artifacts could
change after registration, and handoffs followed mutable inputs. Each control
now fails closed while the corresponding unchanged-input path completes.

## Pinned Asterinas integration

```text
250 catalog entries
x86_64: 245
riscv64: 208
loongarch64: 208
structural errors: 0
coverage warnings: 61
inventory --check exit: 0
config-check issues: 0
```

The 61 warnings are 59 missing regression-source references and 2 missing SCML
declarations. They are not reported as security findings.

The generated catalog distinguishes handlers sharing `epoll.rs`: create and
control handlers have no copy-out operation, wait handlers have `write_val`,
and `epoll_pwait2` has both `read_val` and `write_val`. This is the regression
control for the former whole-file effect pollution.

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

The explicit `--scope selected` pass scanned all 134 files and 825 functions,
producing 155 track-scoped candidates. It does not claim those functions are
syscall reachable; `--rule` can narrow that exhaustive pass by mechanism.

`abi-integer-layout`:

```text
selected files: 182
files with scanned code: 177
functions scanned: 420
candidates: 238
confirmed findings: 0
```

The central dispatcher's repeated `as _` macro pattern is represented by one
systemic candidate rather than one candidate per argument expansion.

The previous parser counted 426 functions. The six removed entries were trait
method declarations ending in `;` that the old brace search attached to later
implementation bodies. The reachable symbol set and all 238 ABI candidates
were retained.

## Adapter validation

The linked-worktree export was exercised through a clean temporary clone of
the Asterinas history. It completed without editing the authoritative checkout:

```text
kind: git-bundle-clone
history scope: ancestors-of-exact-head
independent .git directory: yes
object alternates: none
detached exact HEAD: yes
preflight after preparation: verified
```

The exported checkout is clean and retains local history for archaeology. The
generated Specula command contains `--dry-run`; Specula was not executed.

The generated Asterinas agent-review target passed the checkout's deterministic
`resolve_target.sh --meta` parser in files mode. No review agent was started.

Pinned integration evidence is under `/tmp/aster-syssec-final-v02.6mcs0u` on the
validation host. A final `report` verified every registered artifact and
reported no invalid runs. These temporary files are not source-controlled.

## Nix flake

Locked inputs:

```text
nixpkgs:       2c423e03bbafcff28bfadc6781a4a8257f205cb5
rust-overlay:  f60c1b57ff805a46b5175c76fc981fb4f81efbcc
asterinas-src: 604948581512d83734377974d4c34adb4530f2d7
syzkaller-src: 1e72964b0111319984575e60f266d1fa0a98abb5
```

`nix flake check path:. --print-build-logs` passes. The package check runs the
37 Python tests, Ruff lint and formatting, Pyright, JSON metaschema validation,
Actionlint, and ShellCheck in the Nix sandbox. The package imports successfully
and `nix run path:. -- --version` reports `aster-syssec 0.2.0`.

An installed-package run recorded the reviewer content, rule set, schema set,
and `flake.lock` SHA-256 values plus the output size, schema hash, and artifact
hash. The path-input build has no Git metadata, so its exact content hash is
the package identity; a clean Git flake build additionally records `self.rev`.

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
