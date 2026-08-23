# Nix environments

`flake.lock` is the toolchain lock for host-side reviewer dependencies. The
flake currently supports `x86_64-linux`, matching Kani's supported Linux host
and the Asterinas QEMU/KVM workflow.

## Locked inputs

| Input | Purpose |
| --- | --- |
| `nixpkgs` | Python, uv, JDK, Maven, LLVM, QEMU, Go, and host tools |
| `rust-overlay` | Asterinas nightly components and bare-metal targets |
| `asterinas-src` | Authoritative `rust-toolchain.toml` for the formal shell |
| `syzkaller-src` | Separately pinned syzkaller source revision |

The flake parses `rust-toolchain.toml` from `asterinas-src` and adds Miri,
Cargo, Clippy, and rustfmt. It preserves the checkout's `rust-src`,
`rustc-dev`, `llvm-tools-preview`, and target list.

## Shells

### `default`

```sh
nix develop
```

Provides:

- packaged `syssec` and source-tree `syssec-dev`;
- Python, uv, Git, jq, ripgrep, GNU Make;
- Pyright, Ruff, ShellCheck, nixfmt, and JSON Schema validation.

`syssec` is the immutable Nix package. `syssec-dev` loads
`$SYSSEC_SOURCE_ROOT/src`, defaulting to the current directory.

### `formal`

```sh
nix develop .#formal
```

Adds:

- the Asterinas nightly from the locked source input;
- Miri, `rustc-dev`, `rust-src`, LLVM tools, and all three Asterinas targets;
- cargo-fuzz;
- Kani 0.67.0 installer and `syssec-kani-setup`;
- JDK 21 and Maven for Specula/TLA+;
- Clang, LLD, LLVM, CMake, and pkg-config.

Kani's official installer has a second setup step because its release bundle
contains an architecture-specific compiler, CBMC, libraries, and its own Rust
toolchain. The flake isolates both locations:

```text
$XDG_CACHE_HOME/aster-syssec/kani
$XDG_CACHE_HOME/aster-syssec/kani-rustup
```

If `XDG_CACHE_HOME` is unset, the base is `$HOME/.cache`. Override
`KANI_HOME` or `SYSSEC_KANI_RUSTUP_HOME` when required.

### `kernel-fuzz`

```sh
nix develop .#kernel-fuzz
```

Adds:

- a separately locked syzkaller manager, executor, and execprog;
- Go, QEMU/KVM, Docker client, GDB, strace, and socat.

The syzkaller package is built from `syzkaller-src`, not the older syzkaller
snapshot in nixpkgs. Its Go module closure is fixed by `vendorHash`, and the
source revision is embedded into the binaries and exported as
`SYZKALLER_REVISION`.

This supplies tooling for an Asterinas port. It does not add an Asterinas OS
backend, per-execution coverage, or a manager configuration.

## Commands

```sh
nix flake check
nix build .#syssec
nix build .#kani-installer
nix build .#syzkaller
nix run . -- --help
nix fmt
```

Update locked upstream inputs explicitly:

```sh
nix flake update nixpkgs rust-overlay syzkaller-src
```

The Asterinas input URL contains the reviewed source revision. Change that URL
only with an intentional Asterinas/toolchain update, then run `nix flake lock`.
The `toolchain-contract` check requires Miri and every target named by that
revision.

Kani's version and crate hashes are maintained in `nix/versions.nix` and
`flake.nix`. Update all three together: version, crate source hash, and Cargo
dependency hash. Then run `syssec-kani-setup` in a fresh cache and execute the
smoke proof.

## External state

The flake does not create or mutate:

- the authoritative Asterinas or Specula checkout;
- a Docker daemon;
- `/dev/kvm` or other device permissions;
- Specula agent credentials or network policy;
- Kani's release bundle until `syssec-kani-setup` is explicitly run.

Loom is a crate dependency of a future harness, not a standalone executable.
`sctrace` remains checkout-specific and should be built from the selected
Asterinas source.
