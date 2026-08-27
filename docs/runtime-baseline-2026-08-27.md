# Runtime baseline 2026-08-27

This record supersedes the current-runtime status in the v0.4 handoff without
rewriting the historical 2026-08-26 baseline.

## Immutable inputs

| Input | Identity |
| --- | --- |
| aster-syssec | `c344f8323db7241ea1a3f412a9ee148426b9cc8f` |
| Asterinas content | `974e1bad52e6c6bb9a214c62ff0e16b96c2e6af8` |
| Asterinas merge | `d94f69ac8aa62c3b44ee1fc161c6419d6c655b74` |
| Asterinas NAR | `sha256-Xvq6W1zaDTqpMVh0DltoM6pYNiUcDkyY5bswbH0Mqs8=` |
| Linux | `bf3be28f6721e24961992ebb9e61c0cf21a56806` (6.18.45) |
| QEMU | 11.1.0, SHA-256 `28c1c21be818b265f0e169bdf2de5c83a0827ab9e69059098f2dc753bd6548ea` |
| build container | `asterinas/dev@sha256:a32c639c66899de90875f4b1aa8614926ec172957bb27c59a93c94fdde4da934` |

The Asterinas workspace vendor remained
`sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`. The
`nightly-2026-07-21` `library/Cargo.lock` vendor remained
`sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.
Nix reads the channel from the pinned Asterinas `rust-toolchain.toml`, then
vendors the matching Rust source tree's `library/Cargo.lock`. Public Cargo and
Git inputs may be fetched only while materializing these fixed-output inputs.

## Workflow result

[Workflow run 33066252308](https://github.com/chinrw/aster-syssec/actions/runs/33066252308)
completed successfully on `main`. The job ran from 11:11:06Z to 11:24:28Z.
Pipeline `RUNTIME-PIPELINE-0304FD0DA7CE9812` passed all four stages:

| Stage | Artifact SHA-256 |
| --- | --- |
| export-binary | `bcfeea3d1e117768c7dd993247d71d6a9cd0404136807a153117098de1e04384` |
| run-asterinas | `c7ac486fdcb2be95fff930aa37ab004dda9ebe50abbdd05cd73436727c87bfe8` |
| run-linux | `a640187ad335315a38139bfb5008eefb978498b8d8869e18101680b80ed96581` |
| compare | `3a141b6ff442fc349df58061ddf2336482fbc7c4f7d1c9e1db668469307d5207` |

The pipeline-result SHA-256 is
`7cd16c58dce8674efcaa5c200a036faac092fb3fcfc4bbeb4879ff8bf76ce9c9`.

## Exact binary provenance

`BINARY-PROVENANCE-5444F3816581A564` exported the same static case binary used
by the v0.4 baseline:

```text
binary SHA-256: 696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089
source SHA-256: 374f9297db7164ecbc7c8bb2e0f3e5b37478ddd8b16aba1d5c8309619eeeebda
compiler:       GCC 14.2.1 20250322
linker:         GNU ld 2.44
```

ELF evidence records no interpreter and no dynamic dependencies. Both guests
verified the same binary hash before reporting a normal result.

## Guest results and comparison

Asterinas produced `RUNTIME-RESULT-2EC4A68AE3FC39FB`. Linux produced
`RUNTIME-RESULT-A9EC56E4094FE3EF`. Both returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

Comparison `ORACLE-COMPARISON-145A977B01CEA804` matched all seven declared
fields and recorded `status=match`, `disposition=baseline`, with no diagnostics.
This is a positive contract baseline, not a finding.

## Network and artifact audit

Nix downloads occurred only during input resolution. Runtime execution used
`nix develop --offline`, Docker networking disabled, Cargo offline, host
forwarding disabled, and networkless Asterinas/Linux QEMU. Evidence packing
also used `nix develop --offline`. The Runtime and pack steps contained zero
download, Nix-store copy, or Git-input unpack records.

Artifact `9644206267` has archive digest
`sha256:efb16c471c0054c742557568bd9cf27f984390d5c4a9a13974c0bb646888f41e`.
The downloaded pack contained 31 manifest-listed files plus its index, for 32
files and 16,524,605 bytes. Every listed file SHA-256 and size matched. The
independently recomputed content SHA-256 matched
`42ef5822be32e1446fc777f86fedd4d45c94a10e145192cf6ef14bea5022d377`.
The six stage/result artifacts and the run manifest also passed their pinned
JSON Schema and manifest-integrity checks after download.
