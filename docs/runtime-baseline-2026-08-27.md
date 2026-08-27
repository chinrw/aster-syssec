# Runtime baseline 2026-08-27

This record supersedes the current-runtime status in the v0.4 handoff without
rewriting the historical 2026-08-26 baseline.

## Immutable inputs

| Input | Identity |
| --- | --- |
| aster-syssec | `05234d2e32d9ccc0c60dd5b3dfd2b2e582265d17` |
| Asterinas content | `41eac1dc153196882beaf42472879ded679fcddc` |
| Asterinas merge | `a516d1eb40c2e73563d4680e3251cdbdb95824dc` |
| Asterinas NAR | `sha256-fbSXSPJoCNSloMzlUBTiy7dgkyPiDzVSo5vNCzcAFxE=` |
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
The Rust lockfile SHA-256 is
`9e87d1ac04edbf5fa61e27cb21984a83566573a007767713868965fba70acb6d`.
The combined read-only vendor has NAR hash
`sha256-qi+MIWAY7SJMdaf6X3OVOvnt7rvyckrcpi1TzUl2/cc=`.

## Workflow result

[Workflow run 33101147881](https://github.com/chinrw/aster-syssec/actions/runs/33101147881)
completed successfully on `main`. The job ran from 17:58:44Z to 18:12:55Z.
Pipeline `RUNTIME-PIPELINE-8DC48905054276DA` passed all four stages:

| Stage | Artifact SHA-256 |
| --- | --- |
| export-binary | `a8c255f4ade5da09d31f4a9c57981a0d2f438e32ff7e288b1edfa15e770d6761` |
| run-asterinas | `2144567bd4bebd54b4fc0dc629d265bebe3a718c5255a994cfd688353670da6e` |
| run-linux | `2670e0e25385f205e960296e50818e6bfbbd4317f242a4a4b73aaca2c9e6abbd` |
| compare | `60a9aed045af18619c904c47a774baca6abd8017b5fb3a9d3d1677496ab7003e` |

The pipeline-result SHA-256 is
`27d24820caa18d45bc7ad3b5968b761e3160f5bb5c8780632cfc4892da4d5158`.

## Exact binary provenance

`BINARY-PROVENANCE-77DEBB28B3866340` exported the same static case binary used
by the v0.4 baseline:

```text
binary SHA-256: 696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089
source SHA-256: 374f9297db7164ecbc7c8bb2e0f3e5b37478ddd8b16aba1d5c8309619eeeebda
compiler:       GCC 14.2.1 20250322
linker:         GNU ld 2.44
```

ELF evidence records no interpreter and no dynamic dependencies. Both guests
verified the same binary hash before reporting a normal result.
The Asterinas request SHA-256 is
`accf0b3dc04754e6b97a245657c4dcf1c6e92331ef4e398695023bff6f4d0e98`;
the Linux request SHA-256 is
`b1c74247dbbca566c995e5c981c480319fad03f97ea0cc39514e7bcc2dce857a`.
The Linux packer bound that binary into derived initramfs SHA-256
`c2f7b9593eabf4e7796fbd2b28bacded6b805f5974e367f879b1b63cd1018fbd`.

## Guest results and comparison

Asterinas produced `RUNTIME-RESULT-03AA4E19FBBA4952`. Linux produced
`RUNTIME-RESULT-A53B2305B09B2853`. Both returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

Comparison `ORACLE-COMPARISON-C79BE981955C096B` matched all seven declared
fields and recorded `status=match`, `disposition=baseline`, with no diagnostics.
This is a positive contract baseline, not a finding.

## Network and artifact audit

Nix downloads occurred only during input resolution. Runtime execution used
`nix develop --offline`, Docker networking disabled, Cargo offline, host
forwarding disabled, and networkless Asterinas/Linux QEMU. Evidence packing
also used `nix develop --offline`. The Runtime and pack steps contained zero
download, Nix-store copy, or Git-input unpack records.

Artifact `9658985660` has archive digest
`sha256:2b09caa28c62f330e9c7ffefe3fa2462d82a6460a0c0eeeeef79aa1a125084ea`
and compressed size 15,160,746 bytes.
The downloaded pack contained 31 manifest-listed files plus its index, for 32
files and 16,525,883 bytes. Every listed file SHA-256 and size matched. The
independently recomputed content SHA-256 matched
`6330f79125d4f5ec91301e632cae7ec3541c482eab083b33a0cf98a23958bf26`.
There were no symlinks or unexpected files.
The twelve primary Runtime artifacts, evidence-pack index, and run manifest
also passed their pinned JSON Schema and manifest-integrity checks after
download. The Runtime and pack steps contained 99 log lines and zero download,
fetch, or Nix-store copy records.
