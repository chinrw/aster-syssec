# Runtime baseline 2026-08-27

This record supersedes the current-runtime status in the v0.4 handoff without
rewriting the historical 2026-08-26 baseline.

## Immutable inputs

| Input | Identity |
| --- | --- |
| aster-syssec | `70b3103dba44f00e74fb3bdf5baf153d03e56055` |
| Asterinas content | `820ec6464809071779f3c386634befcc83da10bc` |
| Asterinas merge | `2b8472c7673a86fa47c7fa92796228ba739d343e` |
| Asterinas NAR | `sha256-UAenN/jXYpPthwCRWN6ePbbUIKMv7V59ZCOPwk0+BqY=` |
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

[Workflow run 33075155261](https://github.com/chinrw/aster-syssec/actions/runs/33075155261)
completed successfully on `main`. The job ran from 13:17:07Z to 13:30:44Z.
Pipeline `RUNTIME-PIPELINE-6CDABEF04FBB6E5C` passed all four stages:

| Stage | Artifact SHA-256 |
| --- | --- |
| export-binary | `12330d6c2b5b1cf88d4066137abe30ea6e0c3f6cb452d2e771ec8f8f43c08345` |
| run-asterinas | `4a1cc4b3c962c5ee701ffa7f01702b7e86bf0cfc774188f98d39ec97fd9b12f7` |
| run-linux | `1edc28ef763c72a539b07ce8f37d29eefd5452edea1ffb06068c3c337f3a391d` |
| compare | `7618615446f3777e588dc492d2e8cc7161ec3557d00c8e13bb43bfdd37ba15f0` |

The pipeline-result SHA-256 is
`e6557842c437c7b9f9b726cb80496f9984f335aa1b227aadbda9947b25cb8202`.

## Exact binary provenance

`BINARY-PROVENANCE-50EE3829075242F1` exported the same static case binary used
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

Asterinas produced `RUNTIME-RESULT-92EDFED56F112ACB`. Linux produced
`RUNTIME-RESULT-ACA55E494EE1926A`. Both returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

Comparison `ORACLE-COMPARISON-F4A8F607F68060FB` matched all seven declared
fields and recorded `status=match`, `disposition=baseline`, with no diagnostics.
This is a positive contract baseline, not a finding.

## Network and artifact audit

Nix downloads occurred only during input resolution. Runtime execution used
`nix develop --offline`, Docker networking disabled, Cargo offline, host
forwarding disabled, and networkless Asterinas/Linux QEMU. Evidence packing
also used `nix develop --offline`. The Runtime and pack steps contained zero
download, Nix-store copy, or Git-input unpack records.

Artifact `9648362201` has archive digest
`sha256:906920223ef222dcb611a28431ea2bb11835a0b22a7d1059d7b1ab45ed2e95e9`
and compressed size 15,160,447 bytes.
The downloaded pack contained 31 manifest-listed files plus its index, for 32
files and 16,524,703 bytes. Every listed file SHA-256 and size matched. The
independently recomputed content SHA-256 matched
`b2d2504dc68e1912351370dcfc8a626892cd6efa266e007e28dab08979c8ab65`.
The nine primary Runtime artifacts and the run manifest also passed their
pinned JSON Schema and manifest-integrity checks after download.
