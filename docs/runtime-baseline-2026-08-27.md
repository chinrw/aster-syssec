# Runtime baseline 2026-08-27

This record supersedes the current-runtime status in the v0.4 handoff without
rewriting the historical 2026-08-26 baseline.

## Immutable inputs

| Input | Identity |
| --- | --- |
| aster-syssec | `58b07bf1dd724636e0af35c226bc2f2c94d4bf2a` |
| Asterinas content | `0bc8839d496f185dd7662c79d53e98619bf1169c` |
| Asterinas merge | `a20a44592fbd6e6efdf92af486873cb6f4c83bc5` |
| Asterinas NAR | `sha256-4DljZtGrzNVVSprBN3yC5mqFe/+2N5VE18m2WAKCyQ4=` |
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

[Workflow run 33088278826](https://github.com/chinrw/aster-syssec/actions/runs/33088278826)
completed successfully on `main`. The job ran from 15:31:33Z to 15:45:25Z.
Pipeline `RUNTIME-PIPELINE-F08C97F40D002CAB` passed all four stages:

| Stage | Artifact SHA-256 |
| --- | --- |
| export-binary | `a9b0c5d637112840e3562d11cf1e54f6d2d065013572f16873b9155f8dfd8f9b` |
| run-asterinas | `1b6d50660e1101f8e5acb81e818babb433208de172af2c2294a24360cd94d5b9` |
| run-linux | `c0e0520cbacf82df1ed4341e6a48a51fe377876ede84f63fb98d68a5c8a1af7d` |
| compare | `ce98bfe8c524a79e5d4671e530ba8e6e0fa4536a33f47491f097beef02f84be1` |

The pipeline-result SHA-256 is
`39d8665e9669ffb4c7c8774bb4ac9382f28ecd52a4227e1a6b7e2f4b4701c96d`.

## Exact binary provenance

`BINARY-PROVENANCE-B2D66912DCA5048D` exported the same static case binary used
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

Asterinas produced `RUNTIME-RESULT-A5D56872C1EF1982`. Linux produced
`RUNTIME-RESULT-1AEFC260A34572F0`. Both returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

Comparison `ORACLE-COMPARISON-EBE6A95D8F953B78` matched all seven declared
fields and recorded `status=match`, `disposition=baseline`, with no diagnostics.
This is a positive contract baseline, not a finding.

## Network and artifact audit

Nix downloads occurred only during input resolution. Runtime execution used
`nix develop --offline`, Docker networking disabled, Cargo offline, host
forwarding disabled, and networkless Asterinas/Linux QEMU. Evidence packing
also used `nix develop --offline`. The Runtime and pack steps contained zero
download, Nix-store copy, or Git-input unpack records.

Artifact `9653695572` has archive digest
`sha256:c9f90d9152d0af60fb78442ce1d375954f4f46f7709909e7180ba0d70bb47956`
and compressed size 15,160,800 bytes.
The downloaded pack contained 31 manifest-listed files plus its index, for 32
files and 16,524,597 bytes. Every listed file SHA-256 and size matched. The
independently recomputed content SHA-256 matched
`b6420d3a4757349de0bcde9e75e06c3c3f9ac02c7879ccb93b3e78272f2d8890`.
The twelve primary Runtime artifacts, evidence-pack index, and run manifest
also passed their pinned JSON Schema and manifest-integrity checks after
download. The Runtime and pack steps contained 99 log lines and zero download,
fetch, or Nix-store copy records.
