# Runtime baseline 2026-08-27

This record supersedes the current-runtime status in the v0.4 handoff without
rewriting the historical 2026-08-26 baseline.

## Immutable inputs

| Input | Identity |
| --- | --- |
| aster-syssec | `4af32509539a4f4604ec5cc30bc1d2a4535c7f1c` |
| Asterinas content | `5e3f8ef5d4b77d5ec276fe9df3c9aa89af8028cb` |
| Asterinas merge | `74f1a483962c894f4350967b2c1f0e8d35d7f245` |
| Asterinas NAR | `sha256-rgphrPDofHaCxe/Vk87wGuUovh4vvM3t0FcQdoSy+0E=` |
| Linux | `bf3be28f6721e24961992ebb9e61c0cf21a56806` (6.18.45) |
| QEMU | 11.1.0, SHA-256 `28c1c21be818b265f0e169bdf2de5c83a0827ab9e69059098f2dc753bd6548ea` |
| build container | `asterinas/dev@sha256:a32c639c66899de90875f4b1aa8614926ec172957bb27c59a93c94fdde4da934` |

The Asterinas workspace vendor remained
`sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`. The
`nightly-2026-07-21` `library/Cargo.lock` vendor remained
`sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

## Workflow result

[Workflow run 33055916200](https://github.com/chinrw/aster-syssec/actions/runs/33055916200)
completed successfully on `main`. The job ran from 08:55:56Z to 09:09:32Z.
Pipeline `RUNTIME-PIPELINE-2AAC2AB2DD4DB13A` passed all four stages:

| Stage | Artifact SHA-256 |
| --- | --- |
| export-binary | `9421651bf0bd485dffd30f89d86356dbd1e1e96d07a9775abff63e2ea41ddb7a` |
| run-asterinas | `4f0832a82031f33145dcdc4f68b4792d97bebb013f5d3dccffb1c501d780daf0` |
| run-linux | `e8b9cacf371b96d4ee53fec8972780ca823739238581d1020b1fd4b6d698e7aa` |
| compare | `ada350da53fa94cc44abd18c1865f9293e74b7bd50bcd3a688932b0dd3462fc8` |

The pipeline-result SHA-256 is
`8f971c2769ffc6d70c901355f3f14f69ae3a026d7fd63fca88a93b3fbd3b9d5f`.

## Exact binary provenance

`BINARY-PROVENANCE-E00502BFFACECFFA` exported the same static case binary used
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

Asterinas produced `RUNTIME-RESULT-67B41C3F89E9AF67`. Linux produced
`RUNTIME-RESULT-39228526E46F4A93`. Both returned:

```json
{"case_id":"pipe-partial-efault-read","exit_kind":"normal","return":-1,"errno":14,"first_byte":65,"remaining_return":2,"remaining_errno":0,"remaining_byte_0":65,"remaining_byte_1":66}
```

Comparison `ORACLE-COMPARISON-6E7E057406AE0C1A` matched all seven declared
fields and recorded `status=match`, `disposition=baseline`, with no diagnostics.
This is a positive contract baseline, not a finding.

## Network and artifact audit

Nix downloads occurred only during input resolution. Runtime execution used
`nix develop --offline`, Docker networking disabled, Cargo offline, host
forwarding disabled, and networkless Asterinas/Linux QEMU. Evidence packing
also used `nix develop --offline`. The Runtime and pack steps contained zero
download, Nix-store copy, or Git-input unpack records.

Artifact `9640130176` has archive digest
`sha256:f51c0831eacd0dc65dff18ae8a563650e8026247f09db56d08da541c3b93223c`.
The downloaded pack contained 31 manifest-listed files plus its index, for 32
files and 16,524,561 bytes. Every listed file SHA-256 and size matched. The
independently recomputed content SHA-256 matched
`ea67f513a13ca36de0c754e75e57ed433feca815d2fd81223ecc32c0c196f542`.
