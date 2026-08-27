# Validation

## v0.4.0 release

The release synchronizes the main package, Lab package, Lab dependency, flake
packages, and runtime `__version__` at `0.4.0`.
`docs/v0.4-release.md` records the release scope and explicit deferred work.
Signed annotated tag `v0.4.0` has tag object
`a14a73475e56192b499c7470a234bf4c2cc415ae` and peels to release merge commit
`30b5a4dda39d5d58042ff42865e9b57d157bcd2d`.

The locked flake gate passed with 160 tests, both `0.4.0` package builds, the
Lab boundary and packer shell contracts, Ruff, formatting, Pyright, JSON Schema
validation, Actionlint, and ShellCheck. `nix run . -- --version` and
`nix run .#syssec-lab -- --version` both reported `0.4.0`.

## Post-v0.4 message-header Host extension

Asterinas commit `974e1bad52e6c6bb9a214c62ff0e16b96c2e6af8` moves the
Linux `user_msghdr` layout and pure signed-name-length and iovec-count
validation into the production `aster-uapi` seam. `aster-core` retains user
memory access and errno mapping. The flake pins that commit with NAR hash
`sha256-Xvq6W1zaDTqpMVh0DltoM6pYNiUcDkyY5bswbH0Mqs8=`.

The Host registry now contains 19 core targets: ten Kani proofs, three Miri
tests, three bare-metal layout targets, two bounded fuzz targets, and one Loom
model. Checkout preflight reported 19 targets and zero issues. Both local
profiles passed against the clean Asterinas commit:

- `pr`: three reviewer commands and all 15 blocking targets passed; result
  SHA-256 `5fae22d50cd931d33b1f4c2ee7495346ce372eb3ecdfbab43e2d470d6f48b5d0`;
- `nightly`: two reviewer commands and all 19 targets passed; result SHA-256
  `8e6507da325ce118db6395d82ee16afd1399ac6180d930871a022cb9b20c3ecd`.

The two new Kani proofs cover signed `msg_namelen` handling and the Linux iovec
count limit. The exact Miri test covers x86-64 `user_msghdr` layout and
initialized padding. The verified nightly evidence pack retained 135 files and
1,390,717 bytes with content SHA-256
`5de6971be9d11113abe6c19a11c419a48e106eee831bb7e2c87f79d823364603`.

The combined vendor output rebuilt offline from the fixed Asterinas workspace
and `nightly-2026-07-21` Rust-library inputs. Their hashes remain
`sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=` and
`sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`. The locked flake gate
passed with 161 tests, both packages, the Lab boundary, schema and workflow
checks, Ruff, formatting, Pyright, Actionlint, and ShellCheck. The Runtime
workflow selects the same Asterinas commit.

Asterinas PR #8 passed all 42 reported checks and merged as
`d94f69ac8aa62c3b44ee1fc161c6419d6c655b74`; content commit `974e1bad...`
is an ancestor of its public `main`. aster-syssec PR #19 passed both jobs and
merged as `c344f8323db7241ea1a3f412a9ee148426b9cc8f`. Main push run
`33065312608` then passed `host-verification` and `validate`.

Manual main run `33066250182` executed the complete 19-target nightly profile.
Both jobs passed and `failed_targets` was empty. The remote profile result
SHA-256 is
`4c7e89d80b0aad21f1c5765ee8e88c03e25dddd5434c8f6e94507be1a30585e2`.
Artifact `9643932986` has archive digest
`sha256:05ab9198fdb1d797ec2a704f6549e451872844d0d723e611d6cc32730acddefc`
and compressed size 192,236 bytes. The downloaded pack contained 135 files and
1,389,410 bytes. Every listed file SHA-256 and size matched; the independently
recomputed content SHA-256 matched
`f0fd6aefcb1e15cacaa83dc9c5e0cf592fccadabc1d67d63c957ef24387d2260`.

## Post-v0.4 timespec Host extension

Asterinas commit `820ec6464809071779f3c386634befcc83da10bc` moves the
Linux 64-bit userspace timespec layout and pure duration-range validation into
the production `aster-uapi` seam. `aster-core` retains user memory access,
`UTIME_NOW` and `UTIME_OMIT` handling, and errno mapping. The flake pins that
commit with NAR hash
`sha256-UAenN/jXYpPthwCRWN6ePbbUIKMv7V59ZCOPwk0+BqY=`.

The Host registry now contains 22 core targets: twelve Kani proofs, four Miri
tests, three bare-metal layout targets, two bounded fuzz targets, and one Loom
model. Checkout preflight against the preceding public Asterinas main commit
failed closed with 12 missing-symbol or missing-harness issues. Preflight
against `820ec646...` reported 22 targets and zero issues, with registry hash
`011e5ff6b1be40e0fed6a421811ab6fedc1b2e1f9da458a29e7a035cb90127f4`.

Both local profiles passed against the clean Asterinas commit:

- `pr`: three reviewer commands and all 18 blocking targets passed; result
  SHA-256 `e913b4b361a6cfabd8ca534f4243af15d143dad85a551c3b3d5798bc257b5158`;
- `nightly`: two reviewer commands and all 22 targets passed; result SHA-256
  `e1a7aa531a4cf83ddaa12133ce3ab01c73081cac71fabcfaad3933ed52114cdd`.

The two new Kani proofs cover nonnegative seconds and nanoseconds in
`0..1_000_000_000`. The exact Miri test covers the Linux 64-bit layout. Native
x86-64, LoongArch64, and RISC-V bare-metal checks passed; the RISC-V check used
the exact `nightly-2026-07-21` compiler and the combined fixed vendor with
`-Zbuild-std=core --offline`. Both existing fuzz targets completed 1000/1000
runs after their locked public dependencies were populated into the isolated
Host cache; target execution remained offline.

The nightly evidence pack verified one manifest and retained 153 files and
1,530,304 bytes, with content SHA-256
`1c2e3dbccb05555f8a04de135929350b58f5fa0af000a3e6c91265b16f3e20fc`.
The combined vendor rebuilt offline at the unchanged fixed hashes:

- Asterinas workspace:
  `sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`;
- pinned Rust `library/Cargo.lock`:
  `sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

The locked flake gate passed with 161 tests, both packages, the Lab boundary,
the initramfs packer contract, Ruff, formatting, Pyright, JSON Schema
validation, Actionlint, and ShellCheck.

Nix may fetch those public, lock-bound inputs while materializing the vendor.
The Runtime container and both Asterinas and Linux QEMU guests remain
network-off.

Asterinas PR #9 passed all 42 reported checks and merged as
`2b8472c7673a86fa47c7fa92796228ba739d343e`; content commit `820ec646...`
is an ancestor of its public `main`. aster-syssec PR #21 run `33073822346`
passed both jobs and merged as
`70b3103dba44f00e74fb3bdf5baf153d03e56055`. Main push run `33074303888`
then passed `host-verification` and `validate`.

Manual main run `33075159362` executed the complete 22-target nightly profile.
Both jobs passed and `failed_targets` was empty. The remote profile result
SHA-256 is
`12fa2368e673eef81ce78b9d4bf9a107eb6fd94b5d85b1e0315c8e9cebf9577f`.
Artifact `9647707230` has archive digest
`sha256:24dca7e8cdbcf0423539c63b71ea6d4b05f370a77521ef783aec1cd4c2ffdb24`
and compressed size 213,052 bytes. The downloaded pack contained 153 files and
1,529,521 bytes. Every listed file SHA-256 and size matched; the independently
recomputed content SHA-256 matched
`46f18e7e9d7228684981bd6b6b02fcda76206341a3d0645219fcfe093b65240c`.

## Post-v0.4 signal-set Host extension

Asterinas commit `0bc8839d496f185dd7662c79d53e98619bf1169c` moves the
Linux userspace signal-set layout and exact-size validation into the
production `aster-uapi` seam. `aster-core` retains user memory access, optional
mask handling, signal semantics, and errno mapping. The flake pins that commit
with NAR hash
`sha256-4DljZtGrzNVVSprBN3yC5mqFe/+2N5VE18m2WAKCyQ4=`.

The Host registry now contains 24 core targets: thirteen Kani proofs, five
Miri tests, three bare-metal layout targets, two bounded fuzz targets, and one
Loom model. Checkout preflight against the preceding public Asterinas main
commit failed closed with eight missing-symbol or missing-harness issues.
Preflight against `0bc8839d...` reported 24 targets and zero issues, with
registry hash
`b8c74515ac08f96958d161530e4ae17dbfd93166fd697de076bfb2491f9f6e3e`.

Both local profiles passed against the clean Asterinas commit:

- `pr`: three reviewer commands and all 20 blocking targets passed; result
  SHA-256 `63bf9f3da743171ec5755338eaabe6679b9d0dddf1144a12e5dd8048f39496aa`;
- `nightly`: two reviewer commands and all 24 targets passed; result SHA-256
  `9253b1b8e376211de959623521e12705a917820ea6072608b6f7cb36a8dd14f4`.

The new Kani proof covers the Linux exact-size signal-set contract. The Miri
test covers the userspace signal-set layout. Native x86-64, LoongArch64, and
RISC-V bare-metal checks passed. The verified nightly evidence pack retained
165 files and 1,576,941 bytes with content SHA-256
`c98110a83c028f0b32950f295f1051fab51456c69c3a89c500803acf5947c902`.

The combined vendor rebuilt offline at the unchanged fixed hashes:

- Asterinas workspace:
  `sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`;
- Rust `nightly-2026-07-21` `library/Cargo.lock`:
  `sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

The locked flake gate passed with 161 tests, both packages, the Lab boundary,
the initramfs packer contract, Ruff, formatting, Pyright, JSON Schema
validation, Actionlint, and ShellCheck.

Nix may fetch the public dependencies named by those lockfiles while
materializing the fixed-output vendors. Host target execution, the Runtime
container, and both Asterinas and Linux QEMU guests remain network-off.

Asterinas PR #14's original head passed all 42 reported checks and merged as
`a20a44592fbd6e6efdf92af486873cb6f4c83bc5`; content commit `0bc8839d...`
is an ancestor of its public `main`. aster-syssec PR #23 run `33084600540`
passed both jobs and merged as
`58b07bf1dd724636e0af35c226bc2f2c94d4bf2a`. Main push run `33087541192`
then passed `validate` and the 20-target PR profile.

Manual main run `33088274665` executed the complete 24-target nightly profile.
Both jobs passed and `failed_targets` was empty. The remote profile result
SHA-256 is
`0152f0d279255f258d83ef42697852b008c9640da09acc84fba0004ed8c681f5`.
Artifact `9653324612` has archive digest
`sha256:7e49f6e9bd1185ec01b9596053cb637cc7f4314ff3e8e026b0a9b7f3d8fe0168`
and compressed size 224,384 bytes. The downloaded pack contained 165 files and
1,577,150 bytes. Every listed file SHA-256 and size matched; there were no
symlinks or unexpected files, and the independently recomputed content
SHA-256 matched
`516d0f005c89a0eac168b23f38ecb5680678a66f93d5c4e554c0d4ad30219e97`.

## Post-v0.4 mmap and mremap Host extension

Asterinas commits `525328ea475defedb88421f06c992ffd8c1dc873` and
`41eac1dc153196882beaf42472879ded679fcddc` add checked page alignment and
half-open address-range arithmetic to the production `aster-uapi` seam, then
use it to validate `mmap` and `mremap` inputs before VMAR mutation. The flake
pins the content head with NAR hash
`sha256-fbSXSPJoCNSloMzlUBTiy7dgkyPiDzVSo5vNCzcAFxE=`.

The Host registry contains 27 core targets: sixteen Kani proofs, five Miri
tests, three bare-metal layout targets, two bounded fuzz targets, and one Loom
model. Checkout preflight against the preceding public Asterinas main failed
closed with seven missing-symbol or missing-harness issues. Preflight against
`41eac1dc...` reported 27 targets and zero issues, with registry hash
`f112c5c9d421a667869668596b8eaebdc4302977aa51db487ecaf0cdb5f5c8d5`.

Both local profiles passed against the clean content commit:

- `pr`: three reviewer commands and all 23 blocking targets passed; result
  SHA-256 `931b45cd08adfb06f94bdfd9d4960038384ced0d90568be7ee780a1dd668901e`;
- `nightly`: two reviewer commands and all 27 targets passed; result SHA-256
  `2713dff70c72610a9af9aaedd087309ec68b37f4dcaa606f7fa016231b7ac09a`.

The three new Kani harnesses prove that page alignment cannot wrap, a checked
range preserves its requested length and upper bound, and touching half-open
ranges do not overlap. Replacing checked addition with wrapping addition,
removing the end-limit check, or treating touching ranges as overlapping made
the corresponding proof fail. `aster-uapi` passed 21 unit tests and no-std
checks for x86-64, RISC-V 64, and LoongArch 64. The changed Asterinas core
passed its x86-64 check and Clippy. The regression package built, and the new
overlap-before-resize and page-aligned `MREMAP_DONTUNMAP` cases passed on
Linux. The two-profile evidence pack retained 334 files and 2,894,677 bytes
with content SHA-256
`7616dd19f83f53e8484795eac1e7ada42924d7500feefa7bb89eba530071cf96`.

Nix materialized the combined vendor for the new source pin. It may fetch the
public dependencies named by the Asterinas workspace lock and the
`nightly-2026-07-21` `library/Cargo.lock` during this fixed-output step. The
Rust lockfile SHA-256 is
`9e87d1ac04edbf5fa61e27cb21984a83566573a007767713868965fba70acb6d`.
The fixed vendor hashes remain:

- Asterinas workspace:
  `sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`;
- pinned Rust library:
  `sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

An offline rebuild returned the same combined vendor at
`/nix/store/g35flc5riy2clg1d5l8r3dg0pan7m5dq-asterinas-cargo-vendor-41eac1dc1531-vendor`;
its NAR hash is
`sha256-qi+MIWAY7SJMdaf6X3OVOvnt7rvyckrcpi1TzUl2/cc=` and the tree is read-only.

The locked flake gate passed with 161 tests, both packages, the Lab boundary,
the Linux oracle bundle, the pinned toolchain contract, Kani installer, and
syzkaller checks, plus Ruff, formatting, Pyright, JSON Schema, Actionlint, and
ShellCheck.

Kani, Miri, layout, and Loom used the read-only vendor; fuzz used its
prepopulated isolated cache. Cargo remained offline for every Host target.
Runtime execution remains in the network-disabled container, with host
forwarding disabled for Asterinas and `-nic none` for Linux. Asterinas PR #15
passed all 42 reported checks and merged as
`a516d1eb40c2e73563d4680e3251cdbdb95824dc`; content commit `41eac1dc...`
is an ancestor of public `main`. The corresponding aster-syssec remote CI
receipts are pending.

## Post-v0.4 control-message Host extension

Asterinas commit `5e3f8ef5d4b77d5ec276fe9df3c9aa89af8028cb` moves the
Linux `cmsghdr` type and its checked payload, alignment, and parser-step
calculations into the production `aster-uapi` seam. The flake pins that commit
with NAR hash `sha256-rgphrPDofHaCxe/Vk87wGuUovh4vvM3t0FcQdoSy+0E=`.

The Host registry now contains 16 core targets: eight Kani proofs, two Miri
tests, three bare-metal layout targets, two bounded fuzz targets, and one Loom
model. Checkout preflight reported 16 targets and zero issues. The clean
Asterinas commit passed both local profiles:

- `pr`: three reviewer commands and all 12 blocking targets passed; result
  SHA-256 `f7bc7a7741a5d731f5dfa688d913e86fe338d3675cf6d18cab3976cefd11fc9c`;
- `nightly`: two reviewer commands and all 16 targets passed; result SHA-256
  `a7df096ed33410bb08168c7d31e1f4706b39c59163cceb359bb5a0543dcbfe10`.

The three new Kani proofs cover checked alignment, bounded parser progress,
and payload-length round trips. Miri validates the x86-64 header layout. The
new `cmsg-host-fuzz` target completed 1000/1000 runs after its lockfile inputs
were primed, with execution remaining offline. The verified nightly evidence
pack retained 117 files and 1,269,575 bytes with content SHA-256
`67218b44276ea01f4d6563cc3f6e9a4ac248d8b9a8030db46bee45d52d365403`.

Manual main run `33057517578` then executed the 16-target nightly profile on a
GitHub runner. `validate` and `host-verification` passed; all targets reported
their expected outcome and `failed_targets` was empty. The remote profile
result SHA-256 is
`53c9da816d224947b7ac1ee2627facfe5964d980b5d966b2e0f07b52b639d156`.
Artifact `9640644616` has archive digest
`sha256:d68ef3dff462164bb2922c62de986ef9cf2c9abf86f6df73f6089286258c0f26`
and compressed size 172,748 bytes. The downloaded pack contained 117 files and
1,273,350 bytes. Every listed file SHA-256 and size matched; the independently
recomputed content SHA-256 matched
`04204dcfa82dad651b58e9caa9ba9c42d0698ca05e097112d000bcc556ad9759`.

Both fixed-output vendor derivations rebuilt at their existing hashes.
Historical main run `33055916200` produced the control-message dual-VM
baseline that the current baseline below supersedes.

## Current runtime baseline

Workflow run `33088278826` completed successfully on aster-syssec
`58b07bf1dd724636e0af35c226bc2f2c94d4bf2a` and Asterinas
`0bc8839d496f185dd7662c79d53e98619bf1169c`. Pipeline
`RUNTIME-PIPELINE-F08C97F40D002CAB` passed export, Asterinas, Linux, and
comparison. Both guests returned normal results for binary SHA-256
`696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089`.

Comparison `ORACLE-COMPARISON-EBE6A95D8F953B78` matched all seven declared
fields and retained `disposition=baseline`. The Runtime and evidence-pack
steps contained zero download or Nix-store copy records. The independently
verified pack contained 32 files and 16,524,597 bytes with content SHA-256
`b6420d3a4757349de0bcde9e75e06c3c3f9ac02c7879ccb93b3e78272f2d8890`.
Exact input, stage, result, archive, and provenance identities are recorded in
`docs/runtime-baseline-2026-08-27.md`.

## v0.4.0 runtime baseline

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

## v0.4.0 CI and nightly baseline

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

## Runtime workflow validation

The `runtime-ci-schedule` branch was exercised locally on 2026-08-27 with the
same wrapper and immutable inputs declared by `.github/workflows/runtime.yml`.
The Asterinas build container was pinned to image digest
`sha256:a32c639c66899de90875f4b1aa8614926ec172957bb27c59a93c94fdde4da934`
and ran with Docker networking disabled.

Nix fixed two Cargo vendor inputs:

- Asterinas workspace `Cargo.lock`:
  `sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=`;
- pinned `nightly-2026-07-21` Rust `library/Cargo.lock`:
  `sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=`.

The patched `cargo-osdk` copies the workspace lockfile into each generated
base crate. Its offline dependency resolution was first reproduced without the
lockfile at exit 101, then passed with the pinned lockfile. The combined vendor
also contains the pinned build-std dependencies; no Runtime-stage Cargo or VM
network access is required.

Pipeline `RUNTIME-PIPELINE-53FB20716090B443` passed all four stages:

| Stage | Result SHA-256 |
| --- | --- |
| export-binary | `f9b3430791dca09cdc98ccdc5df8c024c383eeb3df779177ce16382e480efb66` |
| run-asterinas | `e686e3a45b69654613b9d0dee91db76dba8ba331f69f27fe07c2796330c72d23` |
| run-linux | `bd0725beed6f8fd3f29dd149048fa3c981ab2e0c35664b95c407cc518ea07482` |
| compare | `8086bd8b1732816dab07c008c5be1ca51ead2be2f9757be200a6c981620c6a08` |

Asterinas result `RUNTIME-RESULT-6D9D7CBCFF442C92` and Linux result
`RUNTIME-RESULT-E5CD1AB51C3CBCFE` were both normal and bound binary SHA-256
`696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089`.
Comparison `ORACLE-COMPARISON-8E777E1A1927BC98` matched all seven fields and
retained `disposition=baseline`. No Runtime container remained after exit.

The CI-budget evidence pack verified one manifest and retained 32 files,
16,307,773 bytes, with aggregate content SHA-256
`bd571f2b84b4823deda63732cfcc73febd378ca7d20f4624857da47ae193887b`.
The locked flake gate passed with 159 tests, the Lab boundary and packer shell
contracts, Ruff, formatting, Pyright, JSON Schema validation, Actionlint, and
ShellCheck.

PR #13 merged as `892d700f0bcb495498ece1213f0cc9b8a598ee55`. Manual
`main` run `33046453514` then completed successfully in 13 minutes 22 seconds.
Remote pipeline `RUNTIME-PIPELINE-1FFB96559AE63CB4` passed all four stages;
Asterinas result `RUNTIME-RESULT-C6FC018342807742` and Linux result
`RUNTIME-RESULT-E3D9E812576EBE04` were normal and bound the same static binary.
Comparison `ORACLE-COMPARISON-DC078CD0DA73B598` matched all seven fields and
retained `disposition=baseline`.

Artifact `9636131500` uploaded 32 files. Its uncompressed pack contained
16,524,759 bytes with aggregate content SHA-256
`959ad3a7962068e26d57c5a9892c9b0582b181083abb4fc024ef2cac970dc448`.
After download, every registered file hash and the aggregate hash were
independently recomputed and matched the index.

The successful run resolved one additional Nix store path when entering the
formal dev shell, before `syssec` started. The Runtime container and both QEMU
guests remained network-off. PR #14 moved dev shell materialization into input
resolution and made Nix Runtime and evidence invocations explicitly offline.

PR #14 merged as `bfcc09d6a32b42d688d74bfbf9b61494290cff46`. Final
`main` run `33048842078` passed in 12 minutes 1 second. All Nix cache downloads
were confined to input resolution; no `copying path` event occurred during the
Runtime or evidence steps. Pipeline `RUNTIME-PIPELINE-C10BE1B2CD6BAB1E`, both
normal VM results, and comparison `ORACLE-COMPARISON-25B3516F3DEB8BEA` bound
the same static binary and matched all seven fields.

Artifact `9637034442` retained 32 files and 16,524,483 bytes with aggregate
content SHA-256
`d48347099ecbc4a1f2928ae3d6e60fa388f08ff928f47fa60dbc42967583b3da`.
Every registered file hash and the aggregate hash matched after download.

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
