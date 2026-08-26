# Partial-EFAULT runtime baseline, 2026-08-26

This baseline executes one exported static binary in Asterinas and a pinned
Linux VM. It is a positive contract baseline, not a security finding.

## Inputs

| Input | Identity |
| --- | --- |
| Asterinas | `d0bddbf56d893221d103a0c3330f379dc59977b9` |
| Linux | `6.18.45`, stable commit `bf3be28f6721e24961992ebb9e61c0cf21a56806` |
| Nixpkgs | `2c423e03bbafcff28bfadc6781a4a8257f205cb5` |
| Case source | `374f9297db7164ecbc7c8bb2e0f3e5b37478ddd8b16aba1d5c8309619eeeebda` |
| Static binary | `696ed3ef05cda1b7d8e5f9b45bd1706ae4eef186736f028641fdf17e09cc7089` |
| Runtime target | `715c5be6d404b5c978417b5226cba72be1d228d931285b33333802650ed8466a` |
| Kernel config | `47d2ea729c1ab7d3ba2b2791c1b3e89c4472328a840eff1726f52cfce920edc0` |
| Kernel image | `69afb0cfef3fccd67079323bdea04860a49e34fc63fe563959355623dc646c4c` |
| Base initramfs | `716b5589c7184b3c6348bce49b86ed097b772ec761a7408b434c416f1a90861b` |
| QEMU executable | `28c1c21be818b265f0e169bdf2de5c83a0827ab9e69059098f2dc753bd6548ea` |
| Initramfs packer | `e988fa114fa825548a8ea05faad331643932d1873bfc2c3e1daecfd42254c791` |
| Oracle metadata | `faf2d355abd398b67518068aedbd2132d92c4f32913bd2fe8436a217f37fecbf` |

Both VMs used TCG, one vCPU, 2 GiB memory, and no host forwarding. The Linux
command included `-nic none`. The boot deadline was 300 seconds and the case
deadline was 30 seconds.

The flake exports the inputs without committing VM binaries:

```sh
nix build .#linux-oracle-bundle
```

The output contains `bzImage`, `linux.config`, `base-initramfs.cpio.gz`,
`oracle-image.json`, `bundle-provenance.json`, and
`bin/syssec-initramfs-packer`.

## Results

| Result | ID | SHA-256 | Duration |
| --- | --- | --- | --- |
| Asterinas | `RUNTIME-RESULT-F5AFB31941071D5C` | `1066aac0f1d0e6eafbcf814ec24cad35b27d7a416b682c045995833727de5d88` | 178975 ms |
| Linux | `RUNTIME-RESULT-8DC8AF20C2D95236` | `d8bee90baff05125a3c16d01d674d47f4c455c568ae39bf2276280860c6bab03` | 3948 ms |

Both results had `outcome=normal` and bound the same static binary hash. The
Asterinas adapter extracted the binary from the initramfs used to build the
boot ISO and stored a verified copy in evidence before writing its result.

The `partial-efault-pipe-read-v1` comparator produced:

```text
comparison_id = ORACLE-COMPARISON-820CA758EBA9EB43
comparison_sha256 = d2fc4c82bd538c9cbd9ee9bbc928fded59125e6a77cc30cfdb3c0610e338c644
status = match
disposition = baseline
```

The seven equal fields were `return`, `errno`, `first_byte`,
`remaining_return`, `remaining_errno`, `remaining_byte_0`, and
`remaining_byte_1`.

The full local evidence roots were:

```text
/tmp/aster-syssec-asterinas-exact-20260826-005
/tmp/aster-syssec-linux-oracle-20260826-005
```

They are not repository inputs. A later runtime pipeline must reproduce the
run and upload its verified evidence pack before this baseline becomes a CI
artifact.
