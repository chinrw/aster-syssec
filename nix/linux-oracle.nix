{
  pkgs,
  nixpkgsRevision,
}:

let
  linuxRevision = "bf3be28f6721e24961992ebb9e61c0cf21a56806";
  kernel = pkgs.linuxPackages.kernel;
  kernelOutput = kernel.out;
  kernelDerivationPath = builtins.unsafeDiscardStringContext kernel.drvPath;
  kernelOutputPath = builtins.unsafeDiscardStringContext (toString kernelOutput);
  qemu = pkgs.qemu_kvm;
  qemuExecutable = "${qemu}/bin/qemu-system-x86_64";
  packerVersion = "syssec-initramfs-packer 1.0.0";
  oracleId = "linux-x86-64-${builtins.replaceStrings [ "." ] [ "-" ] kernel.version}";

  packer = pkgs.writeShellApplication {
    name = "syssec-initramfs-packer";
    runtimeInputs = with pkgs; [
      coreutils
      cpio
      findutils
      gzip
    ];
    text = builtins.readFile ./linux-oracle/packer.sh;
  };

  busyboxClosure = pkgs.closureInfo {
    rootPaths = [ pkgs.busybox ];
  };

  baseRootfs = pkgs.runCommand "aster-syssec-linux-oracle-initramfs-${kernel.version}" {
    nativeBuildInputs = with pkgs; [
      coreutils
      cpio
      findutils
      gzip
    ];
  } ''
    root="$TMPDIR/root"
    mkdir -p "$root/bin" "$root/dev" "$root/proc" "$root/sys" "$root/tmp"
    while IFS= read -r store_path; do
      cp -a --no-preserve=ownership,timestamps --parents "$store_path" "$root"
    done < ${busyboxClosure}/store-paths
    install -m 0755 ${pkgs.busybox}/bin/busybox "$root/bin/busybox"
    ln -s busybox "$root/bin/sh"
    install -m 0755 ${./linux-oracle/init} "$root/init"
    find "$root" -exec touch -h -d @1 {} +
    (
      cd "$root"
      find . -print0 \
        | LC_ALL=C sort -z \
        | cpio --quiet --null --reproducible --owner=0:0 -o -H newc \
        | gzip -n -9 > "$out"
    )
  '';

  bundle = pkgs.runCommand "aster-syssec-linux-oracle-x86_64-${kernel.version}" {
    nativeBuildInputs = with pkgs; [
      coreutils
      jq
    ];
  } ''
    mkdir -p "$out/bin"
    install -m 0644 ${kernel.configfile} "$out/linux.config"
    install -m 0644 ${kernelOutput}/bzImage "$out/bzImage"
    install -m 0644 ${baseRootfs} "$out/base-initramfs.cpio.gz"
    ln -s ${packer}/bin/syssec-initramfs-packer "$out/bin/syssec-initramfs-packer"

    kernel_config_sha256="$(sha256sum "$out/linux.config" | cut -d ' ' -f 1)"
    kernel_image_sha256="$(sha256sum "$out/bzImage" | cut -d ' ' -f 1)"
    rootfs_sha256="$(sha256sum "$out/base-initramfs.cpio.gz" | cut -d ' ' -f 1)"
    qemu_sha256="$(sha256sum ${qemuExecutable} | cut -d ' ' -f 1)"
    packer_executable="$(readlink -f ${packer}/bin/syssec-initramfs-packer)"
    packer_sha256="$(sha256sum "$packer_executable" | cut -d ' ' -f 1)"

    jq -n \
      --arg id ${oracleId} \
      --arg linux_revision ${linuxRevision} \
      --arg kernel_config_sha256 "$kernel_config_sha256" \
      --arg kernel_image_sha256 "$kernel_image_sha256" \
      --arg rootfs_sha256 "$rootfs_sha256" \
      --arg qemu_executable ${qemuExecutable} \
      --arg qemu_version ${qemu.version} \
      --arg qemu_sha256 "$qemu_sha256" \
      --arg packer_executable "$packer_executable" \
      --arg packer_version ${pkgs.lib.escapeShellArg packerVersion} \
      --arg packer_sha256 "$packer_sha256" \
      '{
        schema_version: 1,
        id: $id,
        target_arch: "x86_64",
        linux_revision: $linux_revision,
        kernel_config: {path: "linux.config", sha256: $kernel_config_sha256},
        kernel_image: {path: "bzImage", sha256: $kernel_image_sha256},
        rootfs: {path: "base-initramfs.cpio.gz", sha256: $rootfs_sha256},
        qemu: {
          executable: $qemu_executable,
          version: $qemu_version,
          sha256: $qemu_sha256,
          machine: "q35",
          cpu: "max",
          acceleration: "tcg",
          memory_bytes: 2147483648,
          smp: 1
        },
        packer: {
          executable: $packer_executable,
          version: $packer_version,
          sha256: $packer_sha256
        }
      }' > "$out/oracle-image.json"

    jq -n \
      --arg nixpkgs_revision ${nixpkgsRevision} \
      --arg linux_version ${kernel.version} \
      --arg linux_revision ${linuxRevision} \
      --arg kernel_derivation ${kernelDerivationPath} \
      --arg kernel_output ${kernelOutputPath} \
      --arg base_rootfs ${baseRootfs} \
      --arg packer ${packer} \
      --arg qemu ${qemu} \
      '{
        schema_version: 1,
        nixpkgs_revision: $nixpkgs_revision,
        linux_version: $linux_version,
        linux_revision: $linux_revision,
        kernel_derivation: $kernel_derivation,
        kernel_output: $kernel_output,
        base_rootfs: $base_rootfs,
        packer: $packer,
        qemu: $qemu
      }' > "$out/bundle-provenance.json"
  '';
in
{
  inherit
    baseRootfs
    bundle
    kernel
    linuxRevision
    packer
    ;
}
