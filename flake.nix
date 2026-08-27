{
  description = "aster-syssec reviewer and verification environments";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # The lock records the Asterinas revision whose rust-toolchain.toml defines
    # the default formal shell. Override this input to use another checkout.
    asterinas-src = {
      url = "github:chinrw/asterinas/d0bddbf56d893221d103a0c3330f379dc59977b9";
      flake = false;
    };

    syzkaller-src = {
      url = "github:google/syzkaller";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      asterinas-src,
      syzkaller-src,
      ...
    }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      versions = import ./nix/versions.nix;

      mkSystem =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          lib = pkgs.lib;
          python = pkgs.python3;
          pythonEnv = python.withPackages (pythonPackages: [
            pythonPackages.jsonschema
            pythonPackages.referencing
          ]);
          linuxOracle = import ./nix/linux-oracle.nix {
            inherit pkgs;
            nixpkgsRevision = nixpkgs.rev;
          };

          projectSource = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./.github
              ./.gitignore
              ./LICENSE
              ./MANIFEST.in
              ./README.md
              ./VALIDATION.md
              ./docs
              ./flake.lock
              ./flake.nix
              ./nix
              ./packages
              ./pyproject.toml
              ./schemas
              ./scripts
              ./src
              ./tests
            ];
          };

          rustSpec = (builtins.fromTOML (builtins.readFile "${asterinas-src}/rust-toolchain.toml")).toolchain;
          rustToolchain = pkgs.rust-bin.fromRustupToolchain (
            rustSpec
            // {
              profile = rustSpec.profile or "minimal";
              components = lib.unique (
                (rustSpec.components or [ ])
                ++ [
                  "cargo"
                  "clippy"
                  "miri"
                  "rustfmt"
                ]
              );
              targets = rustSpec.targets or [ ];
            }
          );

          syzkallerDateStamp = syzkaller-src.lastModifiedDate;
          syzkallerDate = "${builtins.substring 0 4 syzkallerDateStamp}-${
            builtins.substring 4 2 syzkallerDateStamp
          }-${builtins.substring 6 2 syzkallerDateStamp}";
          syzkallerRevisionDate = "${builtins.substring 0 8 syzkallerDateStamp}-${
            builtins.substring 8 6 syzkallerDateStamp
          }";
          syzkaller = pkgs.buildGoModule {
            pname = "syzkaller";
            version = "0-unstable-${syzkallerDate}";
            src = syzkaller-src;
            vendorHash = "sha256-FOA28TsLgk1jB1UJnn5TNd8CQ1gkY0MdDe4V76Z7bBM=";
            nativeBuildInputs = [ pkgs.ncurses ];
            doCheck = false;
            buildPhase = ''
              runHook preBuild
              unset GOFLAGS
              make \
                GITREVDATE=${lib.escapeShellArg syzkallerRevisionDate} \
                GGFLAGS=-trimpath \
                REV=${lib.escapeShellArg syzkaller-src.rev} \
                SYZ_ENV=nix \
                TARGETARCH=amd64 \
                TARGETOS=linux \
                TARGETVMARCH=amd64
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p "$out/bin"
              cp -r bin/. "$out/bin/"
              ln -s linux_amd64/syz-execprog "$out/bin/syz-execprog"
              ln -s linux_amd64/syz-executor "$out/bin/syz-executor"
              runHook postInstall
            '';
            meta = {
              description = "Pinned syzkaller kernel fuzzer toolchain";
              homepage = "https://github.com/google/syzkaller";
              license = lib.licenses.asl20;
              mainProgram = "syz-manager";
              platforms = [ "x86_64-linux" ];
            };
          };

          syssec = python.pkgs.buildPythonApplication {
            pname = "aster-syssec";
            version = "0.3.0";
            pyproject = true;
            src = projectSource;

            build-system = [ python.pkgs.setuptools ];
            dependencies = [
              python.pkgs.jsonschema
              python.pkgs.referencing
            ];
            makeWrapperArgs = [
              "--set"
              "SYSSEC_BUILD_REVISION"
              (self.rev or self.dirtyRev or "unknown")
              "--prefix"
              "PATH"
              ":"
              (lib.makeBinPath [ pkgs.util-linux ])
            ];
            nativeCheckInputs = [
              pkgs.actionlint
              pkgs.check-jsonschema
              pkgs.cpio
              pkgs.git
              pkgs.gzip
              pkgs.jq
              pkgs.pyright
              pkgs.ruff
              pkgs.shellcheck
              pkgs.util-linux
              python.pkgs.jsonschema
              python.pkgs.referencing
            ];
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              export PYTHONPATH="$PWD/src:$PWD/packages/aster-syssec-lab/src:${pythonEnv}/${python.sitePackages}"
              ${pythonEnv.interpreter} -m unittest discover -v
              SYSSEC_INITRAMFS_PACKER=${linuxOracle.packer}/bin/syssec-initramfs-packer \
                bash tests/test_linux_oracle_packer.sh
              ruff check src tests packages/aster-syssec-lab/src
              ruff format --check src tests packages/aster-syssec-lab/src
              pyright src tests packages/aster-syssec-lab/src
              check-jsonschema --check-metaschema schemas/*.json
              actionlint .github/workflows/*.yml
              shellcheck scripts/*.sh tests/*.sh
              runHook postCheck
            '';
            pythonImportsCheck = [ "aster_syssec" ];

            meta = {
              description = "Evidence-first Asterinas syscall security reviewer";
              license = lib.licenses.mpl20;
              mainProgram = "syssec";
              platforms = [ "x86_64-linux" ];
            };
          };

          syssecLab = python.pkgs.buildPythonApplication {
            pname = "aster-syssec-lab";
            version = "0.3.0";
            pyproject = true;
            src = ./packages/aster-syssec-lab;

            build-system = [ python.pkgs.setuptools ];
            dependencies = [ syssec ];
            doCheck = false;
            pythonImportsCheck = [ "aster_syssec_lab" ];

            meta = {
              description = "Authorization-gated Lab boundary for aster-syssec";
              license = lib.licenses.mpl20;
              mainProgram = "syssec-lab";
              platforms = [ "x86_64-linux" ];
            };
          };

          syssecDev = pkgs.writeShellApplication {
            name = "syssec-dev";
            runtimeInputs = [ pythonEnv ];
            text = ''
              source_root="''${SYSSEC_SOURCE_ROOT:-$PWD}"
              if [ ! -f "$source_root/pyproject.toml" ] || [ ! -d "$source_root/src/aster_syssec" ]; then
                  echo "syssec-dev: set SYSSEC_SOURCE_ROOT to the aster-syssec checkout" >&2
                  exit 2
              fi
              export PYTHONPATH="$source_root/src''${PYTHONPATH:+:$PYTHONPATH}"
              exec python3 -m aster_syssec "$@"
            '';
          };

          asterinasRustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };

          cargoOsdk = asterinasRustPlatform.buildRustPackage {
            pname = "cargo-osdk";
            version = "0.18.1";
            src = asterinas-src;
            patches = [ ./nix/cargo-osdk-runtime-source.patch ];
            cargoRoot = "osdk";
            buildAndTestSubdir = "osdk";
            cargoLock.lockFile = "${asterinas-src}/osdk/Cargo.lock";
            doCheck = false;
            env.OSDK_LOCAL_DEV = "1";

            meta = {
              description = "Pinned Asterinas OSDK command-line tool";
              homepage = "https://asterinas.github.io/book/osdk/guide/index.html";
              license = lib.licenses.mpl20;
              mainProgram = "cargo-osdk";
              platforms = [ "x86_64-linux" ];
            };
          };

          asterinasWorkspaceCargoVendor = pkgs.rustPlatform.fetchCargoVendor {
            pname = "asterinas-workspace-cargo-vendor";
            version = builtins.substring 0 12 asterinas-src.rev;
            src = asterinas-src;
            hash = "sha256-BCSyswj+Q1wm6M/XthjZfgjj43tAtmRvhCD4V0ygjCc=";
          };

          asterinasRustStdCargoVendor = pkgs.rustPlatform.fetchCargoVendor {
            pname = "asterinas-rust-std-cargo-vendor";
            version = rustSpec.channel;
            src = "${rustToolchain}/lib/rustlib/src/rust/library";
            hash = "sha256-q/scbT50qB0Qhoqsoa6/QJOHIuN7GTS9B1bdHRJXfZ8=";
          };

          asterinasCargoVendor = pkgs.runCommand
            "asterinas-cargo-vendor-${builtins.substring 0 12 asterinas-src.rev}-vendor"
            { }
            ''
              mkdir -p "$out"
              cp -R ${asterinasWorkspaceCargoVendor}/. "$out/"
              chmod -R u+w "$out"
              cp -R ${asterinasRustStdCargoVendor}/source-registry-0/. "$out/source-registry-0/"
              chmod -R a-w "$out"
            '';

          kaniInstaller = pkgs.rustPlatform.buildRustPackage {
            pname = "kani-verifier";
            version = versions.kani;
            src = pkgs.fetchCrate {
              pname = "kani-verifier";
              version = versions.kani;
              hash = "sha256-m0khwmHJAiEtICN/f2IE70A2/0JNKwaL3so429YtdOY=";
            };
            cargoHash = "sha256-KAFLA97yi74riDkBO3EJ9Uv6SdVQrJ1wLNJ68Jf9yWk=";
            doCheck = false;

            meta = {
              description = "Installer for the Kani Rust Verifier release bundle";
              homepage = "https://model-checking.github.io/kani/";
              license = with lib.licenses; [
                asl20
                mit
              ];
              mainProgram = "kani";
              platforms = [ "x86_64-linux" ];
            };
          };

          kaniSetup = pkgs.writeShellApplication {
            name = "syssec-kani-setup";
            runtimeInputs = [
              kaniInstaller
              pkgs.cacert
              pkgs.rustup
            ];
            text = ''
              cache_root="''${XDG_CACHE_HOME:-$HOME/.cache}/aster-syssec"
              work_root="''${SYSSEC_WORK_ROOT:-$cache_root/work}"
              syssec_cache_root="''${SYSSEC_CACHE_ROOT:-$work_root/cache}"
              export KANI_HOME="''${KANI_HOME:-$syssec_cache_root/kani}"
              export RUSTUP_HOME="''${SYSSEC_KANI_RUSTUP_HOME:-$syssec_cache_root/kani-rustup}"
              mkdir -p "$KANI_HOME"
              mkdir -p "$RUSTUP_HOME"
              exec cargo-kani setup "$@"
            '';
          };

          coreTools = with pkgs; [
            actionlint
            binutils
            check-jsonschema
            git
            gnumake
            jq
            nixfmt
            pyright
            pythonEnv
            ripgrep
            ruff
            shellcheck
            util-linux
            uv
          ];

          formalTools = coreTools ++ [
            rustToolchain
            kaniInstaller
            kaniSetup
            pkgs.rustup
            pkgs.cargo-fuzz
            pkgs.cmake
            pkgs.jdk21_headless
            pkgs.maven
            pkgs.pkg-config
            pkgs.llvmPackages.bintools
            pkgs.llvmPackages.clang
            pkgs.llvmPackages.lld
            pkgs.llvmPackages.llvm
          ];

          kernelFuzzTools = formalTools ++ [
            pkgs.docker-client
            pkgs.gdb
            pkgs.go
            pkgs.qemu_kvm
            pkgs.socat
            pkgs.strace
            syzkaller
          ];

          commonShellHook = ''
            export PATH=${pythonEnv}/bin:$PATH
            cache_root="''${XDG_CACHE_HOME:-$HOME/.cache}/aster-syssec"
            export SYSSEC_WORK_ROOT="''${SYSSEC_WORK_ROOT:-$cache_root/work}"
            export SYSSEC_SOURCE_ROOT="''${SYSSEC_SOURCE_ROOT:-$PWD}"
            export ASTERINAS_PINNED_SOURCE=${lib.escapeShellArg (toString asterinas-src)}
          '';

          formalShellHook = commonShellHook + ''
            export ASTERINAS_RUST_TOOLCHAIN=${lib.escapeShellArg rustSpec.channel}
            export KANI_VERSION=${lib.escapeShellArg versions.kani}
            syssec_cache_root="''${SYSSEC_CACHE_ROOT:-$SYSSEC_WORK_ROOT/cache}"
            export KANI_HOME="''${KANI_HOME:-$syssec_cache_root/kani}"
            export RUSTUP_HOME="''${SYSSEC_KANI_RUSTUP_HOME:-$syssec_cache_root/kani-rustup}"
            export JAVA_HOME=${pkgs.jdk21_headless}
          '';

          kernelFuzzShellHook = formalShellHook + ''
            export SYZKALLER_REVISION=${lib.escapeShellArg syzkaller-src.rev}
          '';
        in
        rec {
          inherit
            asterinasCargoVendor
            cargoOsdk
            kaniInstaller
            kaniSetup
            pkgs
            rustSpec
            rustToolchain
            syssec
            syssecDev
            syssecLab
            syzkaller
            ;

          packages = {
            default = syssec;
            inherit syssec;
            aster-syssec-lab = syssecLab;
            kani-installer = kaniInstaller;
            kani-setup = kaniSetup;
            cargo-osdk = cargoOsdk;
            asterinas-cargo-vendor = asterinasCargoVendor;
            linux-oracle-bundle = linuxOracle.bundle;
            linux-oracle-packer = linuxOracle.packer;
            inherit syzkaller;
          };

          checks = {
            package = syssec;
            lab-package = syssecLab;
            lab-boundary-contract =
              pkgs.runCommand "aster-syssec-lab-boundary-contract"
                {
                  nativeBuildInputs = [
                    pkgs.jq
                    syssecLab
                  ];
                }
                ''
                  mkdir -p "$out"
                  syssec-lab boundary --json > "$out/boundary.json"
                  jq -e '
                    .safety_class == "lab" and
                    .execution_available == false and
                    .authorization_required == true and
                    .network == "off"
                  ' "$out/boundary.json" >/dev/null
                '';
            kani-installer = kaniInstaller;
            linux-oracle-bundle = linuxOracle.bundle;
            inherit syzkaller;
            toolchain-contract = pkgs.runCommand "aster-syssec-toolchain-contract" { } ''
              mkdir -p "$out"
              test -x ${rustToolchain}/bin/cargo
              test -x ${rustToolchain}/bin/cargo-miri
              test -x ${rustToolchain}/bin/rustc
              ${lib.concatMapStringsSep "\n" (
                target: "test -d ${rustToolchain}/lib/rustlib/${lib.escapeShellArg target}"
              ) (rustSpec.targets or [ ])}
              printf '%s\n' ${lib.escapeShellArg rustSpec.channel} > "$out/channel"
              ${rustToolchain}/bin/rustc --version > "$out/rustc-version"
              PATH=${rustToolchain}/bin:$PATH ${rustToolchain}/bin/cargo miri --version > "$out/miri-version"
            '';
          };

          devShells = {
            default = pkgs.mkShell {
              packages = coreTools ++ [
                syssec
                syssecDev
              ];
              shellHook = commonShellHook;
            };

            formal = pkgs.mkShell {
              packages = formalTools ++ [
                syssec
                syssecDev
              ];
              shellHook = formalShellHook;
            };

            kernel-fuzz = pkgs.mkShell {
              packages = kernelFuzzTools ++ [
                syssec
                syssecDev
              ];
              shellHook = kernelFuzzShellHook;
            };
          };

          apps.default = {
            type = "app";
            program = lib.getExe syssec;
            meta.description = "Run the packaged aster-syssec CLI";
          };

          apps.syssec-lab = {
            type = "app";
            program = lib.getExe syssecLab;
            meta.description = "Validate the aster-syssec Lab boundary";
          };

          formatter = pkgs.nixfmt;
        };
    in
    {
      packages = forAllSystems (system: (mkSystem system).packages);
      checks = forAllSystems (system: (mkSystem system).checks);
      devShells = forAllSystems (system: (mkSystem system).devShells);
      apps = forAllSystems (system: (mkSystem system).apps);
      formatter = forAllSystems (system: (mkSystem system).formatter);
    };
}
