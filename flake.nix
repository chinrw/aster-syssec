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
      url = "github:asterinas/asterinas/604948581512d83734377974d4c34adb4530f2d7";
      flake = false;
    };

    syzkaller-src = {
      url = "github:google/syzkaller";
      flake = false;
    };
  };

  outputs =
    {
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

          projectSource = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./.gitignore
              ./LICENSE
              ./MANIFEST.in
              ./README.md
              ./VALIDATION.md
              ./docs
              ./flake.lock
              ./flake.nix
              ./nix
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
            version = "0.1.0";
            pyproject = true;
            src = projectSource;

            build-system = [ python.pkgs.setuptools ];
            nativeCheckInputs = [
              pkgs.check-jsonschema
              pkgs.git
              pkgs.jq
              pkgs.pyright
            ];
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              export PYTHONPATH="$PWD/src"
              ${python.interpreter} -m unittest discover -v
              pyright src tests
              check-jsonschema --check-metaschema schemas/*.json
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

          syssecDev = pkgs.writeShellApplication {
            name = "syssec-dev";
            runtimeInputs = [ python ];
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
              export KANI_HOME="''${KANI_HOME:-$cache_root/kani}"
              export RUSTUP_HOME="''${SYSSEC_KANI_RUSTUP_HOME:-$cache_root/kani-rustup}"
              mkdir -p "$KANI_HOME"
              mkdir -p "$RUSTUP_HOME"
              exec cargo-kani setup "$@"
            '';
          };

          coreTools = with pkgs; [
            check-jsonschema
            git
            gnumake
            jq
            nixfmt
            pyright
            ripgrep
            ruff
            shellcheck
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
            cache_root="''${XDG_CACHE_HOME:-$HOME/.cache}/aster-syssec"
            export SYSSEC_WORK_ROOT="''${SYSSEC_WORK_ROOT:-$cache_root/work}"
            export SYSSEC_SOURCE_ROOT="''${SYSSEC_SOURCE_ROOT:-$PWD}"
          '';

          formalShellHook = commonShellHook + ''
            export ASTERINAS_RUST_TOOLCHAIN=${lib.escapeShellArg rustSpec.channel}
            export KANI_VERSION=${lib.escapeShellArg versions.kani}
            export KANI_HOME="''${KANI_HOME:-$cache_root/kani}"
            export RUSTUP_HOME="''${SYSSEC_KANI_RUSTUP_HOME:-$cache_root/kani-rustup}"
            export JAVA_HOME=${pkgs.jdk21_headless}
          '';

          kernelFuzzShellHook = formalShellHook + ''
            export SYZKALLER_REVISION=${lib.escapeShellArg syzkaller-src.rev}
          '';
        in
        rec {
          inherit
            kaniInstaller
            kaniSetup
            pkgs
            rustSpec
            rustToolchain
            syssec
            syssecDev
            syzkaller
            ;

          packages = {
            default = syssec;
            inherit syssec;
            kani-installer = kaniInstaller;
            kani-setup = kaniSetup;
            inherit syzkaller;
          };

          checks = {
            package = syssec;
            kani-installer = kaniInstaller;
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
