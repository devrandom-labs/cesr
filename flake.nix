{
  description = "cesr — CESR + KERI primitives for Rust (single feature-gated crate)";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs = { nixpkgs.follows = "nixpkgs"; };
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };
  outputs = { self, nixpkgs, utils, crane, fenix, advisory-db, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;

        # Pinned STABLE toolchain read from rust-toolchain.toml (nexus pattern).
        # sha256 hashes the channel manifest (platform-independent) — reused
        # from nexus since cesr pins the SAME 1.95.0 channel.
        rustToolchain = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-gh/xTkxKHL4eiRXzWv8KP7vfjSk61Iq48x47BEDFgfk=";
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          buildInputs = with pkgs; [ openssl ];
          nativeBuildInputs = with pkgs; [ cmake pkg-config ];
          cargoExtraArgs = "--all-features";
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in with pkgs; {
        checks = {
          cesr-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
          });
          cesr-doc = craneLib.cargoDoc (commonArgs // { inherit cargoArtifacts; });
          cesr-fmt = craneLib.cargoFmt { inherit src; };
          cesr-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
          };
          cesr-audit = craneLib.cargoAudit { inherit src advisory-db; };
          cesr-deny = craneLib.cargoDeny { inherit src; };
          cesr-nextest = craneLib.cargoNextest (commonArgs // {
            inherit cargoArtifacts;
            partitions = 1;
            partitionType = "count";
          });
          cesr-doctest = craneLib.cargoDocTest (commonArgs // { inherit cargoArtifacts; });

          cesr-wasm = craneLib.mkCargoDerivation (commonArgs // {
            inherit cargoArtifacts;
            pnameSuffix = "-wasm";
            buildPhaseCargoCommand = ''
              cargo build --target wasm32-unknown-unknown \
                --no-default-features --features alloc,core,utils,keri,serder,crypto,stream
            '';
          });
          cesr-nostd = craneLib.mkCargoDerivation (commonArgs // {
            inherit cargoArtifacts;
            pnameSuffix = "-nostd";
            buildPhaseCargoCommand = ''
              cargo build --no-default-features --features alloc,core,utils,keri
            '';
          });
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          shellHook = ''
            git config core.hooksPath .githooks
          '';
          packages = [
            fenix.packages.${system}.rust-analyzer
            bacon
            cargo-edit
            cargo-expand
            gh
            tree
          ];
        };
      });
}
