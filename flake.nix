{
  description = "cesr — CESR + KERI primitives for Rust (single feature-gated crate)";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      utils,
      crane,
      fenix,
      advisory-db,
      ...
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

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
          nativeBuildInputs = with pkgs; [
            cmake
            pkg-config
          ];
          cargoExtraArgs = "--all-features";
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Repo-hygiene gate: a tiny sandboxed derivation that runs one linter and
        # succeeds (touch $out) only if it does. Keeps the seven non-cargo checks
        # below to one line each. Each was verified green before being wired —
        # never gate on a linter you haven't watched pass.
        lintCheck =
          name: nativeBuildInputs: script:
          pkgs.runCommandLocal name { inherit nativeBuildInputs; } ''
            ${script}
            touch $out
          '';
      in
      with pkgs;
      {
        checks = {
          # ---- Rust / cargo (via crane) ----
          cesr-clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
          cesr-doc = craneLib.cargoDoc (commonArgs // { inherit cargoArtifacts; });
          cesr-fmt = craneLib.cargoFmt { inherit src; };
          cesr-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
          };
          cesr-audit = craneLib.cargoAudit { inherit src advisory-db; };
          cesr-deny = craneLib.cargoDeny { inherit src; };
          cesr-nextest = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            }
          );
          cesr-doctest = craneLib.cargoDocTest (commonArgs // { inherit cargoArtifacts; });

          cesr-wasm = craneLib.mkCargoDerivation (
            commonArgs
            // {
              inherit cargoArtifacts;
              pnameSuffix = "-wasm";
              buildPhaseCargoCommand = ''
                cargo build --target wasm32-unknown-unknown \
                  --no-default-features --features alloc,core,utils,keri,serder,crypto,stream
              '';
            }
          );
          cesr-nostd = craneLib.mkCargoDerivation (
            commonArgs
            // {
              inherit cargoArtifacts;
              pnameSuffix = "-nostd";
              buildPhaseCargoCommand = ''
                cargo build --no-default-features --features alloc,core,utils,keri
              '';
            }
          );

          # ---- Repo hygiene (non-cargo) ----
          # GitHub Actions workflows — the check the pre-commit hook advertises.
          # shellcheck on PATH lets actionlint also vet inline `run:` scripts.
          cesr-actionlint = lintCheck "cesr-actionlint" [
            actionlint
            shellcheck
          ] "actionlint -color ${./.github/workflows}/*.yml";

          # All other YAML (Dependabot, issue-template config) — actionlint only
          # covers workflows, so this catches the rest (duplicate keys, indent).
          cesr-yaml = lintCheck "cesr-yaml" [
            yamllint
          ] "yamllint -c ${./.yamllint.yml} ${./.github} ${./.yamllint.yml}";

          # The git hooks are bash — shellcheck them so a broken hook can't land.
          cesr-shellcheck = lintCheck "cesr-shellcheck" [ shellcheck ] "shellcheck ${./.githooks}/*";

          # Nix formatting + dead-code, so the flake holds itself to the same bar
          # it holds the Rust to. (statix is in the dev shell for local linting;
          # it isn't gated because its single-file check is unreliable sandboxed.)
          cesr-deadnix = lintCheck "cesr-deadnix" [ deadnix ] "deadnix --fail ${./flake.nix}";
          cesr-nixfmt = lintCheck "cesr-nixfmt" [ nixfmt ] "nixfmt --check ${./flake.nix}";

          # Spell-check prose + identifiers (domain terms allowlisted in
          # _typos.toml; opaque test-vector files excluded).
          cesr-typos = lintCheck "cesr-typos" [ typos ] "typos --config ${./_typos.toml} ${./.}";
        };

        # `nix fmt` formats the flake with the same tool the gate checks.
        formatter = nixfmt;

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          # Point git at the tracked hooks, then greet with the same figlet +
          # lolcat + cowsay banner nexus uses — one shared dev-shell ritual.
          shellHook = ''
            git config core.hooksPath .githooks
            figlet -f doom "Cesr" | lolcat -a -d 2
            cowsay -f dragon-and-cow "Welcome to the Cesr dev environment on ${system}!" | lolcat
          '';
          packages = [
            # Rust toolchain extras
            fenix.packages.${system}.rust-analyzer
            bacon
            cargo-edit
            cargo-expand
            cargo-nextest
            cargo-llvm-cov
            cargo-mutants
            cargo-machete
            cargo-outdated
            cargo-semver-checks
            cargo-hack
            cargo-audit
            cargo-deny
            taplo
            # CI / lint parity with `nix flake check`
            actionlint
            shellcheck
            yamllint
            typos
            # statix 0.5.8 (this nixpkgs rev) fails its own insta snapshot
            # tests during build; skip them — the binary itself is fine and
            # statix is dev-shell-only (not part of `nix flake check`).
            (statix.overrideAttrs (_: {
              doCheck = false;
            }))
            deadnix
            nixfmt
            # Supply-chain / commit signing
            gnupg
            # General dev ergonomics
            git
            gh
            jq
            yq-go
            ripgrep
            fd
            tree
            cloc
            tmux
            # Banner glamour (nexus parity)
            figlet
            lolcat
            cowsay
          ];
        };
      }
    );
}
