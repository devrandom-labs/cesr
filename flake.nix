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

        # Crane's `cleanCargoSource` keeps only `.rs`/`.toml`/`Cargo.lock`, which
        # would strip the keripy differential corpus under `tests/corpus/keripy/**`
        # (`.jsonl`). The diff harness embeds those via `include_str!` at compile
        # time, so they MUST reach the sandbox — keep everything crane keeps PLUS
        # any file under a `tests/corpus/` directory.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          name = "cesr-source";
          filter =
            path: type:
            (craneLib.filterCargoSources path type) || (pkgs.lib.hasInfix "/tests/corpus/" (toString path));
        };

        # Source for the isolated `fuzz/` workspace check. Crane's default
        # `cleanCargoSource` keeps only `.rs`/`.toml`/`Cargo.lock`, which would
        # strip the committed corpus seed files under `fuzz/tests/__fuzz__/**`
        # (they have no extension). bolero's DefaultEngine replays those seeds,
        # so they MUST reach the sandbox. This filter keeps everything crane
        # would keep PLUS any file living under a `__fuzz__` corpus directory.
        fuzzSrc = pkgs.lib.cleanSourceWith {
          src = ./.;
          name = "cesr-fuzz-source";
          filter =
            path: type:
            (craneLib.filterCargoSources path type) || (pkgs.lib.hasInfix "/tests/__fuzz__/" (toString path));
        };

        # The fuzz workspace has its OWN Cargo.lock (bolero + cesr path dep).
        # Vendor it separately so the check builds offline/hermetically without
        # touching the root crate's vendored deps.
        fuzzCargoArtifacts = craneLib.vendorCargoDeps { cargoLock = ./fuzz/Cargo.lock; };

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
              cargoClippyExtraArgs = "--workspace --all-targets -- --deny warnings";
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
                cargo build -p cesr-rs --target wasm32-unknown-unknown \
                  --no-default-features --features alloc,core,b64,keri,serder,crypto,stream
                cargo build -p keri-rs --target wasm32-unknown-unknown \
                  --no-default-features
              '';
            }
          );
          cesr-nostd = craneLib.mkCargoDerivation (
            commonArgs
            // {
              inherit cargoArtifacts;
              pnameSuffix = "-nostd";
              buildPhaseCargoCommand = ''
                cargo build -p cesr-rs --no-default-features --features alloc,core,b64,keri,stream
                cargo build -p keri-rs --no-default-features
              '';
            }
          );

          # Deterministic corpus-replay + bounded-random fuzz gate. Runs the
          # bolero `check!` targets in the isolated `fuzz/` workspace via plain
          # `cargo test` on the pinned STABLE toolchain (bolero's DefaultEngine
          # needs no nightly; sanitizers — which do — live in a separate
          # scheduled GitHub workflow). The source carries both the parent crate
          # (so the `cesr = { path = ".." }` dep compiles) and `fuzz/` with its
          # committed corpus seeds; `fuzzCargoArtifacts` vendors the fuzz
          # workspace's own Cargo.lock so the build is fully offline/hermetic.
          cesr-fuzz-replay = craneLib.mkCargoDerivation (
            commonArgs
            // {
              src = fuzzSrc;
              cargoVendorDir = fuzzCargoArtifacts;
              cargoArtifacts = null;
              pnameSuffix = "-fuzz-replay";
              # bolero discovers corpus relative to CARGO_MANIFEST_DIR; run from
              # the fuzz workspace root so `tests/__fuzz__/**` resolves.
              buildPhaseCargoCommand = ''
                (cd fuzz && cargo test --no-fail-fast)
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

        # On-demand coverage report (issue #30 tail), NOT a gating check —
        # coverage instrumentation recompiles the whole crate, too slow for the
        # per-push gate (see `checks` above). `nix build .#coverage -L` writes a
        # browsable HTML report to `./result/html/index.html`.
        #
        # Wired via crane's `cargoLlvmCov` (mirrors devrandom/bombay's
        # `packages.coverage`), using the version-matched `llvm-cov`/
        # `llvm-profdata` from the `llvm-tools-preview` toolchain component
        # already pinned in rust-toolchain.toml. `commonArgs.cargoExtraArgs`
        # already carries `--all-features` (not `--workspace`, which bombay
        # uses, since cesr is a SINGLE crate whose six modules — `b64`, `core`,
        # `crypto`, `stream`, `keri`, `serder` — are all feature-gated); crane
        # appends `cargoLlvmCovExtraArgs` to that same invocation, so repeating
        # `--all-features` here would pass the flag twice and fail cargo.
        packages =
          let
            covLlvm = craneLib.cargoLlvmCov (
              commonArgs
              // {
                inherit cargoArtifacts;
                cargoLlvmCovCommand = "test";
                cargoLlvmCovExtraArgs = "--html --output-dir $out";
              }
            );
          in
          {
            coverage-llvm = covLlvm;
            coverage = covLlvm;
          };

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
            just
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
