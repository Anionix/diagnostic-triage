{
  description = "Policy-aware diagnostic normalization and verification";

  inputs = {
    # Nixpkgs 26.11 dropped x86_64-darwin; v1 release support still includes it.
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-26.05-darwin";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      leanToolchain = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ./lean-toolchain);
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      rustTargetFor = {
        aarch64-darwin = "aarch64-apple-darwin";
        aarch64-linux = "aarch64-unknown-linux-musl";
        x86_64-darwin = "x86_64-apple-darwin";
        x86_64-linux = "x86_64-unknown-linux-musl";
      };
      version = "0.1.0-alpha.1";
      binaryNames = [
        "diagnostic-triage"
        "diagnostic-triage-observer-github-actions"
        "diagnostic-triage-provider-biome"
        "diagnostic-triage-provider-python"
        "diagnostic-triage-provider-rust"
      ];
      releaseFor =
        system:
        let
          pkgs = pkgsFor system;
          rustTarget = rustTargetFor.${system};
          rust = pkgs.rust-bin.stable."1.85.1".default.override {
            targets = nixpkgs.lib.optionals pkgs.stdenv.isLinux [ rustTarget ];
          };
          rustScope = if pkgs.stdenv.isLinux then pkgs.pkgsStatic else pkgs;
          rustPlatform = rustScope.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          source = nixpkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: _type:
              let
                relative = nixpkgs.lib.removePrefix "${toString ./.}/" (toString path);
                name = baseNameOf (toString path);
                excludedTree =
                  relative == ".github"
                  || nixpkgs.lib.hasPrefix ".github/" relative
                  || relative == "tools"
                  || nixpkgs.lib.hasPrefix "tools/" relative;
                nonFixtureTest =
                  nixpkgs.lib.hasPrefix "tests/" relative
                  && relative != "tests/fixtures"
                  && !nixpkgs.lib.hasPrefix "tests/fixtures/" relative;
              in
              name != ".git" && name != "result" && name != "target" && !excludedTree && !nonFixtureTest;
          };
          package = rustPlatform.buildRustPackage {
            pname = "diagnostic-triage";
            inherit version;
            src = source;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--workspace"
              "--bins"
              "--locked"
            ];
            doCheck = false;
            installPhase = ''
              runHook preInstall
              install -d "$out/bin" "$out/share/diagnostic-triage"
              for binary in ${nixpkgs.lib.escapeShellArgs binaryNames}; do
                binary_path="$(find target -type f -path "*/release/$binary" -perm -0100 -print -quit)"
                test -n "$binary_path"
                install -m755 "$binary_path" "$out/bin/$binary"
              done
              cp -R schemas "$out/share/diagnostic-triage/schemas"
              cp -R tests/fixtures "$out/share/diagnostic-triage/fixtures"
              cp -R provenance "$out/share/diagnostic-triage/provenance"
              cp -R release "$out/share/diagnostic-triage/release"
              install -m644 LICENSE README.md flake.nix flake.lock "$out/share/diagnostic-triage/"
              runHook postInstall
            '';
          };
          archiveName = "diagnostic-triage-v${version}-${rustTarget}.tar.gz";
          archiveRoot = nixpkgs.lib.removeSuffix ".tar.gz" archiveName;
          releaseArchive =
            pkgs.runCommand "diagnostic-triage-release-${rustTarget}"
              {
                nativeBuildInputs = [
                  pkgs.coreutils
                  pkgs.findutils
                  pkgs.gnutar
                  pkgs.gzip
                ];
              }
              ''
                set -o pipefail
                install -d "$out" "$TMPDIR/${archiveRoot}"
                cp -R ${package}/bin "$TMPDIR/${archiveRoot}/bin"
                cp -R ${package}/share/diagnostic-triage/. "$TMPDIR/${archiveRoot}/"
                tar \
                  --sort=name \
                  --mtime="@1" \
                  --owner=0 \
                  --group=0 \
                  --numeric-owner \
                  -C "$TMPDIR" \
                  -cf - \
                  "${archiveRoot}" \
                  | gzip -n > "$out/${archiveName}"
              '';
        in
        {
          default = package;
          diagnostic-triage = package;
          release-archive = releaseArchive;
        };
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          python = pkgs.python3.withPackages (pythonPackages: [
            pythonPackages.jsonschema
            pythonPackages.pytest
          ]);
          rust = pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [
              "clippy"
              "rustfmt"
            ];
          };
          # Keep Elan/LSP and the Nix shell on one Lean release.
          lean =
            assert leanToolchain == "leanprover/lean4:v${pkgs.lean4.version}";
            pkgs.lean4;
        in
        {
          default = pkgs.mkShell {
            packages = [
              rust
              lean
              pkgs.jq
              pkgs.nixfmt
              pkgs.pyright
              pkgs.ruff
              pkgs.ty
              python
            ];
          };
          release = pkgs.mkShell {
            packages = [ pkgs.cosign ];
          };
        }
      );

      packages = forAllSystems releaseFor;
      checks = forAllSystems (system: {
        release-archive = (releaseFor system).release-archive;
      });
      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
