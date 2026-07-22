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
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
