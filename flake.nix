{
  description = "Fungi implementation monorepo";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };
  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # x86_64-darwin is omitted: nixpkgs 26.11 dropped support for it.
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      # The VM test and each transport are their own flake-parts modules.
      imports = [
        ./nix/checks/tor-e2e.nix
        ./nix/transports/socks5h.nix
        ./nix/transports/arti.nix
      ];
      perSystem = { system, ... }:
        let
          # Shared crane wiring lives in one helper so the main flake and every
          # transport module derive an identical craneLib/commonArgs/cargoArtifacts.
          crane = import ./nix/lib/crane.nix { inherit inputs system; };
          inherit (crane) pkgs rustToolchain craneLib commonArgs cargoArtifacts buildCrate;
          # The generic test-network driver: a binary in the capnp crate that
          # spawns each backend as a plugin subprocess and drives it over the
          # Transport trait. It links no backend, so it lives with the plugin
          # client machinery rather than in a crate of its own.
          harness = buildCrate { pname = "harness"; crate = "fungi-transport-capnp"; bin = "harness"; };
        in {
          packages.harness = harness;
          packages.default = harness;

          devShells.default = pkgs.mkShell {
            packages = [ rustToolchain pkgs.just pkgs.cargo-nextest ];
          };

          # `nix flake check` runs all of these; on x86_64-linux the VM test
          # (defined in the imported module) joins them.
          checks = {
            nextest = craneLib.cargoNextest (commonArgs // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
            });
            clippy = craneLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            });
            fmt = craneLib.cargoFmt { inherit (commonArgs) src; };
            doc = craneLib.cargoDoc (commonArgs // {
              inherit cargoArtifacts;
              # Deny rustdoc warnings so a broken intra-doc link fails the check.
              env.RUSTDOCFLAGS = "-D warnings";
            });
          };
        };
    };
}
