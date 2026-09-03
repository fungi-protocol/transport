# Shared crane wiring, factored out so the main flake and each per-transport
# module derive an identical pkgs/craneLib/commonArgs/cargoArtifacts from one
# place. Called with { inputs, system }; returns the pieces each caller needs.
#
# Because commonArgs is identical across callers, `buildDepsOnly commonArgs`
# evaluates to the same derivation (same store path) everywhere, so the
# workspace dependencies are built exactly once and reused by the main flake's
# packages/checks and by every transport plugin build.
{ inputs, system }:
let
  pkgs = import inputs.nixpkgs {
    inherit system;
    overlays = [ inputs.rust-overlay.overlays.default ];
  };
  rustToolchain = pkgs.rust-bin.stable.latest.default.override {
    extensions = [ "clippy" "rustfmt" "rust-analyzer" "rust-src" ];
  };
  craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;
  # Shared build inputs. arti pulls a native sqlite; pkg-config finds it.
  # pname/version are set here because the workspace root manifest is virtual
  # (no [package]), so crane can't infer a name for the dependency and check
  # derivations.
  commonArgs = {
    # Like cleanCargoSource but also keeps inputs consumed at compile time:
    # Cap'n Proto schemas and the wire conformance vectors.
    src = pkgs.lib.cleanSourceWith {
      src = ../../.;
      name = "source";
      filter = path: type:
        (pkgs.lib.hasSuffix ".capnp" path)
        || (pkgs.lib.hasSuffix "/crates/fungi-wire/tests/vectors.json" path)
        || (craneLib.filterCargoSources path type);
    };
    pname = "fungi";
    version = "0.1.0";
    strictDeps = true;
    # capnproto: the transport-capnp crate's build script compiles channel.capnp.
    nativeBuildInputs = [ pkgs.pkg-config pkgs.capnproto ];
    buildInputs = [ pkgs.sqlite ];
  };
  # Build every workspace dependency once; reused by packages + checks.
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
  # Build a single workspace crate's binary as its own package. `bin` picks a
  # specific binary target when the crate ships more than its library (e.g. a
  # backend crate that also carries its plugin binary).
  buildCrate = { pname, crate, bin ? null }:
    craneLib.buildPackage (commonArgs // {
      inherit cargoArtifacts pname;
      cargoExtraArgs = "-p ${crate}" + (if bin != null then " --bin ${bin}" else "");
      doCheck = false; # tests run as the `nextest` check, not here
    });
in
{
  inherit pkgs rustToolchain craneLib commonArgs cargoArtifacts buildCrate;
}
