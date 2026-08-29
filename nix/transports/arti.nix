# arti transport as a self-contained flake-parts module: it exports a crane
# build of the plugin binary the VM e2e drives as a subprocess.
{ inputs, ... }:
{
  perSystem = { system, ... }:
    let
      # Same shared crane wiring the main flake uses, so cargoArtifacts is the
      # very same derivation and the workspace deps are not rebuilt per module.
      crane = import ../lib/crane.nix { inherit inputs system; };
    in
    {
      packages.fungi-arti-plugin = crane.buildCrate {
        pname = "fungi-arti-plugin";
        crate = "fungi-transport-arti";
        bin = "fungi-arti-plugin";
      };
    };
}
