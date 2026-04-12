{
  description = "APDU - Go APDU encoding and decoding library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    systems.url = "github:nix-systems/default";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = import inputs.systems;

      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          treefmtEval = inputs.treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
        in
        {
          devShells.default = pkgs.callPackage ./nix/devshell.nix {
            inherit (self') packages;
            treefmt = treefmtEval.config.build.wrapper;
          };

          packages.default = pkgs.callPackage ./nix/apdu.nix { };

          formatter = treefmtEval.config.build.wrapper;

          checks.formatting = treefmtEval.config.build.check inputs.self;
        };
    };
}