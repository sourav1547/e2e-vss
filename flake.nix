{
  description = "Builds the Mixed-VSS CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        craneLib = crane.lib.${system};

        # Filters out non-rust sources
        sourceFilter = with pkgs; name: type: let baseName = baseNameOf (toString name); in ! (
          (type == "directory" && baseName == "target") ||
          (type == "directory" && baseName == "out") ||
          (type == "directory" && baseName == ".idea") ||
          (type == "directory" && baseName == "tmp") ||
          (type == "directory" && baseName == "aws") ||
          (type == "file" && baseName == "flake.lock") ||
          lib.hasSuffix ".nix" baseName ||
          lib.hasSuffix ".md" baseName
        );

        # Common derivation arguments used for all builds
        commonArgs = with pkgs.lib; {
          pname = "cli";          
          src = cleanSourceWith {
            filter = sourceFilter;
            src = cleanSource ./.;  # Basic filter removing .git/, result etc.
          };
        };

        # Build *just* the cargo dependencies, so we can reuse
        # all of that work (e.g. via cachix) when running in CI
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself, reusing the dependency
        # artifacts from above.
        cli = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

      in
      {
        checks = {
          inherit cli;
        };

        packages.default = cli;
      });
}