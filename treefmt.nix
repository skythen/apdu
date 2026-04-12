{ pkgs, ... }:
let
  golangci-lint-wrapped = pkgs.writeShellApplication {
    name = "golangci-lint";
    runtimeInputs = [
      pkgs.go
      pkgs.golangci-lint
    ];
    text = ''
      export GOROOT="${pkgs.go}/share/go"
      golangci-lint run --fix ./...
    '';
  };
in
{
  projectRootFile = "flake.nix";

  programs.gofumpt.enable = true;

  settings.formatter.golangci-lint = {
    command = "${pkgs.lib.getExe golangci-lint-wrapped}";
    includes = [ "*.go" ];
  };
}