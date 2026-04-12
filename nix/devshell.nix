{
  pkgs,
  packages,
  treefmt,
}:
pkgs.mkShell {
  inputsFrom = [ packages.default ];
  packages = with pkgs; [
    go
    gopls
    gotools
    go-tools
    golangci-lint
    delve
    treefmt
  ];
}