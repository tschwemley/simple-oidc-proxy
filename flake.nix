{
  description = "KISS OIDC Authentication Proxy.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/master";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      flake-parts,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
      ];

      perSystem =
        {
          config,
          pkgs,
          system,
          ...
        }:
        {
          # makes pkgs available to all perSystem functions
          _module.args.pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
              air
              go
              nodejs
              sqlc
              tailwindcss
              templ
            ];
          };

          packages.default = pkgs.buildGoModule {
            name = "oidc-sso";
            src = ./.;
            vendorHash = "sha256-XN8Q0NASGpbfAeT5RI1gxfwLBcpaMq4MjT5xnNw4zuU=";
          };
        };

    };
}
