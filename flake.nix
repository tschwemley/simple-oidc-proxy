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
              age
              air
              go
              nodejs
              sqlc
              sops
              tailwindcss
              templ
            ];

            shellHook = ''
              export GOPRIVATE=git.schwem.io
            '';
          };

          packages.default = pkgs.buildGo123Module {
            #__noChroot = true;

            name = "oidcsso";

            src = ./.;

            vendorHash = "sha256-/y4upXlHhq3Vuz5TgKxI+L35+aMoQVlu2A9OfzoyOx0=";
            preferLocal = true;

            # impureEnvVars = [
            #   "REPO_HOST"
            #   "REPO_USER"
            #   "REPO_PASS"
            # ];

            preBuild = # bash
              ''
                export HOME=$(mktemp -d)
                export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
                export SOPS_AGE_KEY_FILE=/etc/sops/age-keys.txt

                source <(${pkgs.sops}/bin/sops -d ${./build.env})
                echo $REPO_HOST

                mkdir -p ~/.ssh/

                cat > ~/.ssh/known_hosts <<EOF
                git.schwem.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjkwVwr1iP35frNmaaB+eW63+m8ExKtQ5OA8qen4dz0
                EOF

                cat > ~/.netrc <<EOF
                  machine $REPO_HOST
                    login $REPO_USER
                    password $REPO_PASS
                EOF
              '';

            GOPRIVATE = "git.schwem.io";
          };
        };
    };
}
