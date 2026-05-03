{
  description = "Lightning-gated podcast members feed token service";

  inputs = {
    # Follow nix-bitcoin's nixpkgs — it pins versions it has tested against.
    # Do not override this with your own nixpkgs.
    nix-bitcoin.url = "github:fort-nix/nix-bitcoin/release";
    nixpkgs.follows = "nix-bitcoin/nixpkgs";
    nixpkgs-unstable.follows = "nix-bitcoin/nixpkgs-unstable";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, nix-bitcoin, flake-utils, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        # The token service Python application
        packages.podcast-token-service =
          pkgs.callPackage ./pkgs/podcast-token-service {};

        # Docker image — built with nix, pushed via GitHub Actions
        packages.dockerImage = pkgs.dockerTools.buildLayeredImage {
          name   = "podcast-token-service";
          tag    = "latest";
          contents = [
            self.packages.${system}.podcast-token-service
            pkgs.cacert  # needed for outbound TLS (relay connections, feed fetch)
          ];
          config = {
            Cmd = [
              "${self.packages.${system}.podcast-token-service}/bin/podcast-token-service"
              "--host" "0.0.0.0"
              "--port" "8765"
            ];
            ExposedPorts = { "8765/tcp" = {}; };
            Volumes = { "/var/lib/podcast-token-service" = {}; };
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };

        packages.default = self.packages.${system}.podcast-token-service;
      }
    ) // {
      # NixOS module — importable as a flake input
      nixosModules.podcast-token-service =
        import ./modules/services/podcast-token-service.nix;

      nixosModules.default = self.nixosModules.podcast-token-service;

      # Example host configuration
      nixosConfigurations.example-host = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = { inherit nix-bitcoin; };
        modules = [
          nix-bitcoin.nixosModules.default
          self.nixosModules.podcast-token-service
          ./nixos-configurations/example-host/configuration.nix
          {
            nixpkgs.overlays = [
              (final: prev: {
                podcast-token-service =
                  self.packages."x86_64-linux".podcast-token-service;
              })
            ];
          }
        ];
      };
    };
}
