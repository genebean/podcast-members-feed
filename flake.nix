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
        # The token service Go application
        packages.podcast-token-service =
          pkgs.callPackage ./pkgs/podcast-token-service {
            inherit (pkgs) buildGoModule;
          };

        # Docker image — built with nix, pushed via GitHub Actions.
        # The Go binary is fully static; only cacert is needed for outbound TLS.
        packages.dockerImage = pkgs.dockerTools.buildLayeredImage {
          name   = "podcast-token-service";
          tag    = "latest";
          contents = [
            self.packages.${system}.podcast-token-service
            pkgs.cacert # needed for outbound TLS (relay connections, feed fetch)
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

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.gotools
            pkgs.golangci-lint
          ];

          shellHook = ''
            start-test-container() {
              nix build .#dockerImage
              podman load < result
              mkdir -p data
              podman run --rm \
                --name podcast-token-service \
                -p 127.0.0.1:8765:8765 \
                -v "$(pwd)/data:/var/lib/podcast-token-service" \
                -e BTCPAY_WEBHOOK_SECRET=testsecret \
                -e PODSERVER_FEED_URL=https://www.spreaker.com/show/6304648/episodes/feed \
                -e FEED_BASE_URL=http://localhost:8765 \
                -e ADMIN_TOKEN=testtoken \
                -e NOSTR_PRIVATE_KEY="$(openssl rand -hex 32)" \
                -e SMTP_HOST=localhost \
                -e DATABASE_PATH=/var/lib/podcast-token-service/tokens.db \
                localhost/podcast-token-service:latest
            }

            test-local-container() {
              local npub="$1"
              if [ -z "$npub" ]; then
                echo "Usage: test-local-container <npub>" >&2
                return 1
              fi
              FEED_BASE_URL=http://localhost:8765 \
              ADMIN_TOKEN=testtoken \
              go run ./cmd/podcast-members-manage \
                --db ./data/tokens.db \
                test-webhook \
                --webhook-secret testsecret \
                --npub "$npub" \
                --feed-url https://feeds.npr.org/500005/podcast.xml \
                --run-expiry-test
            }

            cleanup-test-container() {
              echo "Stopping container (if running)..."
              podman stop podcast-token-service 2>/dev/null || true
              echo "Removing image..."
              podman rmi localhost/podcast-token-service:latest 2>/dev/null || true
              echo "Removing nix result symlink..."
              rm -f result
              echo "Done."
            }

            export -f start-test-container
            export -f test-local-container
            export -f cleanup-test-container

            echo ""
            echo "Development commands available:"
            echo "  start-test-container          build image, load into podman, and run the service"
            echo "  test-local-container <npub>   run end-to-end test against the local container"
            echo "  cleanup-test-container        stop container and remove the local podman image"
            echo ""
          '';
        };
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
