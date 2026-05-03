{ config, pkgs, lib, nix-bitcoin, ... }:

# Example host configuration for a podcast members feed server.
# This wires together:
#   - nix-bitcoin: Bitcoin Core, LND, BTCPay Server, nbxplorer
#   - Alby Hub: LND management interface (via container)
#   - The podcast token service
#   - nginx with TLS (Let's Encrypt)
#   - Tailscale (for the Umbrel path — optional on a dedicated VPS)
#   - sops-nix for secret management
#
# Replace all values marked FIXME before deploying.

{
  imports = [];

  # ---------------------------------------------------------------------------
  # Basic system
  # ---------------------------------------------------------------------------

  networking.hostName = "podcast-node";  # FIXME

  # Open ports for Bitcoin and Lightning peer connections.
  # nginx handles 80/443 — no need to open those here, nix-bitcoin does it.
  networking.firewall.allowedTCPPorts = [
    8333   # Bitcoin Core peer connections
    9735   # LND peer connections
  ];

  # ---------------------------------------------------------------------------
  # nix-bitcoin: Bitcoin Core, LND, BTCPay Server
  # ---------------------------------------------------------------------------

  # Required by nix-bitcoin for automated secret generation
  nix-bitcoin.generateSecrets = true;

  # Allow your admin user to use bitcoin-cli, lncli, etc.
  nix-bitcoin.operator = {
    enable = true;
    name   = "admin";  # FIXME: your admin username
  };

  services.bitcoind = {
    enable = true;
    # A full node is recommended for sovereignty and reliability.
    # For a pruned node, uncomment and set an appropriate prune target (MiB):
    # extraConfig = ''
    #   prune=10000
    # '';
  };

  services.lnd = {
    enable = true;
    # nix-bitcoin wires LND to bitcoind automatically.
    # Alby Hub connects to LND via the macaroon and TLS cert that
    # nix-bitcoin generates at /etc/nix-bitcoin-secrets/lnd-*.
    extraConfig = ''
      [Application Options]
      # Advertise the public IP of this server for Lightning peer discovery.
      # Replace with your actual public IP or domain.
      externalip=YOUR_PUBLIC_IP  # FIXME

      [tor]
      # Optional: enable Tor for outbound connections
      # tor.active=true
    '';
  };

  services.btcpayserver = {
    enable          = true;
    lightningBackend = "lnd";
  };

  # ---------------------------------------------------------------------------
  # Alby Hub (LND management interface)
  #
  # Alby Hub is not packaged in nixpkgs. Run it as a container alongside
  # nix-bitcoin's LND. It connects to LND via the socket and credentials
  # that nix-bitcoin generates.
  #
  # The LND credentials nix-bitcoin generates are at:
  #   TLS cert:  /etc/nix-bitcoin-secrets/lnd-cert
  #   Macaroon:  /etc/nix-bitcoin-secrets/lnd-admin-macaroon
  #   RPC addr:  127.0.0.1:10009
  # ---------------------------------------------------------------------------

  virtualisation.oci-containers.containers.alby-hub = {
    image  = "ghcr.io/getalbyhub/albyhub:latest";
    ports  = [ "127.0.0.1:8080:8080" ];
    volumes = [
      "/var/lib/alby-hub:/data"
      # Mount LND credentials read-only so Alby Hub can connect
      "/etc/nix-bitcoin-secrets/lnd-cert:/lnd/tls.cert:ro"
      "/etc/nix-bitcoin-secrets/lnd-admin-macaroon:/lnd/admin.macaroon:ro"
    ];
    environment = {
      LND_ADDRESS      = "127.0.0.1:10009";
      LND_CERT_FILE    = "/lnd/tls.cert";
      LND_MACAROON_FILE = "/lnd/admin.macaroon";
    };
  };

  # BTCPay connects to Alby Hub. Configure the connection string in the
  # BTCPay admin UI after both services are running:
  #   Server Settings > Lightning > LND REST  http://127.0.0.1:8080
  # or use the LNDHub connection string Alby Hub provides.

  # ---------------------------------------------------------------------------
  # Podcast token service
  # ---------------------------------------------------------------------------

  services.podcastTokenService = {
    enable          = true;
    package         = pkgs.podcast-token-service;
    # sops-nix decrypts this file at runtime — never commit plaintext secrets
    environmentFile = config.sops.secrets."podcast-token-service-env".path;
    port            = 8765;
  };

  # ---------------------------------------------------------------------------
  # nginx with TLS
  # ---------------------------------------------------------------------------

  services.nginx = {
    enable = true;

    # These recommended settings apply globally and eliminate the need to
    # manually set proxy_set_header in every location block.
    recommendedProxySettings  = true;
    recommendedTlsSettings    = true;
    recommendedGzipSettings   = true;
    recommendedOptimisation   = true;

    # Stream proxy for Bitcoin and Lightning peer connections.
    # Forwards incoming TCP on 8333/9735 to the local services.
    # This is the same pattern described in:
    # https://beanbag.technicalissues.us/proxying-bitcoin-core-lnd-with-tailscale-nginx/
    streamConfig = ''
      server {
        listen 0.0.0.0:8333;
        listen [::]:8333;
        proxy_pass 127.0.0.1:8333;
      }
      server {
        listen 0.0.0.0:9735;
        listen [::]:9735;
        proxy_pass 127.0.0.1:9735;
      }
    '';

    virtualHosts."members.yourpodcast.com" = {  # FIXME
      enableACME = true;
      forceSSL   = true;

      # Token service endpoints
      locations."/rss/" = {
        proxyPass = "http://127.0.0.1:${toString config.services.podcastTokenService.port}";
      };
      locations."/webhook/btcpay" = {
        proxyPass = "http://127.0.0.1:${toString config.services.podcastTokenService.port}";
      };
      locations."/api/feed-url" = {
        proxyPass = "http://127.0.0.1:${toString config.services.podcastTokenService.port}";
      };
      locations."/health" = {
        proxyPass = "http://127.0.0.1:${toString config.services.podcastTokenService.port}";
      };

      # Admin endpoints are localhost-only — not exposed through nginx
    };
  };

  # Allow nginx to read ACME certificates
  security.acme = {
    acceptTerms = true;
    defaults.email = "you@yourpodcast.com";  # FIXME
  };

  # ---------------------------------------------------------------------------
  # Tailscale
  #
  # Optional: use if this server proxies for an Umbrel running elsewhere,
  # or if you want to access Bitcoin/LND management interfaces remotely
  # without exposing them to the public internet.
  # ---------------------------------------------------------------------------

  services.tailscale = {
    enable       = true;
    authKeyFile  = config.sops.secrets.tailscale_key.path;
    extraUpFlags = [
      "--advertise-exit-node"
      "--operator" "admin"  # FIXME: match nix-bitcoin.operator.name
      "--ssh"
    ];
    useRoutingFeatures = "both";
  };

  # ---------------------------------------------------------------------------
  # sops-nix secret management
  #
  # Store secrets encrypted in your repo. sops-nix decrypts them at
  # activation time using an age key on the host.
  #
  # To create secrets:
  #   nix run nixpkgs#sops -- -e secrets.yaml > secrets.enc.yaml
  # ---------------------------------------------------------------------------

  sops = {
    age.keyFile     = "/root/.config/sops/age/keys.txt";  # FIXME: your key path
    defaultSopsFile = ../../secrets.yaml;  # FIXME: path to your encrypted secrets

    secrets = {
      "podcast-token-service-env" = {
        # sops-nix writes the decrypted file to a path in /run/secrets/
        # The environmentFile option in the service module points here.
      };
      tailscale_key = {
        restartUnits = [ "tailscaled-autoconnect.service" ];
      };
    };
  };

  # ---------------------------------------------------------------------------
  # State and storage
  # ---------------------------------------------------------------------------

  # Ensure persistent storage directories exist with correct ownership.
  # nix-bitcoin manages its own data directories automatically.
  systemd.tmpfiles.rules = [
    "d /var/lib/alby-hub 0750 root root -"
  ];
}
