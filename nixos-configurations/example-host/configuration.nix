{ config, pkgs, lib, nix-bitcoin, ... }:

# Complete example NixOS host configuration for the podcast members feed.
#
# Wires together:
#   - nix-bitcoin: Bitcoin Core, LND, BTCPay Server, nbxplorer
#   - Alby Hub: LND management interface (Podman container)
#   - Podcast token service
#   - nginx with TLS (Let's Encrypt / ACME)
#   - Tailscale
#   - sops-nix for secret management
#
# Replace all FIXME values before deploying.
# Run `nix flake update` after cloning to generate flake.lock.

{
  imports = [];

  # ---------------------------------------------------------------------------
  # Basic system
  # ---------------------------------------------------------------------------

  networking.hostName = "podcast-node";  # FIXME

  # Bitcoin and Lightning peer connections.
  # These are ecosystem-supporting: making your node publicly reachable
  # helps the Bitcoin and Lightning networks. They are not required for
  # the membership system to function — remove them if you prefer a
  # private node.
  networking.firewall.allowedTCPPorts = [ 80 443 8333 9735 ];

  # ---------------------------------------------------------------------------
  # Podman — default container backend for all oci-containers
  # ---------------------------------------------------------------------------

  virtualisation.oci-containers.backend = "podman";

  # ---------------------------------------------------------------------------
  # nix-bitcoin: Bitcoin Core, LND, BTCPay Server
  #
  # nixpkgs follows nix-bitcoin's pinned versions — see flake.nix.
  # Do not override with your own nixpkgs.
  # ---------------------------------------------------------------------------

  nix-bitcoin.generateSecrets = true;
  nix-bitcoin.operator = {
    enable = true;
    name   = "admin";  # FIXME: your admin username
  };

  services.bitcoind = {
    enable = true;
    # Full node is recommended. For a pruned node — useful when disk
    # space is constrained or when you already run a full node elsewhere
    # but want this stack self-contained — uncomment and set a prune
    # target in MiB (10000 ≈ 10 GB):
    # extraConfig = ''
    #   prune=10000
    # '';
  };

  services.lnd = {
    enable = true;
    # nix-bitcoin wires LND to bitcoind automatically and generates
    # credentials at /etc/nix-bitcoin-secrets/.
    extraConfig = ''
      [Application Options]
      # Advertise your public IP so Lightning peers can find your node.
      # This is ecosystem-supporting but not required.
      externalip=YOUR_PUBLIC_IP  # FIXME — or remove this line
    '';
  };

  services.btcpayserver = {
    enable           = true;
    lightningBackend = "lnd";
  };

  # ---------------------------------------------------------------------------
  # Alby Hub
  #
  # Provides a management interface over LND for channel management,
  # liquidity, and the connection string BTCPay uses. Runs as a Podman
  # container alongside nix-bitcoin's LND.
  #
  # After both services are running, configure BTCPay to connect to
  # Alby Hub: Server Settings > Lightning > paste the connection string
  # from the Alby Hub interface.
  # ---------------------------------------------------------------------------

  virtualisation.oci-containers.containers.alby-hub = {
    image  = "ghcr.io/getalbyhub/albyhub:latest";
    ports  = [ "127.0.0.1:8080:8080" ];
    volumes = [
      "/var/lib/alby-hub:/data"
      # Mount nix-bitcoin LND credentials read-only
      "/etc/nix-bitcoin-secrets/lnd-cert:/lnd/tls.cert:ro"
      "/etc/nix-bitcoin-secrets/lnd-admin-macaroon:/lnd/admin.macaroon:ro"
    ];
    environment = {
      LND_ADDRESS       = "127.0.0.1:10009";
      LND_CERT_FILE     = "/lnd/tls.cert";
      LND_MACAROON_FILE = "/lnd/admin.macaroon";
    };
  };

  # ---------------------------------------------------------------------------
  # Podcast token service
  # ---------------------------------------------------------------------------

  services.podcastTokenService = {
    enable          = true;
    package         = pkgs.podcast-token-service;
    environmentFile = config.sops.secrets."podcast-token-service-env".path;
    port            = 8765;
  };

  # ---------------------------------------------------------------------------
  # nginx with TLS
  #
  # recommendedProxySettings = true applies proxy headers globally —
  # individual location blocks do not need manual proxy_set_header.
  #
  # The stream proxy forwards Bitcoin and Lightning peer connections.
  # See: https://beanbag.technicalissues.us/proxying-bitcoin-core-lnd-with-tailscale-nginx/
  # Remove the streamConfig block if you do not want a publicly reachable node.
  # ---------------------------------------------------------------------------

  services.nginx = {
    enable = true;

    recommendedProxySettings = true;
    recommendedTlsSettings   = true;
    recommendedGzipSettings  = true;
    recommendedOptimisation  = true;

    # TCP stream proxy for Bitcoin and Lightning peer connections.
    # On a dedicated server bitcoind and lnd are local (127.0.0.1).
    # If this server is the VPS proxy for a remote Umbrel over Tailscale,
    # replace 127.0.0.1 with the Umbrel's Tailscale IP.
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

      locations = let
        svc = "http://127.0.0.1:${toString config.services.podcastTokenService.port}";
      in {
        "/rss/".proxyPass          = svc;
        "/webhook/btcpay".proxyPass = svc;
        "/api/feed-url".proxyPass  = svc;
        "/recover".proxyPass       = svc;
        "/health".proxyPass        = svc;

        # /metrics is open to all interfaces but requires bearer token auth
        # (enforced by the service itself). Prometheus scrapes this from
        # your monitoring host.
        "/metrics".proxyPass = svc;

        # /admin/ is localhost-only — not exposed through nginx at all.
        # Access via: curl -H "Authorization: Bearer $ADMIN_TOKEN" \
        #   http://127.0.0.1:8765/admin/cleanup
      };
    };
  };

  security.acme = {
    acceptTerms    = true;
    defaults.email = "you@yourpodcast.com";  # FIXME
  };

  # ---------------------------------------------------------------------------
  # Tailscale
  #
  # Enables remote access to management interfaces without exposing them
  # publicly, and provides the exit node for an Umbrel running elsewhere.
  # ---------------------------------------------------------------------------

  services.tailscale = {
    enable             = true;
    authKeyFile        = config.sops.secrets.tailscale-auth-key.path;
    useRoutingFeatures = "both";
    extraUpFlags       = [
      "--advertise-exit-node"
      "--operator=admin"  # FIXME: match nix-bitcoin.operator.name
      "--ssh"
    ];
  };

  # ---------------------------------------------------------------------------
  # sops-nix secret management
  # ---------------------------------------------------------------------------

  sops = {
    age.keyFile     = "/root/.config/sops/age/keys.txt";  # FIXME
    defaultSopsFile = ../../secrets.yaml;                  # FIXME

    secrets = {
      "podcast-token-service-env" = {};
      tailscale-auth-key = {
        restartUnits = [ "tailscaled-autoconnect.service" ];
      };
    };
  };

  # ---------------------------------------------------------------------------
  # State directories
  # ---------------------------------------------------------------------------

  systemd.tmpfiles.rules = [
    "d /var/lib/alby-hub 0750 root root -"
  ];
}
