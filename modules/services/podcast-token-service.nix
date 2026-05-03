{ config, lib, pkgs, ... }:

let
  cfg = config.services.podcastTokenService;
in {
  options.services.podcastTokenService = {
    enable = lib.mkEnableOption "podcast members feed token service";

    package = lib.mkOption {
      type        = lib.types.package;
      description = "The podcast-token-service package.";
    };

    environmentFile = lib.mkOption {
      type        = lib.types.path;
      description = ''
        Path to a file containing environment variable secrets, decrypted
        at runtime by sops-nix or agenix.

        Required variables:
          BTCPAY_WEBHOOK_SECRET   shared secret from BTCPay webhook settings
          PODSERVER_FEED_URL      internal URL of the PodServer members feed
          FEED_BASE_URL           public base URL for subscriber feed URLs
          SMTP_HOST               SMTP server hostname
          SMTP_PORT               SMTP server port (default: 587)
          SMTP_USER               SMTP username
          SMTP_PASSWORD           SMTP password
          SMTP_FROM               From address for delivery emails
          NOSTR_PRIVATE_KEY       nsec or hex key for the service Nostr keypair

        Optional:
          DATABASE_PATH           override the default database path
      '';
    };

    databasePath = lib.mkOption {
      type        = lib.types.str;
      default     = "/var/lib/podcast-token-service/tokens.db";
      description = "Path to the SQLite database file.";
    };

    port = lib.mkOption {
      type        = lib.types.port;
      default     = 8765;
      description = "Port to listen on (127.0.0.1 only — nginx proxies externally).";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.podcast-token-service = {
      description = "Podcast members feed token service";
      wantedBy    = [ "multi-user.target" ];
      after       = [ "network.target" "btcpayserver.service" ];

      serviceConfig = {
        Type            = "simple";
        DynamicUser     = true;
        StateDirectory  = "podcast-token-service";
        EnvironmentFile = cfg.environmentFile;
        Environment     = [ "DATABASE_PATH=${cfg.databasePath}" ];

        ExecStart = lib.escapeShellArgs [
          "${cfg.package}/bin/podcast-token-service"
          "--host" "127.0.0.1"
          "--port" (toString cfg.port)
        ];

        Restart    = "on-failure";
        RestartSec = "5s";

        # Systemd hardening — aligned with nix-bitcoin service conventions
        NoNewPrivileges         = true;
        ProtectSystem           = "strict";
        ProtectHome             = true;
        PrivateTmp              = true;
        PrivateDevices          = true;
        ProtectKernelTunables   = true;
        ProtectKernelModules    = true;
        ProtectControlGroups    = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces      = true;
        LockPersonality         = true;
        MemoryDenyWriteExecute  = true;
        ReadWritePaths          = [ "/var/lib/podcast-token-service" ];
      };
    };

    # Weekly cleanup timer — removes tokens expired > 90 days ago
    systemd.timers.podcast-token-cleanup = {
      wantedBy    = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "weekly";
        Persistent = true;
      };
    };

    systemd.services.podcast-token-cleanup = {
      description     = "Podcast token service periodic cleanup";
      serviceConfig   = {
        Type      = "oneshot";
        ExecStart = "${pkgs.curl}/bin/curl -sf -X POST http://127.0.0.1:${toString cfg.port}/admin/cleanup";
      };
    };
  };
}
