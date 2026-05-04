# podcast-members-feed

Reference implementation for the architecture described in:

**[Lightning-Gated Podcast Members Feeds with BTCPay Server](#)**
*(link added when article is published)*

Self-hosted Bitcoin-native podcast membership using BTCPay Server subscriptions,
private RSS feeds, and a small token service that bridges the two.

## Repository layout

```
pkgs/podcast-token-service/   Python service + CLI (token_service.py, podcast_members_manage.py)
modules/services/             NixOS module
nixos-configurations/         Complete example host configuration
podman/                       Podman Compose setup for Path A (Umbrel + VPS)
alerts/                       Prometheus/AlertManager rules
.github/workflows/            GitHub Actions: build and push container image
```

## Deployment paths

### Path A: Umbrel + VPS

For people already running Umbrel or who want a quick start.
BTCPay, LND, and Alby Hub run on Umbrel. The token service runs as
a Podman container on a small VPS connected via Tailscale.

```bash
git clone https://github.com/genebean/podcast-members-feed.git
cd podcast-members-feed/podman
cp .env.example .env
# Edit .env with your values
podman pull ghcr.io/genebean/podcast-members-feed:latest
podman compose up -d
```

### Path B: NixOS

For a fully declarative production setup using nix-bitcoin.

Add as a flake input:

```nix
inputs = {
  podcast-members-feed.url = "github:genebean/podcast-members-feed";
  # Follow through for consistent nixpkgs
  nixpkgs.follows          = "podcast-members-feed/nixpkgs";
  nixpkgs-unstable.follows = "podcast-members-feed/nixpkgs-unstable";
};
```

Import the module and enable the service:

```nix
imports = [ podcast-members-feed.nixosModules.podcast-token-service ];

services.podcastTokenService = {
  enable          = true;
  package         = pkgs.podcast-token-service;
  environmentFile = config.sops.secrets."podcast-token-service-env".path;
};
```

See `nixos-configurations/example-host/configuration.nix` for a complete
example including nix-bitcoin, Alby Hub, nginx, TLS, Tailscale, and sops-nix.

After cloning, generate the lock file before building:

```bash
nix flake update
git add flake.lock
```

## Management CLI

The `podcast-members-manage` command is installed alongside the service.

```bash
# NixOS
podcast-members-manage stats
podcast-members-manage subscribers --active
podcast-members-manage subscribers --expiring-days 7
podcast-members-manage feed-url --email subscriber@example.com
podcast-members-manage revoke <btcpay-subscriber-id>

# Podman (Path A)
podman exec podcast-token-service \
  podcast-members-manage \
  --db /var/lib/podcast-token-service/tokens.db \
  stats
```

## Monitoring

The service exposes Prometheus metrics at `/metrics` with bearer token auth.

Example scrape config:

```yaml
- job_name: podcast_token_service
  bearer_token: YOUR_ADMIN_TOKEN
  static_configs:
    - targets: ["members.yourpodcast.com"]
  scheme: https
```

AlertManager rules are in `alerts/podcast-members-feed.rules.yml`.
Include in Prometheus:

```yaml
rule_files:
  - /etc/prometheus/rules/podcast-members-feed.rules.yml
```

On NixOS:

```nix
services.prometheus.ruleFiles = [
  ./alerts/podcast-members-feed.rules.yml
];
```

## Building the container locally

```bash
nix build .#dockerImage
podman load < result
podman run --rm -p 8765:8765 \
  --env-file podman/.env \
  podcast-token-service:latest
```

## Requirements

`libsecp256k1` must be available as a system library:
- NixOS: provided by `pkgs.secp256k1` via the derivation
- The Podman image handles this automatically

## License

MIT
