# podcast-members-feed

Reference implementation for the architecture described in:

**[Lightning-Gated Podcast Members Feeds with BTCPay Server](#)**  
*(link to be added when the article is published)*

This repository contains:

- `pkgs/podcast-token-service/` — the token service Python application
- `modules/services/podcast-token-service.nix` — NixOS module
- `nixos-configurations/example-host/` — complete example host configuration
- `docker/` — Docker Compose setup for the Umbrel + VPS deployment path
- `.github/workflows/container.yml` — GitHub Actions workflow to build and push the container image to ghcr.io

## Quick start

### Path A: Umbrel + VPS

See the article. In brief:

1. Set up Tailscale between your Umbrel and a VPS
2. Copy `docker/compose.yml` and `docker/.env.example` to your VPS
3. Fill in `.env`
4. Pull the image: `docker pull ghcr.io/YOUR_ORG/podcast-token-service:latest`
5. `docker compose up -d`

### Path B: NixOS

Add this repo as a flake input:

```nix
inputs.podcast-members-feed = {
  url = "github:YOUR_ORG/podcast-members-feed";
  inputs.nixpkgs.follows = "nix-bitcoin/nixpkgs";
};
```

Import the module and configure the service:

```nix
imports = [ podcast-members-feed.nixosModules.podcast-token-service ];

services.podcastTokenService = {
  enable          = true;
  package         = pkgs.podcast-token-service;
  environmentFile = config.sops.secrets."podcast-token-service-env".path;
};
```

See `nixos-configurations/example-host/configuration.nix` for a complete
example including nix-bitcoin, nginx, TLS, Tailscale, and sops-nix.

## Building the container locally

```bash
nix build .#dockerImage
docker load < result
docker run --rm -p 8765:8765 --env-file docker/.env podcast-token-service:latest
```

## Requirements

- `libsecp256k1` must be available as a system library
  - NixOS: provided by `pkgs.secp256k1` via the Nix derivation
  - Debian/Ubuntu: `apt install libsecp256k1-dev`
  - Alpine: `apk add secp256k1-dev`

## License

MIT
