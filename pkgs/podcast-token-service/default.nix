{ lib
, buildGoModule
}:

buildGoModule {
  pname   = "podcast-token-service";
  version = "0.1.0";

  # Source is the repository root — go.mod lives there.
  src = ../..;

  # vendorHash = null tells buildGoModule to use the committed vendor/ directory.
  # Run `go mod vendor` and commit the result after any dependency change.
  vendorHash = null;

  # Build both binaries from their respective cmd/ packages.
  subPackages = [
    "cmd/podcast-token-service"
    "cmd/podcast-members-manage"
  ];

  meta = {
    description = "BTCPay subscription webhook to private podcast RSS feed bridge";
    longDescription = ''
      Receives BTCPay Server subscription webhooks, issues and manages
      tokenized private RSS feed URLs, proxies the members feed from
      PodServer, delivers feed URLs via email and NIP-04 Nostr DM, and
      exposes Prometheus metrics for monitoring and alerting.

      Installs two commands:
        podcast-token-service   - the HTTP service (listen on 127.0.0.1:8765)
        podcast-members-manage  - management and testing CLI

      Pure Go — no libsecp256k1 or other native library dependency.
      Nostr cryptography is handled by github.com/nbd-wtf/go-nostr.
    '';
    license   = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
