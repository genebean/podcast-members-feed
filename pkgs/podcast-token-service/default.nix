{ lib
, python3Packages
, pkg-config
, secp256k1
}:

let
  # Bundle the CLI tool alongside the main service in the same derivation.
  # Both are installed as scripts: podcast-token-service and podcast-members-manage.
  combinedSrc = ./.;
in python3Packages.buildPythonApplication {
  pname   = "podcast-token-service";
  version = "0.1.0";
  src     = combinedSrc;
  format  = "pyproject";

  nativeBuildInputs = [
    pkg-config
    python3Packages.setuptools
  ];

  # libsecp256k1 is used via ctypes for Schnorr signing/verification and
  # raw ECDH. All other dependencies are pure Python available in nixpkgs.
  buildInputs = [ secp256k1 ];

  propagatedBuildInputs = with python3Packages; [
    fastapi
    uvicorn
    aiosqlite
    httpx
    python-dotenv
    cryptography      # AES-CBC for NIP-04 message encryption
    cffi              # ctypes support for libsecp256k1
    websockets        # Nostr relay communication
    prometheus-client # /metrics endpoint
  ];

  preBuild = ''
    export PKG_CONFIG_PATH="${secp256k1}/lib/pkgconfig"
  '';

  pythonImportsCheck = [ "token_service" ];

  meta = {
    description = "BTCPay subscription webhook to private podcast RSS feed bridge";
    longDescription = ''
      Receives BTCPay Server subscription webhooks, issues and manages
      tokenized private RSS feed URLs, proxies the members feed from
      PodServer, delivers feed URLs via email and NIP-04 Nostr DM, and
      exposes Prometheus metrics for monitoring and alerting.

      Installs two commands:
        podcast-token-service   - the FastAPI service
        podcast-members-manage  - management CLI
    '';
    license   = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
