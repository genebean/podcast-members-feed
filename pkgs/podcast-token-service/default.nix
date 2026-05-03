{ lib
, python3Packages
, pkg-config
, secp256k1
, stdenv
}:

python3Packages.buildPythonApplication {
  pname   = "podcast-token-service";
  version = "0.1.0";
  src     = ./.;
  format  = "pyproject";

  nativeBuildInputs = [
    pkg-config
    python3Packages.setuptools
  ];

  # secp256k1 is a system library used via cffi for Schnorr signing and
  # raw ECDH. All other deps are pure Python and available in nixpkgs.
  buildInputs = [ secp256k1 ];

  propagatedBuildInputs = with python3Packages; [
    fastapi
    uvicorn
    aiosqlite
    httpx
    python-dotenv
    cryptography  # AES-CBC for NIP-04 message encryption
    cffi          # bindings to libsecp256k1
    websockets    # Nostr relay communication
  ];

  # Tell cffi where to find libsecp256k1 at build time
  preBuild = ''
    export PKG_CONFIG_PATH="${secp256k1}/lib/pkgconfig"
  '';

  pythonImportsCheck = [ "token_service" ];

  meta = {
    description = "BTCPay subscription webhook to private podcast RSS feed bridge";
    longDescription = ''
      Receives BTCPay Server subscription webhooks, issues and manages
      tokenized private RSS feed URLs, proxies the members feed from
      PodServer, and delivers feed URLs via email and NIP-04 Nostr DM.
    '';
    license   = lib.licenses.mit;
    platforms = lib.platforms.linux;
  };
}
