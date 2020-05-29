{ pkgs ? import <nixpkgs> {}
}:

pkgs.stdenv.mkDerivation rec {
  name = "rfc5077";
  src = pkgs.nix-gitignore.gitignoreSource [] ./.;

  buildInputs = [
    pkgs.openssl
    pkgs.gnutls
    pkgs.nss
    pkgs.libpcap
    pkgs.libev
    pkgs.pkg-config
  ];
  buildPhase = "make";
  installPhase = ''
    mkdir -p $out/bin
    cp *-client *-server *-pcap $out/bin
  '';
  outputs = [ "out" ];
}
