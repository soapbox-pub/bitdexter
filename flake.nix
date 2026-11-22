{
  description = "bitdexter, a Bitcoin indexer";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in {
      # What building needs besides Rust (from rust-toolchain.toml): a C
      # compiler for LMDB, and cmake and boost for libbitcoinkernel.
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [ gcc cmake gnumake pkg-config ];
          buildInputs = [ pkgs.boost ];
          # Bitcoin Core on regtest, for tests/regtest.py.
          packages = [ pkgs.bitcoind pkgs.python3 ];
          CMAKE_PREFIX_PATH = "${pkgs.boost.dev}";
          # libbitcoinkernel links libstdc++ dynamically: find it at run time.
          RUSTFLAGS = "-C link-arg=-Wl,-rpath,${pkgs.stdenv.cc.cc.lib}/lib";
        };
      });
    };
}
