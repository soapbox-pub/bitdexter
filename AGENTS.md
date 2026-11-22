# Agent instructions

- **Always commit after making changes**, in the style of `git log`.
- Building needs a C compiler, for LMDB. On DinOS there's none on PATH, so
  build in a nix shell, through `lowcpu`:

  ```sh
  nix shell nixpkgs#gcc --command lowcpu cargo build
  nix shell nixpkgs#gcc --command lowcpu cargo test
  nix shell nixpkgs#gcc --command lowcpu cargo clippy --all-targets
  ```

- Before committing: `cargo fmt`, clippy with no warnings, `cargo test`, and,
  for anything touching sync, the store or the API,
  `nix shell nixpkgs#bitcoind --command python3 -I tests/regtest.py`.
- Compare API responses with a public Esplora with `tests/compare.py`.
- The store's format is described in `src/store/mod.rs`; bump `FORMAT` there
  when it changes.
