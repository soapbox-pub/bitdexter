# Agent instructions

- **Always commit after making changes**, in the style of `git log`.
- Building needs a C and C++ compiler, cmake and boost, for LMDB and
  libbitcoinkernel. `flake.nix` has them; build in its shell, through
  `lowcpu`:

  ```sh
  nix develop --command lowcpu cargo build
  nix develop --command lowcpu cargo test
  nix develop --command lowcpu cargo clippy --all-targets
  ```

- Before committing: `cargo fmt`, clippy with no warnings, `cargo test`, and,
  for anything touching sync, the store or the API,
  `nix develop --command python3 -I tests/regtest.py`.
- Compare API responses with a public Esplora with `tests/compare.py`.
- The store's format is described in `src/store/mod.rs`; bump `FORMAT` there
  when it changes.
