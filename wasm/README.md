# Build

```sh
just make_release
```

If just is not installed, the command can be just copied from `justfile`. This
requires having installed the Rust nightly-2024-08-02 toolchain.

# Serve

```
cargo run --example server
```

The server will listen at port 3001.
