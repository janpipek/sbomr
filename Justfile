# Default: run all checks
default: fmt clippy test

# Format code
fmt:
    cargo fmt --check

# Lint with clippy
clippy:
    cargo clippy -- -D warnings

# Run tests
test:
    cargo test

# Build release binary
build:
    cargo build --release

# Publish to crates.io (dry-run first, then publish)
publish: fmt clippy test
    cargo publish --dry-run
    cargo publish
