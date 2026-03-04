# sbom-viewer

A terminal UI for browsing [CycloneDX](https://cyclonedx.org/) SBOM files (`bom.json`).

## Requirements

- [Rust](https://rustup.rs/) 1.85+ (edition 2024)

## Installation

```sh
cargo install --path .
```

Or just build and run directly:

```sh
cargo build --release
./target/release/sbom-viewer [path/to/bom.json]
```

## Usage

```sh
# Uses bom.json in the current directory by default
sbom-viewer

# Specify a file explicitly
sbom-viewer path/to/bom.json
```

## Keybindings

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Switch between Table and Tree views |
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `PgDn` / `PgUp` | Page down / up |
| `g` / `Home` | Jump to top |
| `G` / `End` | Jump to bottom |
| `Enter` / `Space` | Toggle expand/collapse (Tree view) |
| `l` / `→` | Expand node (Tree view) |
| `h` / `←` | Collapse node (Tree view) |
| `e` | Expand all (Tree view) |
| `c` | Collapse all (Tree view) |
| `q` / `Esc` | Quit |
