# sbom-viewer

A terminal UI for browsing [CycloneDX](https://cyclonedx.org/) SBOM files, built with [ratatui](https://ratatui.rs/) and crossterm. Focus is on **licenses** and **dependency types** (required, dev, optional, transitive).

## Requirements

- [Rust](https://rustup.rs/) 1.85+ (edition 2024)

## Installation

```sh
cargo install --path .
```

Or build and run directly:

```sh
cargo run --release -- [path/to/bom.json]
```

Defaults to `bom.json` in the current directory if no path is given.

## Features

- **Table view** -- all dependencies with sortable, filterable columns: Name, Version, License, Type, Scope, Group, Description
- **Tree view** -- hierarchical dependency graph grouped into required, dev (by group name), and optional extras; fully collapsible
- **Detail panel** -- full metadata for the highlighted dependency including a browsable registry URL
- **Colour-coded dependency types** -- green (required), amber (dev), purple (optional), muted (transitive)
- **Missing license highlighting** -- red italic for components with no declared license
- **Sorting** -- cycle through Name, Version, License, or Type columns; toggle ascending/descending
- **Filtering** -- case-insensitive text search against Name, License, or Type with a dedicated input mode
- **Registry URLs** -- constructs browsable links from purl for 15 package managers and opens them in the default browser
- **Zebra-striped table** with scrollbar

### Supported registries (from purl)

PyPI, npm (including scoped packages), crates.io, RubyGems, Maven Central, NuGet, Go (pkg.go.dev), Packagist, Hex, CocoaPods, pub.dev, Swift, Hackage, CRAN.

## Generating an SBOM

The app reads CycloneDX 1.6 JSON. Generate one with [cdxgen](https://github.com/CycloneDX/cdxgen):

```sh
npx @cyclonedx/cdxgen -o bom.json
```

## Keybindings

### Global

| Key | Action |
|---|---|
| `q` / `Esc` | Quit |
| `Tab` | Switch between Table and Tree tabs |
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `PgUp` / `PgDn` | Page up / down |
| `g` / `Home` | Jump to top |
| `G` / `End` | Jump to bottom |
| `o` | Open selected package's registry page in browser |

### Table tab

| Key | Action |
|---|---|
| `s` | Cycle sort column (Type -> Name -> Version -> License) |
| `S` | Reverse sort direction |
| `/` | Enter filter input mode |
| `f` | Cycle filter column (Name -> License -> Type) |
| `x` | Clear active filter |

### Tree tab

| Key | Action |
|---|---|
| `Enter` / `Space` | Toggle expand / collapse |
| `l` / `→` | Expand node |
| `h` / `←` | Collapse node (or jump to parent) |
| `e` | Expand all |
| `c` | Collapse all |

### Filter input mode

| Key | Action |
|---|---|
| *any character* | Append to search text |
| `Backspace` | Delete last character |
| `Enter` | Apply filter |
| `Esc` | Cancel |

## Dependency type classification

The app uses three signals from the CycloneDX SBOM to classify each component:

1. **`scope`** field -- `"optional"` marks dev-group dependencies
2. **`cdx:pyproject:group`** property -- gives the exact group name (`"dev"`, `"type"`, etc.)
3. **Dependency graph analysis** -- a component that is not in root's `dependsOn`, has no dev group, and is not a transitive child of any other component is classified as an **optional extra** (e.g. from `[project.optional-dependencies]`)

## Project structure

```
src/
├── main.rs    Entry point, terminal setup, event loop, keybindings
├── app.rs     App state, navigation, sort/filter, collapsible tree
├── sbom.rs    CycloneDX JSON parser, data model, purl-to-URL mapping
└── ui.rs      Rendering, colour palette (Textual-inspired dark theme), layout
```
