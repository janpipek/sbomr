# sbomr

A terminal UI for browsing [CycloneDX](https://cyclonedx.org/) SBOM files, built with [ratatui](https://ratatui.rs/) and crossterm. Focus is on **licenses**, **dependency types** (required, dev, optional, transitive), and **security insights** (outdated packages, vulnerabilities, hashes, confidence scores).

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

```sh
sbomr --help
```

## Features

- **Dependency List** -- sortable, filterable columns: Name, Version, License, Type, Registry, Scope, Group, Description
- **Dependency Tree** -- hierarchical dependency graph grouped into required, dev (by group name), and optional extras; starts partially collapsed
- **Metadata tab** -- SBOM provenance (spec version, serial number, timestamp, tool, lifecycle phase) and component statistics (outdated, no-license, copyleft, vulnerable counts)
- **JSON tab** -- collapsible tree viewer for the raw SBOM JSON with syntax highlighting; starts expanded to the first level
- **Detail panel** -- enriched 4-line display: version with outdated indicator (`→ latest`), license with copyleft warning, vulnerability count, confidence score, description, reverse dependencies, purl, VCS/registry URL, and full hash digest
- **Summary bar** -- at-a-glance counts: total, direct, transitive, outdated, no-license, vulnerable
- **Security insights** -- outdated detection via `cdx:cargo:latest_version` (with `↑` indicator in table), vulnerability tracking, SHA hash display, evidence confidence scores
- **Light and dark themes** -- auto-detects terminal background at startup; press `t` to toggle
- **Colour-coded dependency types** -- green (required), amber (dev), purple (optional), muted (transitive)
- **Missing license highlighting** -- red italic for components with no declared license
- **Sorting** -- cycle through Name, Version, License, Type, or Registry columns; toggle ascending/descending
- **Filtering** -- case-insensitive text search against Name, License, or Type with a dedicated input mode
- **Mouse support** -- clickable tabs, column headers (click to sort, click again to reverse), table rows, tree nodes (click to select, click again to toggle), panel title bars, and scroll wheel navigation
- **Registry URLs** -- constructs browsable links from purl for 15 package managers and opens them in the default browser
- **Zebra-striped table** with scrollbar
- **Panic-safe terminal** -- restores terminal state on panic (no leaked escape sequences)

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
| `Tab` / `Shift+Tab` | Next / previous tab |
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `PgUp` / `PgDn` | Page up / down |
| `g` / `Home` | Jump to top (`g` = group on Tree tab) |
| `G` / `End` | Jump to bottom |
| `o` | Open selected package's registry page in browser |
| `t` | Toggle light / dark theme |

### Dependency List

| Key | Action |
|---|---|
| `s` | Cycle sort column (Type -> Name -> Version -> License -> Registry) |
| `S` | Reverse sort direction |
| `/` | Enter filter input mode |
| `f` | Cycle filter column (Name -> License -> Type) |
| `x` | Clear active filter |

### Dependency Tree

| Key | Action |
|---|---|
| `Enter` / `Space` | Toggle expand / collapse |
| `l` / `→` | Expand node |
| `h` / `←` | Collapse node (or jump to parent) |
| `e` | Expand all |
| `c` | Collapse all |
| `g` | Cycle tree grouping (dependency type / source file) |

### JSON

| Key | Action |
|---|---|
| `Enter` / `Space` | Toggle expand / collapse |
| `l` / `→` | Expand node |
| `h` / `←` | Collapse node |
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

## Development

```sh
just          # fmt + clippy + test
just build    # release binary
just install  # cargo install --path .
just publish  # publish to crates.io
```

## Project structure

```
src/
├── main.rs    Entry point, terminal setup, panic hook, event loop, keybindings
├── app.rs     App state, navigation, sort/filter, collapsible tree, JSON tree state
├── sbom.rs    CycloneDX JSON parser, data model, purl-to-URL mapping, JSON tree builder
├── theme.rs   Dark/light colour palettes, OS theme detection
└── ui.rs      Rendering, layout, syntax highlighting (theme-aware)
```
