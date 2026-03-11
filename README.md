# sbomr

A terminal UI for browsing [CycloneDX](https://cyclonedx.org/) SBOM files, built with [ratatui](https://ratatui.rs/) and crossterm. Focus is on **licenses**, **dependency types** (direct, transitive, dev), and **security insights** (outdated packages, vulnerabilities, hashes, confidence scores).

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

### CLI options

- `sbomr [path/to/bom.json]` -- open SBOM in the TUI (defaults to `bom.json`)
- `sbomr --theme dark|light` -- force a theme instead of auto-detect
- `sbomr --csv path/to/output.csv` -- export component table as CSV and exit

## Features

- **Dependency List** -- sortable, filterable columns: Name, Version, Registry, Type, License, Scope, Dep Type, Description
- **Dependency Tree** -- hierarchical dependency graph grouped into required, dev (by group name), and optional extras; starts partially collapsed
- **Vulnerabilities tab** -- sortable-by-severity view with CVSS score/method, affected packages, CWEs, published date, recommendation snippet, and advisory links
- **Metadata tab** -- SBOM provenance (spec version, serial number, timestamp, tool, lifecycle phase) and component statistics (outdated, no-license, copyleft, vulnerable counts)
- **JSON tab** -- collapsible tree viewer for raw SBOM JSON with syntax highlighting
- **Component JSON overlay** -- focused JSON viewer for the selected package (`v`), opened fully expanded with independent navigation and expand/collapse controls
- **Detail panel** -- enriched 4-line display: version with outdated indicator (`→ latest`), license with copyleft warning, vulnerability count, confidence score, description, reverse dependencies, purl, package URL (or VCS fallback), and full hash digest
- **Summary bar** -- at-a-glance counts: total, direct, transitive, outdated, no-license, vulnerable
- **Security insights** -- outdated detection via `cdx:cargo:latest_version` (with `↑` indicator in table), vulnerability tracking, SHA hash display, evidence confidence scores
- **Light and dark themes** -- auto-detects terminal background at startup; press `t` to toggle
- **Missing license highlighting** -- red italic for components with no declared license
- **Sorting** -- cycle through Name, Version, Registry, Type, License, or Scope columns; toggle ascending/descending
- **Filtering** -- case-insensitive text search against Name, License, Scope, or Type with a dedicated input mode
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

### Dependency List / Tree

| Key | Action |
|---|---|
| `v` | Open selected package in Component JSON overlay (expanded) |
| `p` | Open selected package dependency paths modal (incoming + outgoing trees) |

### Dependency List

| Key | Action |
|---|---|
| `s` | Cycle sort column (Name -> Version -> Registry -> Type -> License -> Scope) |
| `S` | Reverse sort direction |
| `/` | Enter filter input mode |
| `f` | Cycle filter column (Name -> License -> Scope -> Type) |
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

### Vulnerabilities

| Key | Action |
|---|---|
| `o` | Open selected vulnerability advisory URL in browser |

### JSON

| Key | Action |
|---|---|
| `Enter` / `Space` | Toggle expand / collapse |
| `l` / `→` | Expand node |
| `h` / `←` | Collapse node |
| `e` | Expand all |
| `c` | Collapse all |

### Component JSON overlay (opened with `v`)

| Key | Action |
|---|---|
| `q` / `Esc` / `v` | Close overlay |
| `j` / `↓`, `k` / `↑` | Move down / up |
| `PgUp` / `PgDn` | Page up / down |
| `g` / `Home`, `G` / `End` | Top / bottom |
| `Enter` / `Space` | Toggle expand / collapse |
| `l` / `→`, `h` / `←` | Expand / collapse |
| `e` / `c` | Expand all / collapse all |
| `y` | Copy selected package JSON to clipboard |
| `t` | Toggle theme |

### Dependency paths modal (opened with `p`)

| Key | Action |
|---|---|
| `p` / `Esc` / `q` | Close modal |
| `j` / `↓`, `k` / `↑` | Move down / up |
| `PgUp` / `PgDn` | Page up / down |
| `g` / `Home`, `G` / `End` | Top / bottom |
| `t` | Toggle theme |

### Mouse

| Action | Effect |
|---|---|
| Click tab | Switch tab |
| Click column header | Sort by that column |
| Click row | Select row |
| Scroll wheel | Scroll table / tree / metadata |
| `Shift+click/drag` | Native terminal text selection (bypasses app mouse capture) |
| `Cmd+click` / `Ctrl+click` | Open URL in browser (terminal-native, works on detail panel links) |

### Filter input mode

| Key | Action |
|---|---|
| *any character* | Append to search text |
| `Backspace` | Delete last character |
| `Enter` | Apply filter |
| `Esc` | Cancel |

## Dependency type classification

The app uses three signals from the CycloneDX SBOM to classify each component:

1. **`cdx:pyproject:group`** property -- gives a concrete dev group (`"dev"`, `"type"`, etc.), classified as `dev`
2. **Root dependency edges** -- components directly referenced by the root are classified as `direct`
3. **Dependency graph analysis** -- components reached through another component are classified as `transitive`

`scope` remains visible as a separate field (e.g. `required`, `optional`, `(unknown)`), but is not used as a separate dep-type category.

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
