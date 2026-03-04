//! Terminal UI rendering with ratatui.
//!
//! Colour palette is designed to match the Textual (Python) dark theme.

use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, Tabs,
    },
};

use crate::app::{App, ClickAreas, InputMode, SortColumn, Tab};
use crate::sbom::DepType;

// ---------------------------------------------------------------------------
// Colour palette — mirrors Textual's dark theme tokens
// ---------------------------------------------------------------------------

/// Surface / main background (Textual $surface)
const BG_SURFACE: Color = Color::Rgb(30, 30, 30);
/// Slightly lighter surface for alternating rows / panels (Textual $surface-lighten-1)
const BG_SURFACE_ALT: Color = Color::Rgb(38, 38, 38);
/// Summary bar background (Textual $primary-background)
const BG_PRIMARY: Color = Color::Rgb(0, 45, 80);
/// Detail panel background (Textual $panel)
const BG_PANEL: Color = Color::Rgb(35, 35, 40);
/// Selection / highlight row
const BG_HIGHLIGHT: Color = Color::Rgb(0, 80, 140);

/// Primary accent (Textual $primary — dodger blue)
const ACCENT: Color = Color::Rgb(0, 135, 255);
/// Secondary text / muted (Textual $text-muted)
const TEXT_MUTED: Color = Color::Rgb(135, 135, 135);
/// Normal text
const TEXT: Color = Color::Rgb(220, 220, 220);
/// Bright text on highlight
const TEXT_BRIGHT: Color = Color::Rgb(255, 255, 255);

/// $success — green for required deps
const COLOR_REQUIRED: Color = Color::Rgb(80, 200, 120);
/// $warning — amber for dev deps
const COLOR_DEV: Color = Color::Rgb(255, 183, 77);
/// #ab47bc — purple for optional deps (same hex as Textual CSS)
const COLOR_OPTIONAL: Color = Color::Rgb(171, 71, 188);
/// Muted for transitive deps
const COLOR_TRANSITIVE: Color = TEXT_MUTED;
/// $error — red for missing licenses
const COLOR_ERROR: Color = Color::Rgb(230, 80, 80);

/// Border colour (subtle)
const BORDER: Color = Color::Rgb(60, 60, 60);
/// Border colour for focused/active panels
const BORDER_ACTIVE: Color = Color::Rgb(80, 80, 90);

/// Tree guide lines
const TREE_GUIDE: Color = Color::Rgb(70, 70, 70);

// ---------------------------------------------------------------------------
// Top-level draw
// ---------------------------------------------------------------------------

pub fn draw(frame: &mut Frame, app: &mut App) {
    // Reset click areas for this frame
    app.click_areas = ClickAreas::default();

    // Fill the entire screen with the surface background
    frame.render_widget(
        Block::default().style(Style::default().bg(BG_SURFACE)),
        frame.area(),
    );

    let show_filter_bar = app.active_tab == Tab::Table
        && (app.has_active_filter() || app.input_mode == InputMode::FilterInput);
    let filter_bar_height = if show_filter_bar { 1 } else { 0 };

    let [
        header_area,
        tabs_area,
        filter_area,
        main_area,
        detail_area,
        footer_area,
    ] = Layout::vertical([
        Constraint::Length(3),                 // summary bar
        Constraint::Length(1),                 // tabs
        Constraint::Length(filter_bar_height), // filter bar (0 or 1)
        Constraint::Min(8),                    // table or tree
        Constraint::Length(5),                 // detail panel
        Constraint::Length(1),                 // footer keybinds
    ])
    .areas(frame.area());

    draw_summary(frame, app, header_area);
    draw_tabs(frame, app, tabs_area);

    if show_filter_bar {
        draw_filter_bar(frame, app, filter_area);
    }

    match app.active_tab {
        Tab::Table => draw_table(frame, app, main_area),
        Tab::Tree => draw_tree(frame, app, main_area),
    }

    draw_detail(frame, app, detail_area);
    draw_footer(frame, app, footer_area);
}

// ---------------------------------------------------------------------------
// Summary bar
// ---------------------------------------------------------------------------

fn draw_summary(frame: &mut Frame, app: &App, area: Rect) {
    let total = app.sbom.components.len();
    let direct = app.sbom.components.values().filter(|c| c.is_direct).count();
    let dev = app
        .sbom
        .components
        .values()
        .filter(|c| !c.dep_group.is_empty())
        .count();
    let unique_licenses: std::collections::HashSet<&String> = app
        .sbom
        .components
        .values()
        .flat_map(|c| c.licenses.iter())
        .collect();

    let text = Line::from(vec![
        Span::styled(
            format!("  {} ", app.sbom.root_name),
            Style::default().bold().fg(TEXT_BRIGHT),
        ),
        Span::styled(
            format!("v{}", app.sbom.root_version),
            Style::default().fg(TEXT_MUTED),
        ),
        Span::raw("    "),
        Span::styled("Components ", Style::default().fg(TEXT_MUTED)),
        Span::styled(format!("{total}"), Style::default().bold().fg(TEXT)),
        Span::raw("    "),
        Span::styled("Direct ", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format!("{direct}"),
            Style::default().bold().fg(COLOR_REQUIRED),
        ),
        Span::raw("    "),
        Span::styled("Dev/Tool ", Style::default().fg(TEXT_MUTED)),
        Span::styled(format!("{dev}"), Style::default().bold().fg(COLOR_DEV)),
        Span::raw("    "),
        Span::styled("Licenses ", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format!("{} unique", unique_licenses.len()),
            Style::default().bold().fg(TEXT),
        ),
    ]);

    let block = Block::default()
        .style(Style::default().bg(BG_PRIMARY))
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(ACCENT))
        .padding(Padding::new(0, 0, 1, 0));
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

fn draw_tabs(frame: &mut Frame, app: &mut App, area: Rect) {
    let titles = vec![" Dependency List ", " Dependency Tree "];
    let selected = match app.active_tab {
        Tab::Table => 0,
        Tab::Tree => 1,
    };
    let tabs = Tabs::new(titles.clone())
        .select(selected)
        .style(Style::default().fg(TEXT_MUTED).bg(BG_SURFACE))
        .highlight_style(
            Style::default()
                .fg(ACCENT)
                .bold()
                .add_modifier(Modifier::UNDERLINED),
        )
        .divider(Span::styled("│", Style::default().fg(BORDER)));
    frame.render_widget(tabs, area);

    // Record clickable tab areas.
    // Tab layout: each title is rendered sequentially with a "│" divider between them.
    // We compute approximate positions based on title widths.
    let tab_variants = [Tab::Table, Tab::Tree];
    let mut x = area.x;
    for (i, title) in titles.iter().enumerate() {
        let w = title.len() as u16;
        let tab_area = Rect::new(x, area.y, w, 1);
        app.click_areas.tabs.push((tab_area, tab_variants[i]));
        x += w + 1; // +1 for the "│" divider
    }
}

// ---------------------------------------------------------------------------
// Table tab
// ---------------------------------------------------------------------------

fn sort_header_cell(label: &str, col: SortColumn, app: &App) -> Cell<'static> {
    if app.sort_column == col {
        Cell::from(format!("{label} {}", app.sort_direction.indicator()))
    } else {
        Cell::from(label.to_string())
    }
}

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let header = Row::new(vec![
        sort_header_cell("Name", SortColumn::Name, app),
        sort_header_cell("Version", SortColumn::Version, app),
        sort_header_cell("License", SortColumn::License, app),
        sort_header_cell("Type", SortColumn::Type, app),
        Cell::from("Scope"),
        Cell::from("Group"),
        Cell::from("Description"),
    ])
    .style(Style::default().bold().fg(ACCENT).bg(BG_SURFACE_ALT))
    .height(1)
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .visible_rows
        .iter()
        .enumerate()
        .map(|(i, bom_ref)| {
            let comp = &app.sbom.components[bom_ref];
            let type_color = dep_type_color(&comp.dep_type);

            let license_style = if comp.licenses.is_empty() {
                Style::default().fg(COLOR_ERROR).italic()
            } else {
                Style::default().fg(TEXT)
            };

            let row_bg = if i % 2 == 1 {
                BG_SURFACE_ALT
            } else {
                BG_SURFACE
            };

            Row::new(vec![
                Cell::from(comp.name.clone()).style(Style::default().fg(TEXT)),
                Cell::from(comp.version.clone()).style(Style::default().fg(TEXT_MUTED)),
                Cell::from(comp.license_str()).style(license_style),
                Cell::from(comp.dep_type.label()).style(Style::default().fg(type_color)),
                Cell::from(comp.scope.clone()).style(Style::default().fg(TEXT_MUTED)),
                Cell::from(if comp.dep_group.is_empty() {
                    "-".to_string()
                } else {
                    comp.dep_group.clone()
                })
                .style(Style::default().fg(TEXT_MUTED)),
                Cell::from(truncate(&comp.description, 50)).style(Style::default().fg(TEXT_MUTED)),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    let widths = [
        Constraint::Length(22),
        Constraint::Length(10),
        Constraint::Length(28),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(20),
    ];

    // Record column header click areas.
    // The table has a 1-cell border on each side, so content starts at area.x + 1.
    // The highlight_symbol "▶ " takes 2 chars, so columns start at area.x + 1 + 2.
    // The header row is at area.y + 1 (below the top border).
    {
        let sortable_columns: [(usize, SortColumn); 4] = [
            (0, SortColumn::Name),
            (1, SortColumn::Version),
            (2, SortColumn::License),
            (3, SortColumn::Type),
        ];
        let content_width = area.width.saturating_sub(2); // minus left+right borders
        let resolved = resolve_widths(&widths, content_width.saturating_sub(2)); // minus highlight symbol
        let mut col_x = area.x + 1 + 2; // border + highlight symbol
        for (col_idx, col_width) in resolved.iter().enumerate() {
            if let Some(&(_, sort_col)) = sortable_columns.iter().find(|(i, _)| *i == col_idx) {
                let header_area = Rect::new(col_x, area.y + 1, *col_width, 1);
                app.click_areas.column_headers.push((header_area, sort_col));
            }
            col_x += col_width;
        }

        // Record the table body area (rows start after border + header row).
        let body_y = area.y + 2; // top border + header
        let body_height = area.height.saturating_sub(3); // top border + header + bottom border
        app.click_areas.table_body = Some(Rect::new(area.x, body_y, area.width, body_height));
    }

    let title = if app.has_active_filter() {
        format!(
            " Dependency List ({}/{}) ",
            app.visible_rows.len(),
            app.sbom.components.len()
        )
    } else {
        format!(" Dependency List ({}) ", app.sbom.components.len())
    };

    // Record the title bar (top border row) as a click target to switch to Tree tab.
    let title_bar = Rect::new(area.x, area.y, area.width, 1);
    app.click_areas.panel_titles.push((title_bar, Tab::Tree));

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_ACTIVE))
                .title(title)
                .title_style(Style::default().fg(ACCENT).bold()),
        )
        .row_highlight_style(
            Style::default()
                .bg(BG_HIGHLIGHT)
                .fg(TEXT_BRIGHT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(table, area, &mut app.table_state);

    // Scrollbar
    let visible_height = area.height.saturating_sub(3) as usize;
    if app.table_len() > visible_height {
        let scroll_pos = app.table_state.offset();
        let mut scrollbar_state =
            ScrollbarState::new(app.table_len().saturating_sub(visible_height))
                .position(scroll_pos);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_style(Style::default().fg(BORDER))
                .thumb_style(Style::default().fg(TEXT_MUTED)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

fn draw_filter_bar(frame: &mut Frame, app: &App, area: Rect) {
    let is_inputting = app.input_mode == InputMode::FilterInput;
    let display_text = if is_inputting {
        &app.filter_input_buf
    } else {
        &app.filter_text
    };

    let mut spans = vec![
        Span::styled(
            " Filter ",
            Style::default().bold().fg(BG_SURFACE).bg(ACCENT),
        ),
        Span::styled(
            format!(" {} ", app.filter_column.label()),
            Style::default().fg(ACCENT).bold(),
        ),
        Span::styled("│ ", Style::default().fg(BORDER)),
    ];

    if display_text.is_empty() && !is_inputting {
        spans.push(Span::styled(
            "press / to filter",
            Style::default().fg(TEXT_MUTED).italic(),
        ));
    } else {
        spans.push(Span::styled(display_text, Style::default().fg(TEXT)));
        if is_inputting {
            spans.push(Span::styled("█", Style::default().fg(ACCENT)));
        }
    }

    if !display_text.is_empty() && !is_inputting {
        spans.push(Span::styled(
            "  (x to clear)",
            Style::default().fg(TEXT_MUTED),
        ));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(BG_SURFACE_ALT)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Tree tab
// ---------------------------------------------------------------------------

fn draw_tree(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible_height = area.height.saturating_sub(2) as usize; // borders
    app.adjust_tree_scroll(visible_height);

    // Record tree body area (inside borders)
    let body_y = area.y + 1; // top border
    let body_height = area.height.saturating_sub(2); // top + bottom borders
    app.click_areas.tree_body = Some(Rect::new(area.x, body_y, area.width, body_height));

    let start = app.tree_scroll_offset;
    let end = (start + visible_height).min(app.flat_tree.len());

    let lines: Vec<Line> = app.flat_tree[start..end]
        .iter()
        .enumerate()
        .map(|(vi, line)| {
            let absolute_idx = start + vi;
            let is_selected = absolute_idx == app.tree_selected;

            let mut spans = Vec::new();

            if line.is_category {
                // Category header (bold, coloured)
                let color = category_color(&line.label);
                let chevron = if !line.has_children {
                    "  "
                } else if line.expanded {
                    "▼ "
                } else {
                    "▶ "
                };
                spans.push(Span::styled(
                    format!("  {chevron}"),
                    Style::default().fg(color),
                ));
                spans.push(Span::styled(
                    line.label.clone(),
                    Style::default().fg(color).bold(),
                ));
                if !line.expanded && line.has_children {
                    spans.push(Span::styled(
                        " ...",
                        Style::default().fg(TEXT_MUTED).italic(),
                    ));
                }
            } else {
                // Build indent with proper vertical guide lines
                let mut indent = String::new();
                for &has_guide in &line.guides {
                    if has_guide {
                        indent.push_str("│   ");
                    } else {
                        indent.push_str("    ");
                    }
                }
                let connector = if line.is_last_child {
                    "└── "
                } else {
                    "├── "
                };
                spans.push(Span::styled(
                    format!("{indent}{connector}"),
                    Style::default().fg(TREE_GUIDE),
                ));

                // Expand/collapse icon for nodes with children
                if line.has_children {
                    let icon = if line.expanded { "▼ " } else { "▶ " };
                    spans.push(Span::styled(icon, Style::default().fg(ACCENT)));
                } else {
                    spans.push(Span::styled("  ", Style::default()));
                }

                // Parse label: "name version  [license]"
                if let Some((name_ver, license_part)) = line.label.split_once("  [") {
                    let license = license_part.trim_end_matches(']');
                    // Split name and version
                    if let Some((name, version)) = name_ver.rsplit_once(' ') {
                        spans.push(Span::styled(name, Style::default().fg(TEXT)));
                        spans.push(Span::styled(
                            format!(" {version}"),
                            Style::default().fg(TEXT_MUTED),
                        ));
                    } else {
                        spans.push(Span::styled(name_ver, Style::default().fg(TEXT)));
                    }
                    spans.push(Span::raw("  "));
                    let lic_color = if license == "(none)" {
                        COLOR_ERROR
                    } else {
                        TEXT_MUTED
                    };
                    let lic_style = if license == "(none)" {
                        Style::default().fg(lic_color).italic()
                    } else {
                        Style::default().fg(lic_color)
                    };
                    spans.push(Span::styled(format!("[{license}]"), lic_style));
                } else {
                    spans.push(Span::styled(line.label.clone(), Style::default().fg(TEXT)));
                }

                // Collapsed hint
                if line.has_children && !line.expanded {
                    spans.push(Span::styled(
                        " ...",
                        Style::default().fg(TEXT_MUTED).italic(),
                    ));
                }
            }

            let result = Line::from(spans);
            if is_selected {
                result.style(
                    Style::default()
                        .bg(BG_HIGHLIGHT)
                        .fg(TEXT_BRIGHT)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                result
            }
        })
        .collect();

    // Record the title bar (top border row) as a click target to switch to Table tab.
    let title_bar = Rect::new(area.x, area.y, area.width, 1);
    app.click_areas.panel_titles.push((title_bar, Tab::Table));

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .title(" Dependency Tree ")
            .title_style(Style::default().fg(ACCENT).bold()),
    );
    frame.render_widget(paragraph, area);

    // Scrollbar
    if app.tree_len() > visible_height {
        let mut scrollbar_state =
            ScrollbarState::new(app.tree_len()).position(app.tree_scroll_offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_style(Style::default().fg(BORDER))
                .thumb_style(Style::default().fg(TEXT_MUTED)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let content = if let Some(bom_ref) = app.selected_bom_ref() {
        if let Some(comp) = app.sbom.components.get(bom_ref) {
            let type_color = dep_type_color(&comp.dep_type);
            let license_style = if comp.licenses.is_empty() {
                Style::default().fg(COLOR_ERROR).italic()
            } else {
                Style::default().fg(TEXT)
            };
            vec![
                Line::from(vec![
                    Span::styled(&comp.name, Style::default().bold().fg(TEXT_BRIGHT)),
                    Span::styled(
                        format!(" {}", comp.version),
                        Style::default().fg(TEXT_MUTED),
                    ),
                    Span::styled("  │  ", Style::default().fg(BORDER)),
                    Span::styled("Type ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(
                        comp.dep_type.label(),
                        Style::default().fg(type_color).bold(),
                    ),
                    Span::styled("  │  ", Style::default().fg(BORDER)),
                    Span::styled("License ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(comp.license_str(), license_style),
                    Span::styled("  │  ", Style::default().fg(BORDER)),
                    Span::styled("Scope ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(&comp.scope, Style::default().fg(TEXT)),
                    Span::styled("  │  ", Style::default().fg(BORDER)),
                    Span::styled("Group ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(
                        if comp.dep_group.is_empty() {
                            "-"
                        } else {
                            &comp.dep_group
                        },
                        Style::default().fg(TEXT),
                    ),
                ]),
                Line::from(Span::styled(
                    &comp.description,
                    Style::default().fg(TEXT_MUTED),
                )),
                Line::from({
                    let mut info_spans = vec![Span::styled(
                        format!("purl: {}", comp.purl),
                        Style::default().fg(TEXT_MUTED).italic(),
                    )];
                    if let Some(url) = comp.registry_url() {
                        info_spans.push(Span::styled("    ", Style::default()));
                        info_spans.push(Span::styled(
                            url,
                            Style::default()
                                .fg(ACCENT)
                                .add_modifier(Modifier::UNDERLINED),
                        ));
                    }
                    info_spans
                }),
            ]
        } else {
            vec![Line::from("")]
        }
    } else {
        vec![Line::from(Span::styled(
            "Select a dependency to view details",
            Style::default().fg(TEXT_MUTED).italic(),
        ))]
    };

    let block = Block::default()
        .style(Style::default().bg(BG_PANEL))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER_ACTIVE))
        .title(" Detail ")
        .title_style(Style::default().fg(ACCENT).bold());
    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let key_style = Style::default().bold().fg(BG_SURFACE).bg(TEXT_MUTED);
    let sep = Style::default().fg(TEXT_MUTED);

    if app.input_mode == InputMode::FilterInput {
        let spans = vec![
            Span::styled(" Enter ", key_style),
            Span::styled(" Apply  ", sep),
            Span::styled(" Esc ", key_style),
            Span::styled(" Cancel  ", sep),
            Span::styled(
                "  Type to filter...",
                Style::default().fg(TEXT_MUTED).italic(),
            ),
        ];
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default().bg(BG_SURFACE_ALT)),
            area,
        );
        return;
    }

    let mut spans = vec![
        Span::styled(" q ", key_style),
        Span::styled(" Quit  ", sep),
        Span::styled(" Tab ", key_style),
        Span::styled(" Switch  ", sep),
        Span::styled(" ↑↓ ", key_style),
        Span::styled(" Navigate  ", sep),
        Span::styled(" o ", key_style),
        Span::styled(" Open URL  ", sep),
    ];
    if app.active_tab == Tab::Table {
        spans.extend([
            Span::styled(" s ", key_style),
            Span::styled(" Sort  ", sep),
            Span::styled(" S ", key_style),
            Span::styled(" Reverse  ", sep),
            Span::styled(" / ", key_style),
            Span::styled(" Filter  ", sep),
            Span::styled(" f ", key_style),
            Span::styled(" Filter Col  ", sep),
        ]);
        if app.has_active_filter() {
            spans.extend([
                Span::styled(" x ", key_style),
                Span::styled(" Clear  ", sep),
            ]);
        }
    }
    if app.active_tab == Tab::Tree {
        spans.extend([
            Span::styled(" Enter ", key_style),
            Span::styled(" Toggle  ", sep),
            Span::styled(" ←→ ", key_style),
            Span::styled(" Collapse/Expand  ", sep),
            Span::styled(" e ", key_style),
            Span::styled(" Expand All  ", sep),
            Span::styled(" c ", key_style),
            Span::styled(" Collapse All  ", sep),
        ]);
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(BG_SURFACE_ALT)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dep_type_color(dt: &DepType) -> Color {
    match dt {
        DepType::Required => COLOR_REQUIRED,
        DepType::Dev(_) => COLOR_DEV,
        DepType::Optional => COLOR_OPTIONAL,
        DepType::Transitive => COLOR_TRANSITIVE,
    }
}

fn category_color(label: &str) -> Color {
    if label.contains("required") {
        COLOR_REQUIRED
    } else if label.contains("dev") {
        COLOR_DEV
    } else {
        COLOR_OPTIONAL
    }
}

/// Resolve constraint widths into absolute pixel values (matching ratatui's layout logic).
fn resolve_widths(constraints: &[Constraint], available: u16) -> Vec<u16> {
    // First pass: allocate fixed lengths and collect Min columns
    let mut result = vec![0u16; constraints.len()];
    let mut remaining = available;
    let mut min_indices = Vec::new();
    for (i, c) in constraints.iter().enumerate() {
        match c {
            Constraint::Length(w) => {
                let w = (*w).min(remaining);
                result[i] = w;
                remaining = remaining.saturating_sub(w);
            }
            Constraint::Min(min) => {
                result[i] = *min;
                remaining = remaining.saturating_sub(*min);
                min_indices.push(i);
            }
            _ => {}
        }
    }
    // Distribute remaining space to Min columns
    if !min_indices.is_empty() && remaining > 0 {
        let extra = remaining / min_indices.len() as u16;
        for idx in min_indices {
            result[idx] += extra;
        }
    }
    result
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}
