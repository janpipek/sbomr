//! Terminal UI rendering with ratatui.
//!
//! Colours are provided by the active [`Theme`] stored in [`App`].

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
use crate::theme::ThemeColors;

// ---------------------------------------------------------------------------
// Top-level draw
// ---------------------------------------------------------------------------

pub fn draw(frame: &mut Frame, app: &mut App) {
    // Reset click areas for this frame
    app.click_areas = ClickAreas::default();

    let c = app.theme.colors();

    // Fill the entire screen with the surface background
    frame.render_widget(
        Block::default().style(Style::default().bg(c.bg_surface)),
        frame.area(),
    );

    let show_filter_bar = app.active_tab == Tab::Table
        && (app.has_active_filter() || app.input_mode == InputMode::FilterInput);
    let filter_bar_height = if show_filter_bar { 1 } else { 0 };
    let detail_height = match app.active_tab {
        Tab::Json | Tab::Metadata => 0,
        _ => 6,
    };

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
        Constraint::Length(detail_height),     // detail panel (0 on JSON tab)
        Constraint::Length(1),                 // footer keybinds
    ])
    .areas(frame.area());

    draw_summary(frame, app, header_area, &c);
    draw_tabs(frame, app, tabs_area, &c);

    if show_filter_bar {
        draw_filter_bar(frame, app, filter_area, &c);
    }

    match app.active_tab {
        Tab::Table => draw_table(frame, app, main_area, &c),
        Tab::Tree => draw_tree(frame, app, main_area, &c),
        Tab::Metadata => draw_metadata(frame, app, main_area, &c),
        Tab::Json => draw_json(frame, app, main_area, &c),
    }

    if detail_height > 0 {
        draw_detail(frame, app, detail_area, &c);
    }
    draw_footer(frame, app, footer_area, &c);
}

// ---------------------------------------------------------------------------
// Summary bar
// ---------------------------------------------------------------------------

fn draw_summary(frame: &mut Frame, app: &App, area: Rect, c: &ThemeColors) {
    let total = app.sbom.components.len();
    let direct = app.sbom.components.values().filter(|c| c.is_direct).count();
    let dev = app
        .sbom
        .components
        .values()
        .filter(|c| !c.dep_group.is_empty())
        .count();
    let outdated = app
        .sbom
        .components
        .values()
        .filter(|c| c.is_outdated())
        .count();
    let no_license = app
        .sbom
        .components
        .values()
        .filter(|c| c.licenses.is_empty())
        .count();
    let vulnerable: usize = app
        .sbom
        .components
        .values()
        .filter(|c| c.vuln_count > 0)
        .count();

    let mut spans = vec![
        Span::styled(
            format!("  {} ", app.sbom.root_name),
            Style::default().bold().fg(c.text_bright),
        ),
        Span::styled(
            format!("v{}", app.sbom.root_version),
            Style::default().fg(c.text_muted),
        ),
        Span::raw("    "),
        Span::styled("Components ", Style::default().fg(c.text_muted)),
        Span::styled(format!("{total}"), Style::default().bold().fg(c.text)),
        Span::raw("    "),
        Span::styled("Direct ", Style::default().fg(c.text_muted)),
        Span::styled(
            format!("{direct}"),
            Style::default().bold().fg(c.color_required),
        ),
        Span::raw("    "),
        Span::styled("Dev/Tool ", Style::default().fg(c.text_muted)),
        Span::styled(format!("{dev}"), Style::default().bold().fg(c.color_dev)),
    ];
    if outdated > 0 {
        spans.extend([
            Span::raw("    "),
            Span::styled("Outdated ", Style::default().fg(c.text_muted)),
            Span::styled(
                format!("{outdated}"),
                Style::default().bold().fg(c.color_warning),
            ),
        ]);
    }
    if no_license > 0 {
        spans.extend([
            Span::raw("    "),
            Span::styled("No License ", Style::default().fg(c.text_muted)),
            Span::styled(
                format!("{no_license}"),
                Style::default().bold().fg(c.color_error),
            ),
        ]);
    }
    if vulnerable > 0 {
        spans.extend([
            Span::raw("    "),
            Span::styled("Vulnerable ", Style::default().fg(c.text_muted)),
            Span::styled(
                format!("{vulnerable}"),
                Style::default().bold().fg(c.color_error),
            ),
        ]);
    }
    let text = Line::from(spans);

    let block = Block::default()
        .style(Style::default().bg(c.bg_primary))
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(c.accent))
        .padding(Padding::new(0, 0, 1, 0));
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

fn draw_tabs(frame: &mut Frame, app: &mut App, area: Rect, c: &ThemeColors) {
    let titles = vec![
        " Dependency List ",
        " Dependency Tree ",
        " Metadata ",
        " JSON ",
    ];
    let selected = match app.active_tab {
        Tab::Table => 0,
        Tab::Tree => 1,
        Tab::Metadata => 2,
        Tab::Json => 3,
    };
    let tabs = Tabs::new(titles.clone())
        .select(selected)
        .style(Style::default().fg(c.text_muted).bg(c.bg_surface))
        .highlight_style(
            Style::default()
                .fg(c.accent)
                .bold()
                .add_modifier(Modifier::UNDERLINED),
        )
        .divider(Span::styled("│", Style::default().fg(c.border)));
    frame.render_widget(tabs, area);

    // Tabs widget renders: pad_left(1) + title + pad_right(1) + divider(1) per tab.
    // The last tab has no divider. Account for padding to align click areas correctly.
    let tab_variants = [Tab::Table, Tab::Tree, Tab::Metadata, Tab::Json];
    let area_end = area.x + area.width;
    let pad = 1u16; // default Tabs padding on each side
    let divider_w = 1u16;
    let mut x = area.x;
    for (i, title) in titles.iter().enumerate() {
        let last = i == titles.len() - 1;
        let title_w = title.len() as u16;
        let full_w = pad + title_w + pad + if last { 0 } else { divider_w };
        // The clickable region covers the padding + title + padding (not the divider)
        let click_w = (pad + title_w + pad).min(area_end.saturating_sub(x));
        if x < area_end {
            let tab_area = Rect::new(x, area.y, click_w, 1);
            app.click_areas.tabs.push((tab_area, tab_variants[i]));
        }
        x += full_w;
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

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect, c: &ThemeColors) {
    let header = Row::new(vec![
        sort_header_cell("Name", SortColumn::Name, app),
        sort_header_cell("Version", SortColumn::Version, app),
        sort_header_cell("License", SortColumn::License, app),
        sort_header_cell("Type", SortColumn::Type, app),
        sort_header_cell("Registry", SortColumn::Registry, app),
        Cell::from("Scope"),
        Cell::from("Group"),
        Cell::from("Description"),
    ])
    .style(Style::default().bold().fg(c.accent).bg(c.bg_surface_alt))
    .height(1)
    .bottom_margin(0);

    let rows: Vec<Row> = app
        .visible_rows
        .iter()
        .enumerate()
        .map(|(i, bom_ref)| {
            let comp = &app.sbom.components[bom_ref];
            let type_color = dep_type_color(&comp.dep_type, c);

            let license_style = if comp.licenses.is_empty() {
                Style::default().fg(c.color_error).italic()
            } else {
                Style::default().fg(c.text)
            };

            let row_bg = if i % 2 == 1 {
                c.bg_surface_alt
            } else {
                c.bg_surface
            };

            Row::new(vec![
                Cell::from(comp.name.clone()).style(Style::default().fg(c.text)),
                Cell::from(Line::from(if comp.is_outdated() {
                    vec![
                        Span::styled(&comp.version, Style::default().fg(c.text_muted)),
                        Span::styled(" ↑", Style::default().fg(c.color_warning)),
                    ]
                } else {
                    vec![Span::styled(
                        &comp.version,
                        Style::default().fg(c.text_muted),
                    )]
                })),
                Cell::from(comp.license_str()).style(license_style),
                Cell::from(comp.dep_type.label()).style(Style::default().fg(type_color)),
                Cell::from(if comp.registry.is_empty() {
                    "-".to_string()
                } else {
                    comp.registry.clone()
                })
                .style(Style::default().fg(c.text_muted)),
                Cell::from(comp.scope.clone()).style(Style::default().fg(c.text_muted)),
                Cell::from(if comp.dep_group.is_empty() {
                    "-".to_string()
                } else {
                    comp.dep_group.clone()
                })
                .style(Style::default().fg(c.text_muted)),
                Cell::from(truncate(&comp.description, 50))
                    .style(Style::default().fg(c.text_muted)),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    let widths = [
        Constraint::Length(22), // Name
        Constraint::Length(10), // Version
        Constraint::Length(28), // License
        Constraint::Length(14), // Type
        Constraint::Length(10), // Registry
        Constraint::Length(10), // Scope
        Constraint::Length(8),  // Group
        Constraint::Min(20),    // Description
    ];

    // Record column header click areas.
    // The table has a 1-cell border on each side, so content starts at area.x + 1.
    // The highlight_symbol "▶ " takes 2 chars, so columns start at area.x + 1 + 2.
    // The header row is at area.y + 1 (below the top border).
    {
        let sortable_columns: [(usize, SortColumn); 5] = [
            (0, SortColumn::Name),
            (1, SortColumn::Version),
            (2, SortColumn::License),
            (3, SortColumn::Type),
            (4, SortColumn::Registry),
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
                .border_style(Style::default().fg(c.border_active))
                .title(title)
                .title_style(Style::default().fg(c.accent).bold()),
        )
        .row_highlight_style(
            Style::default()
                .bg(c.bg_highlight)
                .fg(c.text_bright)
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
                .track_style(Style::default().fg(c.border))
                .thumb_style(Style::default().fg(c.text_muted)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

fn draw_filter_bar(frame: &mut Frame, app: &App, area: Rect, c: &ThemeColors) {
    let is_inputting = app.input_mode == InputMode::FilterInput;
    let display_text = if is_inputting {
        &app.filter_input_buf
    } else {
        &app.filter_text
    };

    let mut spans = vec![
        Span::styled(
            " Filter ",
            Style::default().bold().fg(c.bg_surface).bg(c.accent),
        ),
        Span::styled(
            format!(" {} ", app.filter_column.label()),
            Style::default().fg(c.accent).bold(),
        ),
        Span::styled("│ ", Style::default().fg(c.border)),
    ];

    if display_text.is_empty() && !is_inputting {
        spans.push(Span::styled(
            "press / to filter",
            Style::default().fg(c.text_muted).italic(),
        ));
    } else {
        spans.push(Span::styled(display_text, Style::default().fg(c.text)));
        if is_inputting {
            spans.push(Span::styled("█", Style::default().fg(c.accent)));
        }
    }

    if !display_text.is_empty() && !is_inputting {
        spans.push(Span::styled(
            "  (x to clear)",
            Style::default().fg(c.text_muted),
        ));
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(c.bg_surface_alt)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Tree tab
// ---------------------------------------------------------------------------

fn draw_tree(frame: &mut Frame, app: &mut App, area: Rect, c: &ThemeColors) {
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
                let color = category_color(&line.label, c);
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
                        Style::default().fg(c.text_muted).italic(),
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
                    Style::default().fg(c.tree_guide),
                ));

                // Expand/collapse icon for nodes with children
                if line.has_children {
                    let icon = if line.expanded { "▼ " } else { "▶ " };
                    spans.push(Span::styled(icon, Style::default().fg(c.accent)));
                } else {
                    spans.push(Span::styled("  ", Style::default()));
                }

                // Parse label: "name version  [license]"
                if let Some((name_ver, license_part)) = line.label.split_once("  [") {
                    let license = license_part.trim_end_matches(']');
                    // Split name and version
                    if let Some((name, version)) = name_ver.rsplit_once(' ') {
                        spans.push(Span::styled(name, Style::default().fg(c.text)));
                        spans.push(Span::styled(
                            format!(" {version}"),
                            Style::default().fg(c.text_muted),
                        ));
                    } else {
                        spans.push(Span::styled(name_ver, Style::default().fg(c.text)));
                    }
                    spans.push(Span::raw("  "));
                    let lic_color = if license == "(none)" {
                        c.color_error
                    } else {
                        c.text_muted
                    };
                    let lic_style = if license == "(none)" {
                        Style::default().fg(lic_color).italic()
                    } else {
                        Style::default().fg(lic_color)
                    };
                    spans.push(Span::styled(format!("[{license}]"), lic_style));
                } else {
                    spans.push(Span::styled(
                        line.label.clone(),
                        Style::default().fg(c.text),
                    ));
                }

                // Collapsed hint
                if line.has_children && !line.expanded {
                    spans.push(Span::styled(
                        " ...",
                        Style::default().fg(c.text_muted).italic(),
                    ));
                }
            }

            let result = Line::from(spans);
            if is_selected {
                result.style(
                    Style::default()
                        .bg(c.bg_highlight)
                        .fg(c.text_bright)
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
            .border_style(Style::default().fg(c.border_active))
            .title(format!(" Dependency Tree ({}) ", app.tree_grouping.label()))
            .title_style(Style::default().fg(c.accent).bold()),
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
                .track_style(Style::default().fg(c.border))
                .thumb_style(Style::default().fg(c.text_muted)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Metadata tab
// ---------------------------------------------------------------------------

fn meta_row<'a>(label: &str, value: &str, c: &ThemeColors) -> Line<'a> {
    let display = if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    };
    Line::from(vec![
        Span::styled(
            format!("  {label:<22} "),
            Style::default().fg(c.text_muted).bold(),
        ),
        Span::styled(display, Style::default().fg(c.text)),
    ])
}

fn draw_metadata(frame: &mut Frame, app: &mut App, area: Rect, c: &ThemeColors) {
    let m = &app.sbom.metadata;

    let tool_str = if m.tool_name.is_empty() {
        String::new()
    } else {
        format!("{} {}", m.tool_name, m.tool_version)
    };

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            "  SBOM Provenance",
            Style::default().fg(c.accent).bold(),
        )),
        Line::from(""),
        meta_row("Spec Version", &m.spec_version, c),
        meta_row("Serial Number", &m.serial_number, c),
        meta_row("Timestamp", &m.timestamp, c),
        meta_row("Tool", &tool_str, c),
        meta_row("Lifecycle Phase", &m.lifecycle_phase, c),
    ];

    // Component types: split on literal `\n`, one per line, sorted
    {
        let mut types: Vec<&str> = m
            .component_types
            .split("\\n")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        types.sort_unstable();
        if types.is_empty() {
            lines.push(meta_row("Component Types", "-", c));
        } else {
            lines.push(meta_row("Component Types", types[0], c));
            let indent = format!("{:<25}", "");
            for t in &types[1..] {
                lines.push(Line::from(vec![
                    Span::styled(indent.clone(), Style::default()),
                    Span::styled((*t).to_string(), Style::default().fg(c.text)),
                ]));
            }
        }
    }

    // Component sources: one per line, sorted
    // cdxgen encodes literal `\n` (backslash + n) as separator in the JSON value.
    {
        let mut srcs: Vec<&str> = m
            .component_src_files
            .split("\\n")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        srcs.sort_unstable();
        if srcs.is_empty() {
            lines.push(meta_row("Component Sources", "-", c));
        } else {
            lines.push(meta_row("Component Sources", srcs[0], c));
            let indent = format!("{:<25}", "");
            for src in &srcs[1..] {
                lines.push(Line::from(vec![
                    Span::styled(indent.clone(), Style::default()),
                    Span::styled((*src).to_string(), Style::default().fg(c.text)),
                ]));
            }
        }
    }

    if !m.annotation.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Annotation",
            Style::default().fg(c.accent).bold(),
        )));
        for chunk in m.annotation.as_bytes().chunks(80) {
            let s = String::from_utf8_lossy(chunk);
            lines.push(Line::from(Span::styled(
                format!("  {s}"),
                Style::default().fg(c.text_muted),
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Component Statistics",
        Style::default().fg(c.accent).bold(),
    )));
    lines.push(Line::from(""));

    let total = app.sbom.components.len();
    let direct = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.is_direct)
        .count();
    let transitive = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.dep_type == DepType::Transitive)
        .count();
    let outdated = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.is_outdated())
        .count();
    let no_license = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.licenses.is_empty())
        .count();
    let with_hashes = app
        .sbom
        .components
        .values()
        .filter(|comp| !comp.hashes.is_empty())
        .count();
    let with_vcs = app
        .sbom
        .components
        .values()
        .filter(|comp| !comp.vcs_url.is_empty())
        .count();
    let vulnerable = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.vuln_count > 0)
        .count();
    let copyleft = app
        .sbom
        .components
        .values()
        .filter(|comp| comp.has_copyleft())
        .count();

    lines.push(meta_row("Total Components", &total.to_string(), c));
    lines.push(meta_row("Direct", &direct.to_string(), c));
    lines.push(meta_row("Transitive", &transitive.to_string(), c));
    lines.push(meta_row(
        "With Hashes",
        &format!("{with_hashes}/{total}"),
        c,
    ));
    lines.push(meta_row("With VCS URL", &format!("{with_vcs}/{total}"), c));

    if outdated > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<22} ", "Outdated"),
                Style::default().fg(c.text_muted).bold(),
            ),
            Span::styled(
                outdated.to_string(),
                Style::default().fg(c.color_warning).bold(),
            ),
        ]));
    }
    if no_license > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<22} ", "No License"),
                Style::default().fg(c.text_muted).bold(),
            ),
            Span::styled(
                no_license.to_string(),
                Style::default().fg(c.color_error).bold(),
            ),
        ]));
    }
    if copyleft > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<22} ", "Copyleft"),
                Style::default().fg(c.text_muted).bold(),
            ),
            Span::styled(
                copyleft.to_string(),
                Style::default().fg(c.color_warning).bold(),
            ),
        ]));
    }
    if vulnerable > 0 {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<22} ", "Vulnerable"),
                Style::default().fg(c.text_muted).bold(),
            ),
            Span::styled(
                vulnerable.to_string(),
                Style::default().fg(c.color_error).bold(),
            ),
        ]));
    }

    // Record the title bar (top border row) as a click target to switch to Table tab.
    let title_bar = Rect::new(area.x, area.y, area.width, 1);
    app.click_areas.panel_titles.push((title_bar, Tab::Table));

    // Store line count and clamp scroll offset.
    let content_height = area.height.saturating_sub(2) as usize; // minus top/bottom border
    app.metadata_line_count = lines.len();
    let max_scroll = lines.len().saturating_sub(content_height);
    if app.metadata_scroll_offset > max_scroll {
        app.metadata_scroll_offset = max_scroll;
    }

    let paragraph = Paragraph::new(lines)
        .scroll((app.metadata_scroll_offset as u16, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(c.border_active))
                .title(" Metadata ")
                .title_style(Style::default().fg(c.accent).bold()),
        );
    frame.render_widget(paragraph, area);

    // Scrollbar
    if app.metadata_line_count > content_height {
        let mut scrollbar_state =
            ScrollbarState::new(max_scroll).position(app.metadata_scroll_offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_style(Style::default().fg(c.border))
                .thumb_style(Style::default().fg(c.text_muted)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// JSON tab
// ---------------------------------------------------------------------------

use crate::sbom::FlatJsonLine;

/// Colour a JSON value string based on its content.
fn style_json_value<'a>(text: &str, c: &ThemeColors) -> Span<'a> {
    let t = text.trim();
    if t.starts_with('"') {
        Span::styled(text.to_string(), Style::default().fg(c.color_required))
    } else if t == "true" || t == "false" {
        Span::styled(text.to_string(), Style::default().fg(c.color_dev))
    } else if t == "null" {
        Span::styled(text.to_string(), Style::default().fg(c.color_error))
    } else if t.starts_with('{') || t.starts_with('}') || t.starts_with('[') || t.starts_with(']') {
        // Structural chars or collapsed summary
        Span::styled(text.to_string(), Style::default().fg(c.text_muted))
    } else if t
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit() || ch == '-')
    {
        Span::styled(text.to_string(), Style::default().fg(c.color_optional))
    } else {
        Span::styled(text.to_string(), Style::default().fg(c.text))
    }
}

/// Build coloured spans for a single FlatJsonLine.
fn render_json_line<'a>(line: &FlatJsonLine, c: &ThemeColors) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    // Indent
    let indent = "  ".repeat(line.depth);
    if !indent.is_empty() {
        spans.push(Span::styled(indent, Style::default()));
    }
    // Collapse/expand indicator for collapsible nodes
    if line.collapsible {
        let icon = if line.expanded { "▼ " } else { "▶ " };
        spans.push(Span::styled(icon, Style::default().fg(c.accent)));
    }
    // Key
    if !line.key.is_empty() {
        // Split into quoted key and colon-space
        spans.push(Span::styled(
            line.key.clone(),
            Style::default().fg(c.accent),
        ));
    }
    // Value
    spans.push(style_json_value(&line.value, c));
    // Trailing comma
    if line.trailing_comma {
        spans.push(Span::styled(",", Style::default().fg(c.text_muted)));
    }
    spans
}

fn draw_json(frame: &mut Frame, app: &mut App, area: Rect, c: &ThemeColors) {
    let visible_height = area.height.saturating_sub(2) as usize; // borders
    app.adjust_json_scroll(visible_height);

    // Record body area for mouse clicks
    let body_y = area.y + 1;
    let body_height = area.height.saturating_sub(2);
    app.click_areas.json_body = Some(Rect::new(area.x, body_y, area.width, body_height));

    let start = app.json_scroll_offset;
    let end = (start + visible_height).min(app.json_len());

    let lines: Vec<Line> = app.flat_json[start..end]
        .iter()
        .enumerate()
        .map(|(vi, line)| {
            let absolute_idx = start + vi;
            let is_selected = absolute_idx == app.json_selected;
            let spans = render_json_line(line, c);
            let result = Line::from(spans);
            if is_selected {
                result.style(
                    Style::default()
                        .bg(c.bg_highlight)
                        .fg(c.text_bright)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                result
            }
        })
        .collect();

    let title_bar = Rect::new(area.x, area.y, area.width, 1);
    app.click_areas.panel_titles.push((title_bar, Tab::Table));

    let first = start + 1;
    let last = end;
    let total = app.json_len();
    let title = format!(" JSON  lines {first}-{last} / {total} ");
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(c.border_active))
            .title(title)
            .title_style(Style::default().fg(c.accent).bold()),
    );
    frame.render_widget(paragraph, area);

    // Scrollbar
    if app.json_len() > visible_height {
        let mut scrollbar_state =
            ScrollbarState::new(app.json_len()).position(app.json_scroll_offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼"))
                .track_style(Style::default().fg(c.border))
                .thumb_style(Style::default().fg(c.text_muted)),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

fn draw_detail(frame: &mut Frame, app: &App, area: Rect, c: &ThemeColors) {
    let content = if app.active_tab == Tab::Metadata {
        // On the Metadata tab, show SBOM-level info instead of per-component detail
        vec![
            Line::from(vec![
                Span::styled(
                    &app.sbom.root_name,
                    Style::default().bold().fg(c.text_bright),
                ),
                Span::styled(
                    format!(" v{}", app.sbom.root_version),
                    Style::default().fg(c.text_muted),
                ),
                Span::styled("  │  ", Style::default().fg(c.border)),
                Span::styled(
                    format!("{} components", app.sbom.components.len()),
                    Style::default().fg(c.text),
                ),
            ]),
            Line::from(Span::styled(
                "Use Dependency List or Dependency Tree tabs to select a component",
                Style::default().fg(c.text_muted).italic(),
            )),
            Line::from(""),
            Line::from(""),
        ]
    } else if let Some(bom_ref) = app.selected_bom_ref() {
        if let Some(comp) = app.sbom.components.get(bom_ref) {
            let type_color = dep_type_color(&comp.dep_type, c);
            let license_style = if comp.licenses.is_empty() {
                Style::default().fg(c.color_error).italic()
            } else {
                Style::default().fg(c.text)
            };

            // Line 1: name, version, type, license, outdated indicator
            let mut line1 = vec![
                Span::styled(&comp.name, Style::default().bold().fg(c.text_bright)),
                Span::styled(
                    format!(" {}", comp.version),
                    Style::default().fg(c.text_muted),
                ),
            ];
            if comp.is_outdated() {
                line1.push(Span::styled(
                    format!(" → {}", comp.latest_version),
                    Style::default().fg(c.color_warning).bold(),
                ));
            }
            line1.extend([
                Span::styled("  │  ", Style::default().fg(c.border)),
                Span::styled("Type ", Style::default().fg(c.text_muted)),
                Span::styled(
                    comp.dep_type.label(),
                    Style::default().fg(type_color).bold(),
                ),
                Span::styled("  │  ", Style::default().fg(c.border)),
                Span::styled("License ", Style::default().fg(c.text_muted)),
                Span::styled(comp.license_str(), license_style),
            ]);
            if comp.has_copyleft() {
                line1.push(Span::styled(
                    " ⚠ copyleft",
                    Style::default().fg(c.color_warning),
                ));
            }
            if comp.vuln_count > 0 {
                line1.extend([
                    Span::styled("  │  ", Style::default().fg(c.border)),
                    Span::styled(
                        format!("{} vuln(s)", comp.vuln_count),
                        Style::default().fg(c.color_error).bold(),
                    ),
                ]);
            }
            if let Some(conf) = comp.confidence {
                line1.extend([
                    Span::styled("  │  ", Style::default().fg(c.border)),
                    Span::styled(
                        format!("conf {:.0}%", conf * 100.0),
                        Style::default().fg(c.text_muted),
                    ),
                ]);
            }

            // Line 2: description + reverse deps
            let mut line2_spans: Vec<Span> = Vec::new();
            if !comp.description.is_empty() {
                line2_spans.push(Span::styled(
                    truncate(&comp.description, 60),
                    Style::default().fg(c.text_muted),
                ));
            }
            // Reverse deps
            let bom_ref_str = bom_ref.to_string();
            if let Some(rdeps) = app.sbom.reverse_deps.get(&bom_ref_str) {
                let names: Vec<&str> = rdeps
                    .iter()
                    .filter_map(|r| app.sbom.components.get(r).map(|c| c.name.as_str()))
                    .take(5)
                    .collect();
                if !names.is_empty() {
                    if !line2_spans.is_empty() {
                        line2_spans.push(Span::styled("  │  ", Style::default().fg(c.border)));
                    }
                    let suffix = if rdeps.len() > 5 {
                        format!(", +{}", rdeps.len() - 5)
                    } else {
                        String::new()
                    };
                    line2_spans.push(Span::styled("Used by ", Style::default().fg(c.text_muted)));
                    line2_spans.push(Span::styled(
                        format!("{}{suffix}", names.join(", ")),
                        Style::default().fg(c.text),
                    ));
                }
            }
            if line2_spans.is_empty() {
                line2_spans.push(Span::styled("", Style::default()));
            }

            // Line 3: purl, VCS or registry URL
            let mut line3_spans = vec![Span::styled(
                format!("purl: {}", comp.purl),
                Style::default().fg(c.text_muted).italic(),
            )];
            if !comp.vcs_url.is_empty() {
                line3_spans.push(Span::styled("    ", Style::default()));
                line3_spans.push(Span::styled(
                    &comp.vcs_url,
                    Style::default()
                        .fg(c.accent)
                        .add_modifier(Modifier::UNDERLINED),
                ));
            } else if let Some(url) = comp.registry_url() {
                line3_spans.push(Span::styled("    ", Style::default()));
                line3_spans.push(Span::styled(
                    url,
                    Style::default()
                        .fg(c.accent)
                        .add_modifier(Modifier::UNDERLINED),
                ));
            }

            // Line 4: hash digest (full, truncated by terminal width)
            let line4 = if let Some((alg, digest)) = comp.hashes.first() {
                Line::from(vec![
                    Span::styled(format!("{alg}: "), Style::default().fg(c.text_muted)),
                    Span::styled(digest, Style::default().fg(c.text_muted).italic()),
                ])
            } else {
                Line::from("")
            };

            vec![
                Line::from(line1),
                Line::from(line2_spans),
                Line::from(line3_spans),
                line4,
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(""),
                Line::from(""),
                Line::from(""),
            ]
        }
    } else {
        vec![
            Line::from(Span::styled(
                "Select a dependency to view details",
                Style::default().fg(c.text_muted).italic(),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(""),
        ]
    };

    let block = Block::default()
        .style(Style::default().bg(c.bg_panel))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(c.border_active))
        .title(" Detail ")
        .title_style(Style::default().fg(c.accent).bold());
    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn draw_footer(frame: &mut Frame, app: &App, area: Rect, c: &ThemeColors) {
    let key_style = Style::default().bold().fg(c.bg_surface).bg(c.text_muted);
    let sep = Style::default().fg(c.text_muted);

    if app.input_mode == InputMode::FilterInput {
        let spans = vec![
            Span::styled(" Enter ", key_style),
            Span::styled(" Apply  ", sep),
            Span::styled(" Esc ", key_style),
            Span::styled(" Cancel  ", sep),
            Span::styled(
                "  Type to filter...",
                Style::default().fg(c.text_muted).italic(),
            ),
        ];
        frame.render_widget(
            Paragraph::new(Line::from(spans)).style(Style::default().bg(c.bg_surface_alt)),
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
        Span::styled(" t ", key_style),
        Span::styled(format!(" {} ", app.theme.label()), sep),
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
            Span::styled(" g ", key_style),
            Span::styled(" Group  ", sep),
        ]);
    }
    if app.active_tab == Tab::Json {
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
        Paragraph::new(Line::from(spans)).style(Style::default().bg(c.bg_surface_alt)),
        area,
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dep_type_color(dt: &DepType, c: &ThemeColors) -> Color {
    match dt {
        DepType::Required => c.color_required,
        DepType::Dev(_) => c.color_dev,
        DepType::Optional => c.color_optional,
        DepType::Transitive => c.color_transitive,
    }
}

fn category_color(label: &str, c: &ThemeColors) -> Color {
    if label.contains("required") {
        c.color_required
    } else if label.contains("dev") {
        c.color_dev
    } else {
        c.color_optional
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
