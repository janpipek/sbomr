//! Terminal UI rendering with ratatui.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Padding, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, Tabs,
    },
    Frame,
};

use crate::app::{App, Tab};
use crate::sbom::DepType;

// Colours for dependency types
const COLOR_REQUIRED: Color = Color::Green;
const COLOR_DEV: Color = Color::Yellow;
const COLOR_OPTIONAL: Color = Color::Magenta;
const COLOR_TRANSITIVE: Color = Color::DarkGray;
const COLOR_LICENSE_NONE: Color = Color::Red;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header_area, tabs_area, main_area, detail_area, footer_area] = Layout::vertical([
        Constraint::Length(3), // summary bar
        Constraint::Length(1), // tabs
        Constraint::Min(8),    // table or tree
        Constraint::Length(5), // detail panel
        Constraint::Length(1), // footer keybinds
    ])
    .areas(frame.area());

    draw_summary(frame, app, header_area);
    draw_tabs(frame, app, tabs_area);

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
            format!(" {} ", app.sbom.root_name),
            Style::default().bold().fg(Color::Cyan),
        ),
        Span::raw(format!("v{}  ", app.sbom.root_version)),
        Span::styled("Components: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{total}"), Style::default().bold()),
        Span::raw("  "),
        Span::styled("Direct: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{direct}"),
            Style::default().bold().fg(COLOR_REQUIRED),
        ),
        Span::raw("  "),
        Span::styled("Dev/Tool: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{dev}"), Style::default().bold().fg(COLOR_DEV)),
        Span::raw("  "),
        Span::styled("Licenses: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} unique", unique_licenses.len()),
            Style::default().bold(),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray))
        .padding(Padding::new(0, 0, 1, 0));
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles = vec![" Table ", " Tree "];
    let selected = match app.active_tab {
        Tab::Table => 0,
        Tab::Tree => 1,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(Style::default().fg(Color::Cyan).bold().underlined())
        .divider("|");
    frame.render_widget(tabs, area);
}

// ---------------------------------------------------------------------------
// Table tab
// ---------------------------------------------------------------------------

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let header_style = Style::default().bold().fg(Color::Cyan);
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Version"),
        Cell::from("License"),
        Cell::from("Type"),
        Cell::from("Scope"),
        Cell::from("Group"),
        Cell::from("Description"),
    ])
    .style(header_style)
    .height(1);

    let rows: Vec<Row> = app
        .sbom
        .sorted_components
        .iter()
        .map(|bom_ref| {
            let comp = &app.sbom.components[bom_ref];
            let type_color = dep_type_color(&comp.dep_type);

            let license_style = if comp.licenses.is_empty() {
                Style::default().fg(COLOR_LICENSE_NONE).italic()
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(comp.name.clone()),
                Cell::from(comp.version.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(comp.license_str()).style(license_style),
                Cell::from(comp.dep_type.label()).style(Style::default().fg(type_color)),
                Cell::from(comp.scope.clone()),
                Cell::from(if comp.dep_group.is_empty() {
                    "-".to_string()
                } else {
                    comp.dep_group.clone()
                }),
                Cell::from(truncate(&comp.description, 50))
                    .style(Style::default().fg(Color::DarkGray)),
            ])
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

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray))
                .title(" Dependencies ")
                .title_style(Style::default().fg(Color::Cyan).bold()),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
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
                .end_symbol(Some("▼")),
            area,
            &mut scrollbar_state,
        );
    }
}

// ---------------------------------------------------------------------------
// Tree tab
// ---------------------------------------------------------------------------

fn draw_tree(frame: &mut Frame, app: &mut App, area: Rect) {
    let visible_height = area.height.saturating_sub(2) as usize; // borders
    app.adjust_tree_scroll(visible_height);

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
                // Category header (bold, colored)
                let color = if line.label.contains("required") {
                    COLOR_REQUIRED
                } else if line.label.contains("dev") {
                    COLOR_DEV
                } else {
                    COLOR_OPTIONAL
                };
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
                    spans.push(Span::styled(" ...", Style::default().fg(Color::DarkGray)));
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
                    Style::default().fg(Color::DarkGray),
                ));

                // Expand/collapse icon for nodes with children
                if line.has_children {
                    let icon = if line.expanded { "▼ " } else { "▶ " };
                    spans.push(Span::styled(icon, Style::default().fg(Color::Cyan)));
                } else {
                    spans.push(Span::styled("  ", Style::default()));
                }

                // Parse label to colorize: "name version  [license]"
                if let Some((name_ver, license_part)) = line.label.split_once("  [") {
                    let license = license_part.trim_end_matches(']');
                    spans.push(Span::styled(
                        name_ver.to_string(),
                        Style::default().fg(Color::White),
                    ));
                    spans.push(Span::raw("  "));
                    let lic_color = if license == "(none)" {
                        COLOR_LICENSE_NONE
                    } else {
                        Color::DarkGray
                    };
                    spans.push(Span::styled(
                        format!("[{license}]"),
                        Style::default().fg(lic_color),
                    ));
                } else {
                    spans.push(Span::styled(
                        line.label.clone(),
                        Style::default().fg(Color::White),
                    ));
                }

                // Show collapsed hint
                if line.has_children && !line.expanded {
                    spans.push(Span::styled(" ...", Style::default().fg(Color::DarkGray)));
                }
            }

            let line = Line::from(spans);
            if is_selected {
                line.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                line
            }
        })
        .collect();

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Dependency Tree ")
            .title_style(Style::default().fg(Color::Cyan).bold()),
    );
    frame.render_widget(paragraph, area);

    // Scrollbar
    if app.tree_len() > visible_height {
        let mut scrollbar_state =
            ScrollbarState::new(app.tree_len()).position(app.tree_scroll_offset);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("▲"))
                .end_symbol(Some("▼")),
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
            vec![
                Line::from(vec![
                    Span::styled(&comp.name, Style::default().bold().fg(Color::White)),
                    Span::raw(format!(" {}  ", comp.version)),
                    Span::styled("Type: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(comp.dep_type.label(), Style::default().fg(type_color)),
                    Span::raw("  "),
                    Span::styled("License: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        comp.license_str(),
                        if comp.licenses.is_empty() {
                            Style::default().fg(COLOR_LICENSE_NONE).italic()
                        } else {
                            Style::default()
                        },
                    ),
                    Span::raw("  "),
                    Span::styled("Scope: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(&comp.scope),
                    Span::raw("  "),
                    Span::styled("Group: ", Style::default().fg(Color::DarkGray)),
                    Span::raw(if comp.dep_group.is_empty() {
                        "-"
                    } else {
                        &comp.dep_group
                    }),
                ]),
                Line::from(Span::styled(
                    &comp.description,
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    format!("purl: {}", comp.purl),
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else {
            vec![Line::from("")]
        }
    } else {
        vec![Line::from(Span::styled(
            "Select a dependency to view details",
            Style::default().fg(Color::DarkGray).italic(),
        ))]
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Detail ")
        .title_style(Style::default().fg(Color::Cyan).bold());
    let paragraph = Paragraph::new(content).block(block);
    frame.render_widget(paragraph, area);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let key_style = Style::default().bold().fg(Color::Black).bg(Color::DarkGray);
    let mut spans = vec![
        Span::styled(" q ", key_style),
        Span::raw(" Quit  "),
        Span::styled(" Tab ", key_style),
        Span::raw(" Switch  "),
        Span::styled(" ↑↓ ", key_style),
        Span::raw(" Navigate  "),
        Span::styled(" PgUp/Dn ", key_style),
        Span::raw(" Page  "),
    ];
    if app.active_tab == Tab::Tree {
        spans.extend([
            Span::styled(" Enter ", key_style),
            Span::raw(" Toggle  "),
            Span::styled(" ←→ ", key_style),
            Span::raw(" Collapse/Expand  "),
            Span::styled(" e ", key_style),
            Span::raw(" Expand All  "),
            Span::styled(" c ", key_style),
            Span::raw(" Collapse All  "),
        ]);
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len])
    } else {
        s.to_string()
    }
}
