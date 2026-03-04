mod app;
mod sbom;
mod ui;

use std::io;
use std::path::PathBuf;

use color_eyre::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

fn main() -> Result<()> {
    color_eyre::install()?;

    // Determine SBOM file path from args (default: bom.json)
    let sbom_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bom.json"));

    if !sbom_path.exists() {
        eprintln!("Error: SBOM file not found: {}", sbom_path.display());
        eprintln!("Usage: sbom-viewer [path/to/bom.json]");
        std::process::exit(1);
    }

    let sbom_data = sbom::parse_sbom(&sbom_path)?;
    let mut app = app::App::new(sbom_data);

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = run_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Open a URL in the default browser, platform-aware.
fn open_url(url: &str) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status()
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).status()
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported platform",
        ))
    }
}

fn handle_mouse(app: &mut app::App, mouse: crossterm::event::MouseEvent) {
    let col = mouse.column;
    let row = mouse.row;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // 1. Check tab clicks
            for &(area, tab) in &app.click_areas.tabs {
                if col >= area.x
                    && col < area.x + area.width
                    && row >= area.y
                    && row < area.y + area.height
                {
                    app.active_tab = tab;
                    return;
                }
            }

            // 2. Check panel title bar clicks (switch to the other tab)
            for &(area, tab) in &app.click_areas.panel_titles {
                if col >= area.x
                    && col < area.x + area.width
                    && row >= area.y
                    && row < area.y + area.height
                {
                    app.active_tab = tab;
                    return;
                }
            }

            // 3. Check column header clicks (only on Table tab)
            if app.active_tab == app::Tab::Table {
                for &(area, sort_col) in &app.click_areas.column_headers {
                    if col >= area.x
                        && col < area.x + area.width
                        && row >= area.y
                        && row < area.y + area.height
                    {
                        app.set_sort_column(sort_col);
                        return;
                    }
                }
            }

            // 4. Check table body clicks
            if app.active_tab == app::Tab::Table {
                if let Some(body) = app.click_areas.table_body {
                    if col >= body.x
                        && col < body.x + body.width
                        && row >= body.y
                        && row < body.y + body.height
                    {
                        let offset = app.table_state.offset();
                        let clicked_row = (row - body.y) as usize + offset;
                        app.select_table_row(clicked_row);
                        return;
                    }
                }
            }

            // 5. Check tree body clicks
            if app.active_tab == app::Tab::Tree {
                if let Some(body) = app.click_areas.tree_body {
                    if col >= body.x
                        && col < body.x + body.width
                        && row >= body.y
                        && row < body.y + body.height
                    {
                        let clicked_row = (row - body.y) as usize + app.tree_scroll_offset;
                        if clicked_row < app.tree_len() {
                            if clicked_row == app.tree_selected {
                                // Click on already-selected node: toggle expand/collapse
                                app.toggle_selected();
                            } else {
                                app.select_tree_row(clicked_row);
                            }
                        }
                        return;
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => {
            app.move_up();
        }
        MouseEventKind::ScrollDown => {
            app.move_down();
        }
        _ => {}
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut app::App,
) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        match event::read()? {
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // Filter input mode captures all keys
                if app.input_mode == app::InputMode::FilterInput {
                    match key.code {
                        KeyCode::Enter => app.filter_input_confirm(),
                        KeyCode::Esc => app.filter_input_cancel(),
                        KeyCode::Backspace => app.filter_input_backspace(),
                        KeyCode::Char(ch) => app.filter_input_char(ch),
                        _ => {}
                    }
                    continue;
                }

                // Normal mode
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    KeyCode::Tab | KeyCode::BackTab => {
                        app.active_tab = app.active_tab.next();
                    }
                    KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                    KeyCode::PageUp => app.page_up(10),
                    KeyCode::PageDown => app.page_down(10),
                    KeyCode::Home | KeyCode::Char('g') => app.home(),
                    KeyCode::End | KeyCode::Char('G') => app.end(),
                    // Tree expand/collapse
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if app.active_tab == app::Tab::Tree {
                            app.toggle_selected();
                        }
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        if app.active_tab == app::Tab::Tree {
                            app.expand_selected();
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        if app.active_tab == app::Tab::Tree {
                            app.collapse_selected();
                        }
                    }
                    KeyCode::Char('e') => {
                        if app.active_tab == app::Tab::Tree {
                            app.expand_all();
                        }
                    }
                    KeyCode::Char('c') => {
                        if app.active_tab == app::Tab::Tree {
                            app.collapse_all();
                        }
                    }
                    // Table sort/filter
                    KeyCode::Char('s') => {
                        if app.active_tab == app::Tab::Table {
                            app.cycle_sort_column();
                        }
                    }
                    KeyCode::Char('S') => {
                        if app.active_tab == app::Tab::Table {
                            app.toggle_sort_direction();
                        }
                    }
                    KeyCode::Char('/') => {
                        if app.active_tab == app::Tab::Table {
                            app.begin_filter_input();
                        }
                    }
                    KeyCode::Char('f') => {
                        if app.active_tab == app::Tab::Table {
                            app.cycle_filter_column();
                        }
                    }
                    KeyCode::Char('x') => {
                        if app.active_tab == app::Tab::Table {
                            app.clear_filter();
                        }
                    }
                    // Open package registry URL in browser
                    KeyCode::Char('o') => {
                        if let Some(bom_ref) = app.selected_bom_ref() {
                            if let Some(comp) = app.sbom.components.get(bom_ref) {
                                if let Some(url) = comp.registry_url() {
                                    let _ = open_url(&url);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Mouse(mouse) => {
                handle_mouse(app, mouse);
            }
            _ => {}
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
