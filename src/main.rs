mod app;
mod sbom;
mod theme;
mod ui;

use std::io;
use std::path::PathBuf;

use color_eyre::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, MouseButton, MouseEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::prelude::*;

/// Restore the terminal to a sane state (raw mode off, alternate screen off,
/// mouse capture off, cursor visible).  Called both on normal exit and from
/// the panic hook so that a crash never leaves the terminal broken.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    );
    let _ = crossterm::execute!(io::stdout(), crossterm::cursor::Show);
}

fn main() -> Result<()> {
    // Install a panic hook that restores the terminal *before* printing the
    // panic message, so the user sees it in their normal shell.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    color_eyre::install()?;

    // Determine SBOM file path from args (default: bom.json)
    let arg = std::env::args().nth(1);
    if matches!(arg.as_deref(), Some("--help" | "-h")) {
        println!("Usage: sbomr [path/to/bom.json]");
        println!();
        println!("Interactive TUI viewer for CycloneDX SBOMs.");
        println!("If no path is given, looks for bom.json in the current directory.");
        std::process::exit(0);
    }

    let sbom_path = arg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bom.json"));

    if !sbom_path.exists() {
        eprintln!("Error: SBOM file not found: {}", sbom_path.display());
        eprintln!("Usage: sbomr [path/to/bom.json]");
        std::process::exit(1);
    }

    let sbom_data = sbom::parse_sbom(&sbom_path)?;
    let initial_theme = theme::detect_os_theme();
    let mut app = app::App::new(sbom_data, initial_theme);

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

    // Restore terminal on normal exit
    restore_terminal();

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

/// Check whether (col, row) falls inside `area`.
fn in_rect(col: u16, row: u16, area: Rect) -> bool {
    col >= area.x && col < area.x + area.width && row >= area.y && row < area.y + area.height
}

fn handle_mouse(app: &mut app::App, mouse: crossterm::event::MouseEvent) {
    let col = mouse.column;
    let row = mouse.row;

    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            // 1. Check tab clicks
            for &(area, tab) in &app.click_areas.tabs {
                if in_rect(col, row, area) {
                    app.active_tab = tab;
                    return;
                }
            }

            // 2. Check panel title bar clicks (switch to the other tab)
            for &(area, tab) in &app.click_areas.panel_titles {
                if in_rect(col, row, area) {
                    app.active_tab = tab;
                    return;
                }
            }

            // 3. Check column header clicks (only on Table tab)
            if app.active_tab == app::Tab::Table {
                for &(area, sort_col) in &app.click_areas.column_headers {
                    if in_rect(col, row, area) {
                        app.set_sort_column(sort_col);
                        return;
                    }
                }
            }

            // 4. Check table body clicks
            if app.active_tab == app::Tab::Table
                && let Some(body) = app.click_areas.table_body
                && in_rect(col, row, body)
            {
                let offset = app.table_state.offset();
                let clicked_row = (row - body.y) as usize + offset;
                app.select_table_row(clicked_row);
            }

            // 5. Check tree body clicks
            if app.active_tab == app::Tab::Tree
                && let Some(body) = app.click_areas.tree_body
                && in_rect(col, row, body)
            {
                let clicked_row = (row - body.y) as usize + app.tree_scroll_offset;
                if clicked_row < app.tree_len() {
                    if clicked_row == app.tree_selected {
                        app.toggle_selected();
                    } else {
                        app.select_tree_row(clicked_row);
                    }
                }
            }

            // 6. Check JSON body clicks
            if app.active_tab == app::Tab::Json
                && let Some(body) = app.click_areas.json_body
                && in_rect(col, row, body)
            {
                let clicked_row = (row - body.y) as usize + app.json_scroll_offset;
                if clicked_row < app.json_len() {
                    if clicked_row == app.json_selected {
                        // Re-click toggles expand/collapse
                        app.toggle_json_selected();
                    } else {
                        app.json_selected = clicked_row;
                    }
                }
            }
        }
        MouseEventKind::ScrollUp => app.move_up(),
        MouseEventKind::ScrollDown => app.move_down(),
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
                    // Tree / JSON expand/collapse
                    KeyCode::Enter | KeyCode::Char(' ') => match app.active_tab {
                        app::Tab::Tree => app.toggle_selected(),
                        app::Tab::Json => app.toggle_json_selected(),
                        _ => {}
                    },
                    KeyCode::Right | KeyCode::Char('l') => match app.active_tab {
                        app::Tab::Tree => app.expand_selected(),
                        app::Tab::Json => app.expand_json_selected(),
                        _ => {}
                    },
                    KeyCode::Left | KeyCode::Char('h') => match app.active_tab {
                        app::Tab::Tree => app.collapse_selected(),
                        app::Tab::Json => app.collapse_json_selected(),
                        _ => {}
                    },
                    KeyCode::Char('e') => match app.active_tab {
                        app::Tab::Tree => app.expand_all(),
                        app::Tab::Json => app.expand_all_json(),
                        _ => {}
                    },
                    KeyCode::Char('c') => match app.active_tab {
                        app::Tab::Tree => app.collapse_all(),
                        app::Tab::Json => app.collapse_all_json(),
                        _ => {}
                    },
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
                    // Toggle light/dark theme
                    KeyCode::Char('t') => {
                        app.toggle_theme();
                    }
                    // Open package registry URL in browser
                    KeyCode::Char('o') => {
                        if let Some(bom_ref) = app.selected_bom_ref()
                            && let Some(comp) = app.sbom.components.get(bom_ref)
                            && let Some(url) = comp.registry_url()
                        {
                            let _ = open_url(&url);
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
