mod app;
mod sbom;
mod ui;

use std::io;
use std::path::PathBuf;

use color_eyre::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
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
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    let result = run_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut app::App,
) -> Result<()> {
    loop {
        terminal.draw(|frame| ui::draw(frame, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
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
                _ => {}
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
