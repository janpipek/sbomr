//! Theme definitions for dark and light modes.
//!
//! The dark palette mirrors Textual's dark theme tokens.
//! The light palette is designed for readability on light terminal backgrounds.

use ratatui::style::Color;

/// Which colour scheme is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
}

impl Theme {
    pub fn toggle(self) -> Self {
        match self {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Dark,
        }
    }

    /// Return the colour palette for this theme.
    pub fn colors(self) -> ThemeColors {
        match self {
            Theme::Dark => ThemeColors::dark(),
            Theme::Light => ThemeColors::light(),
        }
    }
}

/// All colours used by the UI, parameterised by theme.
#[derive(Debug, Clone, Copy)]
pub struct ThemeColors {
    // Backgrounds
    pub bg_surface: Color,
    pub bg_surface_alt: Color,
    pub bg_primary: Color,
    pub bg_panel: Color,
    pub bg_highlight: Color,

    // Text
    pub accent: Color,
    pub text_muted: Color,
    pub text: Color,
    pub text_bright: Color,

    // Semantic
    pub color_required: Color,
    pub color_dev: Color,
    pub color_optional: Color,
    pub color_error: Color,
    pub color_warning: Color,

    // Vulnerability severity
    pub vuln_critical: Color,
    pub vuln_high: Color,
    pub vuln_medium: Color,
    pub vuln_low: Color,

    // Borders / guides
    pub border: Color,
    pub border_active: Color,
    pub tree_guide: Color,
}

impl ThemeColors {
    /// Dark palette — mirrors Textual's dark theme tokens.
    pub fn dark() -> Self {
        Self {
            bg_surface: Color::Rgb(30, 30, 30),
            bg_surface_alt: Color::Rgb(38, 38, 38),
            bg_primary: Color::Rgb(0, 45, 80),
            bg_panel: Color::Rgb(35, 35, 40),
            bg_highlight: Color::Rgb(0, 80, 140),

            accent: Color::Rgb(0, 135, 255),
            text_muted: Color::Rgb(135, 135, 135),
            text: Color::Rgb(220, 220, 220),
            text_bright: Color::Rgb(255, 255, 255),

            color_required: Color::Rgb(80, 200, 120),
            color_dev: Color::Rgb(255, 183, 77),
            color_optional: Color::Rgb(171, 71, 188),

            color_error: Color::Rgb(230, 80, 80),
            color_warning: Color::Rgb(255, 200, 50),

            vuln_critical: Color::Rgb(230, 50, 50),
            vuln_high: Color::Rgb(255, 120, 50),
            vuln_medium: Color::Rgb(255, 200, 50),
            vuln_low: Color::Rgb(255, 255, 100),

            border: Color::Rgb(60, 60, 60),
            border_active: Color::Rgb(80, 80, 90),
            tree_guide: Color::Rgb(70, 70, 70),
        }
    }

    /// Light palette — designed for readability on light terminal backgrounds.
    pub fn light() -> Self {
        Self {
            bg_surface: Color::Rgb(250, 250, 250),
            bg_surface_alt: Color::Rgb(240, 240, 240),
            bg_primary: Color::Rgb(200, 220, 245),
            bg_panel: Color::Rgb(235, 235, 240),
            bg_highlight: Color::Rgb(180, 215, 255),

            accent: Color::Rgb(0, 90, 200),
            text_muted: Color::Rgb(110, 110, 110),
            text: Color::Rgb(30, 30, 30),
            text_bright: Color::Rgb(0, 0, 0),

            color_required: Color::Rgb(30, 140, 60),
            color_dev: Color::Rgb(180, 120, 0),
            color_optional: Color::Rgb(140, 50, 160),

            color_error: Color::Rgb(200, 40, 40),
            color_warning: Color::Rgb(180, 140, 0),

            vuln_critical: Color::Rgb(200, 30, 30),
            vuln_high: Color::Rgb(220, 90, 20),
            vuln_medium: Color::Rgb(180, 140, 0),
            vuln_low: Color::Rgb(160, 160, 0),

            border: Color::Rgb(200, 200, 200),
            border_active: Color::Rgb(160, 160, 170),
            tree_guide: Color::Rgb(180, 180, 180),
        }
    }
}

/// Detect the OS/terminal colour scheme.
///
/// Uses the `COLORFGBG` environment variable (set by many terminals) as a
/// heuristic: if the background component is dark (≤ 6) we return `Dark`,
/// otherwise `Light`.  Falls back to `Dark` when the variable is absent.
pub fn detect_os_theme() -> Theme {
    // COLORFGBG is "fg;bg" where bg is a colour index (0-15).
    // Indices 0-6 are typically dark colours; 7+ are light.
    if let Ok(val) = std::env::var("COLORFGBG")
        && let Some(bg_str) = val.rsplit(';').next()
        && let Ok(bg) = bg_str.parse::<u8>()
        && bg > 6
    {
        return Theme::Light;
    }
    Theme::Dark
}
