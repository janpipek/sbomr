//! Application state and input handling.

use crate::sbom::{Component, SBOMData, TreeNode};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Table,
    Tree,
    Metadata,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Table => Tab::Tree,
            Tab::Tree => Tab::Metadata,
            Tab::Metadata => Tab::Table,
        }
    }
}

// ---------------------------------------------------------------------------
// Sort / Filter types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Name,
    Version,
    License,
    Type,
    Registry,
}

#[allow(dead_code)]
impl SortColumn {
    pub const ALL: &[SortColumn] = &[
        SortColumn::Name,
        SortColumn::Version,
        SortColumn::License,
        SortColumn::Type,
        SortColumn::Registry,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SortColumn::Name => "Name",
            SortColumn::Version => "Version",
            SortColumn::License => "License",
            SortColumn::Type => "Type",
            SortColumn::Registry => "Registry",
        }
    }

    /// Cycle to the next sort column.
    pub fn next(self) -> Self {
        let all = Self::ALL;
        let idx = all.iter().position(|&c| c == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    pub fn toggle(self) -> Self {
        match self {
            SortDirection::Asc => SortDirection::Desc,
            SortDirection::Desc => SortDirection::Asc,
        }
    }

    pub fn indicator(self) -> &'static str {
        match self {
            SortDirection::Asc => "▲",
            SortDirection::Desc => "▼",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterColumn {
    Name,
    License,
    Type,
}

impl FilterColumn {
    pub const ALL: &[FilterColumn] = &[
        FilterColumn::Name,
        FilterColumn::License,
        FilterColumn::Type,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FilterColumn::Name => "Name",
            FilterColumn::License => "License",
            FilterColumn::Type => "Type",
        }
    }

    pub fn next(self) -> Self {
        let all = Self::ALL;
        let idx = all.iter().position(|&c| c == self).unwrap_or(0);
        all[(idx + 1) % all.len()]
    }
}

/// Whether the user is typing a filter string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    FilterInput,
}

// ---------------------------------------------------------------------------
// Persistent collapsible tree
// ---------------------------------------------------------------------------

/// A node in the stateful tree that remembers its expanded/collapsed state.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StatefulNode {
    pub label: String,
    pub bom_ref: String,
    pub is_category: bool,
    pub expanded: bool,
    pub children: Vec<StatefulNode>,
}

impl StatefulNode {
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }

    pub fn set_expanded_recursive(&mut self, expanded: bool) {
        self.expanded = expanded;
        for child in &mut self.children {
            child.set_expanded_recursive(expanded);
        }
    }
}

/// A single visible line produced by flattening the tree (respecting collapsed nodes).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FlatTreeLine {
    pub depth: usize,
    pub label: String,
    pub bom_ref: String,
    pub is_category: bool,
    pub is_last_child: bool,
    pub has_children: bool,
    pub expanded: bool,
    pub path: Vec<usize>,
    pub guides: Vec<bool>,
}

// ---------------------------------------------------------------------------
// Click areas — stored after each draw so the event loop can do hit-testing
// ---------------------------------------------------------------------------

/// Saved layout regions for mouse hit-testing.
#[derive(Debug, Clone, Default)]
pub struct ClickAreas {
    /// Area of each tab label: (area, Tab)
    pub tabs: Vec<(Rect, Tab)>,
    /// Area of each sortable column header: (area, SortColumn)
    pub column_headers: Vec<(Rect, SortColumn)>,
    /// Area of the table body (rows)
    pub table_body: Option<Rect>,
    /// Area of the tree body (rows)
    pub tree_body: Option<Rect>,
    /// Panel title bars that act as tab switches: (area, Tab)
    pub panel_titles: Vec<(Rect, Tab)>,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub sbom: SBOMData,
    pub active_tab: Tab,
    pub input_mode: InputMode,
    pub theme: Theme,

    // Table
    pub table_state: TableState,
    /// The filtered+sorted list of bom-refs currently shown in the table.
    pub visible_rows: Vec<String>,

    // Sort
    pub sort_column: SortColumn,
    pub sort_direction: SortDirection,

    // Filter
    pub filter_column: FilterColumn,
    pub filter_text: String,
    /// Temporary buffer while the user is typing in FilterInput mode.
    pub filter_input_buf: String,

    // Tree
    pub tree_selected: usize,
    pub tree_scroll_offset: usize,
    pub tree_roots: Vec<StatefulNode>,
    pub flat_tree: Vec<FlatTreeLine>,

    /// Areas saved after each draw for mouse click handling.
    pub click_areas: ClickAreas,

    pub should_quit: bool,
}

impl App {
    pub fn new(sbom: SBOMData, theme: Theme) -> Self {
        let tree_roots = build_stateful_tree(&sbom.tree_roots);
        let flat_tree = flatten_visible(&tree_roots);

        let mut app = App {
            sbom,
            active_tab: Tab::Table,
            input_mode: InputMode::Normal,
            theme,
            table_state: TableState::default(),
            visible_rows: Vec::new(),
            sort_column: SortColumn::Type,
            sort_direction: SortDirection::Asc,
            filter_column: FilterColumn::Name,
            filter_text: String::new(),
            filter_input_buf: String::new(),
            tree_selected: 0,
            tree_scroll_offset: 0,
            tree_roots,
            flat_tree,
            click_areas: ClickAreas::default(),
            should_quit: false,
        };
        app.rebuild_visible_rows();
        app
    }

    pub fn table_len(&self) -> usize {
        self.visible_rows.len()
    }

    pub fn tree_len(&self) -> usize {
        self.flat_tree.len()
    }

    fn table_selected(&self) -> usize {
        self.table_state.selected().unwrap_or(0)
    }

    pub fn selected_bom_ref(&self) -> Option<&str> {
        match self.active_tab {
            Tab::Table => self
                .visible_rows
                .get(self.table_selected())
                .map(|s| s.as_str()),
            Tab::Tree => self
                .flat_tree
                .get(self.tree_selected)
                .filter(|l| !l.bom_ref.is_empty())
                .map(|l| l.bom_ref.as_str()),
            Tab::Metadata => None,
        }
    }

    pub fn has_active_filter(&self) -> bool {
        !self.filter_text.is_empty()
    }

    pub fn toggle_theme(&mut self) {
        self.theme = self.theme.toggle();
    }

    // -- Sort / Filter ------------------------------------------------------

    pub fn cycle_sort_column(&mut self) {
        self.sort_column = self.sort_column.next();
        self.rebuild_visible_rows();
    }

    pub fn toggle_sort_direction(&mut self) {
        self.sort_direction = self.sort_direction.toggle();
        self.rebuild_visible_rows();
    }

    /// Set sort to a specific column. If already sorted by that column, toggle direction.
    pub fn set_sort_column(&mut self, col: SortColumn) {
        if self.sort_column == col {
            self.sort_direction = self.sort_direction.toggle();
        } else {
            self.sort_column = col;
            self.sort_direction = SortDirection::Asc;
        }
        self.rebuild_visible_rows();
    }

    pub fn cycle_filter_column(&mut self) {
        self.filter_column = self.filter_column.next();
        // Re-apply existing filter with new column
        if self.has_active_filter() {
            self.rebuild_visible_rows();
        }
    }

    pub fn begin_filter_input(&mut self) {
        self.input_mode = InputMode::FilterInput;
        self.filter_input_buf = self.filter_text.clone();
    }

    pub fn filter_input_char(&mut self, ch: char) {
        self.filter_input_buf.push(ch);
    }

    pub fn filter_input_backspace(&mut self) {
        self.filter_input_buf.pop();
    }

    pub fn filter_input_confirm(&mut self) {
        self.filter_text = self.filter_input_buf.clone();
        self.input_mode = InputMode::Normal;
        self.rebuild_visible_rows();
    }

    pub fn filter_input_cancel(&mut self) {
        self.filter_input_buf.clear();
        self.input_mode = InputMode::Normal;
    }

    pub fn clear_filter(&mut self) {
        self.filter_text.clear();
        self.filter_input_buf.clear();
        self.input_mode = InputMode::Normal;
        self.rebuild_visible_rows();
    }

    /// Rebuild the visible_rows list based on current filter + sort settings.
    fn rebuild_visible_rows(&mut self) {
        let filter_lower = self.filter_text.to_lowercase();
        let has_filter = !filter_lower.is_empty();

        // 1. Filter
        let mut rows: Vec<String> = self
            .sbom
            .sorted_components
            .iter()
            .filter(|bom_ref| {
                if !has_filter {
                    return true;
                }
                let comp = match self.sbom.components.get(*bom_ref) {
                    Some(c) => c,
                    None => return false,
                };
                match self.filter_column {
                    FilterColumn::Name => comp.name.to_lowercase().contains(&filter_lower),
                    FilterColumn::License => {
                        comp.license_str().to_lowercase().contains(&filter_lower)
                    }
                    FilterColumn::Type => {
                        comp.dep_type.label().to_lowercase().contains(&filter_lower)
                    }
                }
            })
            .cloned()
            .collect();

        // 2. Sort
        let components = &self.sbom.components;
        let sort_col = self.sort_column;
        let sort_dir = self.sort_direction;

        rows.sort_by(|a, b| {
            let ca = &components[a];
            let cb = &components[b];
            let ord = compare_by_column(ca, cb, sort_col);
            match sort_dir {
                SortDirection::Asc => ord,
                SortDirection::Desc => ord.reverse(),
            }
        });

        self.visible_rows = rows;

        // Reset selection
        if self.visible_rows.is_empty() {
            self.table_state.select(None);
        } else {
            let sel = self
                .table_selected()
                .min(self.visible_rows.len().saturating_sub(1));
            self.table_state.select(Some(sel));
        }
    }

    // -- Tree expand/collapse -----------------------------------------------

    pub fn toggle_selected(&mut self) {
        if let Some(line) = self.flat_tree.get(self.tree_selected) {
            if !line.has_children {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = self.node_at_path_mut(&path) {
                node.expanded = !node.expanded;
            }
            self.rebuild_flat_tree();
        }
    }

    pub fn expand_selected(&mut self) {
        if let Some(line) = self.flat_tree.get(self.tree_selected) {
            if !line.has_children || line.expanded {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = self.node_at_path_mut(&path) {
                node.expanded = true;
            }
            self.rebuild_flat_tree();
        }
    }

    pub fn collapse_selected(&mut self) {
        if let Some(line) = self.flat_tree.get(self.tree_selected) {
            let path = line.path.clone();

            if line.has_children && line.expanded {
                if let Some(node) = self.node_at_path_mut(&path) {
                    node.expanded = false;
                }
                self.rebuild_flat_tree();
                return;
            }

            if path.len() > 1 {
                let parent_path = &path[..path.len() - 1];
                if let Some(node) = self.node_at_path_mut(parent_path) {
                    node.expanded = false;
                }
                self.rebuild_flat_tree();
                let parent_path_vec = parent_path.to_vec();
                if let Some(idx) = self
                    .flat_tree
                    .iter()
                    .position(|l| l.path == parent_path_vec)
                {
                    self.tree_selected = idx;
                }
            }
        }
    }

    pub fn expand_all(&mut self) {
        for root in &mut self.tree_roots {
            root.set_expanded_recursive(true);
        }
        self.rebuild_flat_tree();
    }

    pub fn collapse_all(&mut self) {
        for root in &mut self.tree_roots {
            root.set_expanded_recursive(false);
        }
        self.rebuild_flat_tree();
        self.tree_selected = self.tree_selected.min(self.tree_len().saturating_sub(1));
    }

    fn node_at_path_mut(&mut self, path: &[usize]) -> Option<&mut StatefulNode> {
        if path.is_empty() {
            return None;
        }
        let mut current = self.tree_roots.get_mut(path[0])?;
        for &idx in &path[1..] {
            current = current.children.get_mut(idx)?;
        }
        Some(current)
    }

    fn rebuild_flat_tree(&mut self) {
        self.flat_tree = flatten_visible(&self.tree_roots);
        if self.tree_selected >= self.flat_tree.len() {
            self.tree_selected = self.flat_tree.len().saturating_sub(1);
        }
    }

    // -- Navigation ---------------------------------------------------------

    pub fn move_up(&mut self) {
        match self.active_tab {
            Tab::Table => {
                let i = self.table_selected();
                if i > 0 {
                    self.table_state.select(Some(i - 1));
                }
            }
            Tab::Tree => {
                if self.tree_selected > 0 {
                    self.tree_selected -= 1;
                }
            }
            Tab::Metadata => {}
        }
    }

    pub fn move_down(&mut self) {
        match self.active_tab {
            Tab::Table => {
                let i = self.table_selected();
                if i + 1 < self.table_len() {
                    self.table_state.select(Some(i + 1));
                }
            }
            Tab::Tree => {
                if self.tree_selected + 1 < self.tree_len() {
                    self.tree_selected += 1;
                }
            }
            Tab::Metadata => {}
        }
    }

    pub fn page_up(&mut self, page_size: usize) {
        match self.active_tab {
            Tab::Table => {
                let i = self.table_selected().saturating_sub(page_size);
                self.table_state.select(Some(i));
            }
            Tab::Tree => {
                self.tree_selected = self.tree_selected.saturating_sub(page_size);
            }
            Tab::Metadata => {}
        }
    }

    pub fn page_down(&mut self, page_size: usize) {
        match self.active_tab {
            Tab::Table => {
                let max = self.table_len().saturating_sub(1);
                let i = (self.table_selected() + page_size).min(max);
                self.table_state.select(Some(i));
            }
            Tab::Tree => {
                let max = self.tree_len().saturating_sub(1);
                self.tree_selected = (self.tree_selected + page_size).min(max);
            }
            Tab::Metadata => {}
        }
    }

    pub fn home(&mut self) {
        match self.active_tab {
            Tab::Table => self.table_state.select(Some(0)),
            Tab::Tree => self.tree_selected = 0,
            Tab::Metadata => {}
        }
    }

    pub fn end(&mut self) {
        match self.active_tab {
            Tab::Table => self
                .table_state
                .select(Some(self.table_len().saturating_sub(1))),
            Tab::Tree => self.tree_selected = self.tree_len().saturating_sub(1),
            Tab::Metadata => {}
        }
    }

    /// Select a table row by visible index (from mouse click).
    pub fn select_table_row(&mut self, row: usize) {
        if row < self.table_len() {
            self.table_state.select(Some(row));
        }
    }

    /// Select a tree row by visible index (from mouse click).
    pub fn select_tree_row(&mut self, row: usize) {
        if row < self.tree_len() {
            self.tree_selected = row;
        }
    }

    pub fn adjust_tree_scroll(&mut self, viewport_height: usize) {
        if self.tree_selected < self.tree_scroll_offset {
            self.tree_scroll_offset = self.tree_selected;
        } else if self.tree_selected >= self.tree_scroll_offset + viewport_height {
            self.tree_scroll_offset = self.tree_selected - viewport_height + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Sort comparator
// ---------------------------------------------------------------------------

fn compare_by_column(a: &Component, b: &Component, col: SortColumn) -> std::cmp::Ordering {
    match col {
        SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        SortColumn::Version => a.version.cmp(&b.version),
        SortColumn::License => a
            .license_str()
            .to_lowercase()
            .cmp(&b.license_str().to_lowercase()),
        SortColumn::Type => a
            .dep_type
            .sort_key()
            .cmp(&b.dep_type.sort_key())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        SortColumn::Registry => a
            .registry
            .to_lowercase()
            .cmp(&b.registry.to_lowercase())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
    }
}

// ---------------------------------------------------------------------------
// Build stateful tree from parsed TreeNodes
// ---------------------------------------------------------------------------

fn build_stateful_tree(roots: &[TreeNode]) -> Vec<StatefulNode> {
    roots
        .iter()
        .map(|root| StatefulNode {
            label: root.label.clone(),
            bom_ref: root.bom_ref.clone(),
            is_category: true,
            expanded: true,
            children: build_stateful_children(&root.children),
        })
        .collect()
}

fn build_stateful_children(children: &[TreeNode]) -> Vec<StatefulNode> {
    children
        .iter()
        .map(|child| StatefulNode {
            label: child.label.clone(),
            bom_ref: child.bom_ref.clone(),
            is_category: false,
            expanded: true,
            children: build_stateful_children(&child.children),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Flatten visible tree (skips children of collapsed nodes)
// ---------------------------------------------------------------------------

fn flatten_visible(roots: &[StatefulNode]) -> Vec<FlatTreeLine> {
    let mut lines = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        let is_last = i == roots.len() - 1;
        lines.push(FlatTreeLine {
            depth: 0,
            label: root.label.clone(),
            bom_ref: root.bom_ref.clone(),
            is_category: true,
            is_last_child: is_last,
            has_children: root.has_children(),
            expanded: root.expanded,
            path: vec![i],
            guides: vec![],
        });
        if root.expanded {
            let parent_guides = vec![!is_last];
            flatten_visible_children(&root.children, 1, &mut lines, &[i], &parent_guides);
        }
    }
    lines
}

fn flatten_visible_children(
    children: &[StatefulNode],
    depth: usize,
    lines: &mut Vec<FlatTreeLine>,
    parent_path: &[usize],
    parent_guides: &[bool],
) {
    for (i, child) in children.iter().enumerate() {
        let is_last = i == children.len() - 1;
        let mut path = parent_path.to_vec();
        path.push(i);
        let guides = parent_guides.to_vec();

        lines.push(FlatTreeLine {
            depth,
            label: child.label.clone(),
            bom_ref: child.bom_ref.clone(),
            is_category: false,
            is_last_child: is_last,
            has_children: child.has_children(),
            expanded: child.expanded,
            path: path.clone(),
            guides: guides.clone(),
        });
        if child.expanded && child.has_children() {
            let mut child_guides = guides;
            child_guides.push(!is_last);
            flatten_visible_children(&child.children, depth + 1, lines, &path, &child_guides);
        }
    }
}
