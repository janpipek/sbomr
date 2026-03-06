//! Application state and input handling.

use crate::sbom::{
    Component, FlatJsonLine, JsonNode, JsonNodeKind, SBOMData, TreeNode, build_tree,
    build_tree_by_source, flatten_json,
};
use crate::theme::Theme;
use ratatui::layout::Rect;
use ratatui::widgets::TableState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Table,
    Tree,
    Vulns,
    Metadata,
    Json,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Table => Tab::Tree,
            Tab::Tree => Tab::Vulns,
            Tab::Vulns => Tab::Metadata,
            Tab::Metadata => Tab::Json,
            Tab::Json => Tab::Table,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Table => Tab::Json,
            Tab::Tree => Tab::Table,
            Tab::Vulns => Tab::Tree,
            Tab::Metadata => Tab::Vulns,
            Tab::Json => Tab::Metadata,
        }
    }
}

// ---------------------------------------------------------------------------
// Tree grouping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeGrouping {
    DepType,
    Source,
}

impl TreeGrouping {
    pub fn next(self) -> Self {
        match self {
            TreeGrouping::DepType => TreeGrouping::Source,
            TreeGrouping::Source => TreeGrouping::DepType,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TreeGrouping::DepType => "by dependency type",
            TreeGrouping::Source => "by source file",
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
    Scope,
    Registry,
    Type,
}

#[allow(dead_code)]
impl SortColumn {
    pub const ALL: &[SortColumn] = &[
        SortColumn::Name,
        SortColumn::Version,
        SortColumn::Registry,
        SortColumn::Type,
        SortColumn::License,
        SortColumn::Scope,
    ];

    pub fn label(self) -> &'static str {
        match self {
            SortColumn::Name => "Name",
            SortColumn::Version => "Version",
            SortColumn::License => "License",
            SortColumn::Scope => "Scope",
            SortColumn::Registry => "Registry",
            SortColumn::Type => "Type",
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
    Scope,
    Type,
}

impl FilterColumn {
    pub const ALL: &[FilterColumn] = &[
        FilterColumn::Name,
        FilterColumn::License,
        FilterColumn::Scope,
        FilterColumn::Type,
    ];

    pub fn label(self) -> &'static str {
        match self {
            FilterColumn::Name => "Name",
            FilterColumn::License => "License",
            FilterColumn::Scope => "Scope",
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
    /// Area of the JSON viewer body (rows)
    pub json_body: Option<Rect>,
    /// Area of the vulnerability table body
    pub vuln_body: Option<Rect>,
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
    pub tree_grouping: TreeGrouping,
    pub tree_selected: usize,
    pub tree_scroll_offset: usize,
    pub tree_roots: Vec<StatefulNode>,
    pub flat_tree: Vec<FlatTreeLine>,

    // Vulnerabilities table
    pub vuln_table_state: TableState,
    pub vuln_count: usize,

    // Metadata scroll
    pub metadata_scroll_offset: usize,
    pub metadata_line_count: usize,

    // JSON viewer (collapsible tree)
    pub json_root: JsonNode,
    pub flat_json: Vec<FlatJsonLine>,
    pub json_selected: usize,
    pub json_scroll_offset: usize,

    // Component JSON overlay
    pub comp_json_active: bool,
    pub comp_json_root: JsonNode,
    pub comp_json_flat: Vec<FlatJsonLine>,
    pub comp_json_selected: usize,
    pub comp_json_scroll: usize,

    /// Areas saved after each draw for mouse click handling.
    pub click_areas: ClickAreas,

    pub should_quit: bool,
}

impl App {
    pub fn new(sbom: SBOMData, theme: Theme) -> Self {
        let tree_roots = build_stateful_tree(&sbom.tree_roots);
        let flat_tree = flatten_visible(&tree_roots);
        let json_root = sbom.json_root.clone();
        let flat_json = flatten_json(&json_root);

        let vuln_count = sbom.vulnerabilities.len();
        let mut app = App {
            sbom,
            active_tab: Tab::Table,
            input_mode: InputMode::Normal,
            theme,
            table_state: TableState::default(),
            visible_rows: Vec::new(),
            sort_column: SortColumn::Name,
            sort_direction: SortDirection::Asc,
            filter_column: FilterColumn::Name,
            filter_text: String::new(),
            filter_input_buf: String::new(),
            tree_grouping: TreeGrouping::DepType,
            tree_selected: 0,
            tree_scroll_offset: 0,
            tree_roots,
            flat_tree,
            vuln_table_state: TableState::default(),
            vuln_count,
            metadata_scroll_offset: 0,
            metadata_line_count: 0,
            json_root,
            flat_json,
            json_selected: 0,
            json_scroll_offset: 0,
            comp_json_active: false,
            comp_json_root: JsonNode {
                key: None,
                kind: JsonNodeKind::Object,
                children: vec![],
                expanded: true,
                child_count: 0,
            },
            comp_json_flat: vec![],
            comp_json_selected: 0,
            comp_json_scroll: 0,
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
            Tab::Vulns | Tab::Metadata | Tab::Json => None,
        }
    }

    pub fn vuln_selected(&self) -> usize {
        self.vuln_table_state.selected().unwrap_or(0)
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
                    FilterColumn::Scope => comp.scope.to_lowercase().contains(&filter_lower),
                    FilterColumn::Type => comp.comp_type.to_lowercase().contains(&filter_lower),
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

    pub fn cycle_tree_grouping(&mut self) {
        self.tree_grouping = self.tree_grouping.next();
        let new_roots = match self.tree_grouping {
            TreeGrouping::DepType => build_tree(
                &self.sbom.root_ref,
                &self.sbom.root_direct,
                &self.sbom.dev_refs,
                &self.sbom.all_child_refs,
                &self.sbom.components,
                &self.sbom.dep_graph,
            ),
            TreeGrouping::Source => {
                build_tree_by_source(&self.sbom.components, &self.sbom.dep_graph)
            }
        };
        self.tree_roots = build_stateful_tree(&new_roots);
        self.tree_selected = 0;
        self.tree_scroll_offset = 0;
        self.rebuild_flat_tree();
    }

    // -- Navigation ---------------------------------------------------------

    pub fn json_len(&self) -> usize {
        self.flat_json.len()
    }

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
            Tab::Vulns => {
                let i = self.vuln_selected();
                if i > 0 {
                    self.vuln_table_state.select(Some(i - 1));
                }
            }
            Tab::Json => {
                if self.json_selected > 0 {
                    self.json_selected -= 1;
                }
            }
            Tab::Metadata => {
                if self.metadata_scroll_offset > 0 {
                    self.metadata_scroll_offset -= 1;
                }
            }
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
            Tab::Vulns => {
                let i = self.vuln_selected();
                if i + 1 < self.vuln_count {
                    self.vuln_table_state.select(Some(i + 1));
                }
            }
            Tab::Json => {
                if self.json_selected + 1 < self.json_len() {
                    self.json_selected += 1;
                }
            }
            Tab::Metadata => {
                self.metadata_scroll_offset += 1;
            }
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
            Tab::Vulns => {
                let i = self.vuln_selected().saturating_sub(page_size);
                self.vuln_table_state.select(Some(i));
            }
            Tab::Json => {
                self.json_selected = self.json_selected.saturating_sub(page_size);
            }
            Tab::Metadata => {
                self.metadata_scroll_offset = self.metadata_scroll_offset.saturating_sub(page_size);
            }
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
            Tab::Vulns => {
                let max = self.vuln_count.saturating_sub(1);
                let i = (self.vuln_selected() + page_size).min(max);
                self.vuln_table_state.select(Some(i));
            }
            Tab::Json => {
                let max = self.json_len().saturating_sub(1);
                self.json_selected = (self.json_selected + page_size).min(max);
            }
            Tab::Metadata => {
                self.metadata_scroll_offset = (self.metadata_scroll_offset + page_size)
                    .min(self.metadata_line_count.saturating_sub(1));
            }
        }
    }

    pub fn home(&mut self) {
        match self.active_tab {
            Tab::Table => self.table_state.select(Some(0)),
            Tab::Tree => self.tree_selected = 0,
            Tab::Vulns => self.vuln_table_state.select(Some(0)),
            Tab::Json => self.json_selected = 0,
            Tab::Metadata => self.metadata_scroll_offset = 0,
        }
    }

    pub fn end(&mut self) {
        match self.active_tab {
            Tab::Table => self
                .table_state
                .select(Some(self.table_len().saturating_sub(1))),
            Tab::Tree => self.tree_selected = self.tree_len().saturating_sub(1),
            Tab::Vulns => self
                .vuln_table_state
                .select(Some(self.vuln_count.saturating_sub(1))),
            Tab::Json => self.json_selected = self.json_len().saturating_sub(1),
            Tab::Metadata => {
                self.metadata_scroll_offset = self.metadata_line_count.saturating_sub(1);
            }
        }
    }

    pub fn adjust_json_scroll(&mut self, viewport_height: usize) {
        if self.json_selected < self.json_scroll_offset {
            self.json_scroll_offset = self.json_selected;
        } else if self.json_selected >= self.json_scroll_offset + viewport_height {
            self.json_scroll_offset = self.json_selected - viewport_height + 1;
        }
    }

    // -- JSON tree expand/collapse ------------------------------------------

    fn json_node_at_path_mut<'a>(
        node: &'a mut JsonNode,
        path: &[usize],
    ) -> Option<&'a mut JsonNode> {
        if path.is_empty() {
            return Some(node);
        }
        let mut current = node;
        for &idx in path {
            current = current.children.get_mut(idx)?;
        }
        Some(current)
    }

    pub fn toggle_json_selected(&mut self) {
        if let Some(line) = self.flat_json.get(self.json_selected) {
            if !line.collapsible {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = Self::json_node_at_path_mut(&mut self.json_root, &path) {
                node.expanded = !node.expanded;
            }
            self.rebuild_flat_json();
        }
    }

    pub fn expand_json_selected(&mut self) {
        if let Some(line) = self.flat_json.get(self.json_selected) {
            if !line.collapsible || line.expanded {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = Self::json_node_at_path_mut(&mut self.json_root, &path) {
                node.expanded = true;
            }
            self.rebuild_flat_json();
        }
    }

    pub fn collapse_json_selected(&mut self) {
        if let Some(line) = self.flat_json.get(self.json_selected) {
            if line.collapsible && line.expanded {
                let path = line.path.clone();
                if let Some(node) = Self::json_node_at_path_mut(&mut self.json_root, &path) {
                    node.expanded = false;
                }
                self.rebuild_flat_json();
                return;
            }
            // If on a leaf or collapsed node, collapse the parent
            if !line.path.is_empty() {
                let parent_path = &line.path[..line.path.len() - 1];
                if let Some(node) = Self::json_node_at_path_mut(&mut self.json_root, parent_path)
                    && matches!(node.kind, JsonNodeKind::Object | JsonNodeKind::Array)
                {
                    node.expanded = false;
                }
                let pp = parent_path.to_vec();
                self.rebuild_flat_json();
                // Move selection to the collapsed parent
                if let Some(idx) = self.flat_json.iter().position(|l| l.path == pp) {
                    self.json_selected = idx;
                }
            }
        }
    }

    fn set_json_expanded_recursive(node: &mut JsonNode, expanded: bool) {
        if matches!(node.kind, JsonNodeKind::Object | JsonNodeKind::Array) {
            node.expanded = expanded;
        }
        for child in &mut node.children {
            Self::set_json_expanded_recursive(child, expanded);
        }
    }

    pub fn expand_all_json(&mut self) {
        Self::set_json_expanded_recursive(&mut self.json_root, true);
        self.rebuild_flat_json();
    }

    pub fn collapse_all_json(&mut self) {
        Self::set_json_expanded_recursive(&mut self.json_root, false);
        self.rebuild_flat_json();
        self.json_selected = self.json_selected.min(self.json_len().saturating_sub(1));
    }

    fn rebuild_flat_json(&mut self) {
        self.flat_json = flatten_json(&self.json_root);
        if self.json_selected >= self.flat_json.len() {
            self.json_selected = self.flat_json.len().saturating_sub(1);
        }
    }

    // -- Component JSON overlay --------------------------------------------

    pub fn comp_json_len(&self) -> usize {
        self.comp_json_flat.len()
    }

    pub fn open_comp_json(&mut self) {
        let bom_ref = match self.selected_bom_ref() {
            Some(r) => r.to_string(),
            None => return,
        };
        let comp = match self.sbom.components.get(&bom_ref) {
            Some(c) => c,
            None => return,
        };
        let value = crate::sbom::component_to_json_value(comp);
        self.comp_json_root = crate::sbom::build_json_tree(&value);
        self.comp_json_flat = flatten_json(&self.comp_json_root);
        self.comp_json_selected = 0;
        self.comp_json_scroll = 0;
        self.comp_json_active = true;
    }

    pub fn close_comp_json(&mut self) {
        self.comp_json_active = false;
    }

    pub fn adjust_comp_json_scroll(&mut self, viewport_height: usize) {
        if self.comp_json_selected < self.comp_json_scroll {
            self.comp_json_scroll = self.comp_json_selected;
        } else if self.comp_json_selected >= self.comp_json_scroll + viewport_height {
            self.comp_json_scroll = self.comp_json_selected - viewport_height + 1;
        }
    }

    pub fn comp_json_move_up(&mut self) {
        if self.comp_json_selected > 0 {
            self.comp_json_selected -= 1;
        }
    }

    pub fn comp_json_move_down(&mut self) {
        if self.comp_json_selected + 1 < self.comp_json_len() {
            self.comp_json_selected += 1;
        }
    }

    pub fn comp_json_page_up(&mut self, page_size: usize) {
        self.comp_json_selected = self.comp_json_selected.saturating_sub(page_size);
    }

    pub fn comp_json_page_down(&mut self, page_size: usize) {
        let max = self.comp_json_len().saturating_sub(1);
        self.comp_json_selected = (self.comp_json_selected + page_size).min(max);
    }

    pub fn comp_json_home(&mut self) {
        self.comp_json_selected = 0;
    }

    pub fn comp_json_end(&mut self) {
        self.comp_json_selected = self.comp_json_len().saturating_sub(1);
    }

    pub fn toggle_comp_json_selected(&mut self) {
        if let Some(line) = self.comp_json_flat.get(self.comp_json_selected) {
            if !line.collapsible {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = Self::json_node_at_path_mut(&mut self.comp_json_root, &path) {
                node.expanded = !node.expanded;
            }
            self.rebuild_comp_json_flat();
        }
    }

    pub fn expand_comp_json_selected(&mut self) {
        if let Some(line) = self.comp_json_flat.get(self.comp_json_selected) {
            if !line.collapsible || line.expanded {
                return;
            }
            let path = line.path.clone();
            if let Some(node) = Self::json_node_at_path_mut(&mut self.comp_json_root, &path) {
                node.expanded = true;
            }
            self.rebuild_comp_json_flat();
        }
    }

    pub fn collapse_comp_json_selected(&mut self) {
        if let Some(line) = self.comp_json_flat.get(self.comp_json_selected) {
            if line.collapsible && line.expanded {
                let path = line.path.clone();
                if let Some(node) =
                    Self::json_node_at_path_mut(&mut self.comp_json_root, &path)
                {
                    node.expanded = false;
                }
                self.rebuild_comp_json_flat();
                return;
            }
            if !line.path.is_empty() {
                let parent_path = line.path[..line.path.len() - 1].to_vec();
                if let Some(node) =
                    Self::json_node_at_path_mut(&mut self.comp_json_root, &parent_path)
                    && matches!(node.kind, JsonNodeKind::Object | JsonNodeKind::Array)
                {
                    node.expanded = false;
                }
                self.rebuild_comp_json_flat();
                if let Some(idx) = self.comp_json_flat.iter().position(|l| l.path == parent_path)
                {
                    self.comp_json_selected = idx;
                }
            }
        }
    }

    pub fn expand_all_comp_json(&mut self) {
        Self::set_json_expanded_recursive(&mut self.comp_json_root, true);
        self.rebuild_comp_json_flat();
    }

    pub fn collapse_all_comp_json(&mut self) {
        Self::set_json_expanded_recursive(&mut self.comp_json_root, false);
        self.rebuild_comp_json_flat();
        self.comp_json_selected = self
            .comp_json_selected
            .min(self.comp_json_len().saturating_sub(1));
    }

    fn rebuild_comp_json_flat(&mut self) {
        self.comp_json_flat = flatten_json(&self.comp_json_root);
        if self.comp_json_selected >= self.comp_json_flat.len() {
            self.comp_json_selected = self.comp_json_flat.len().saturating_sub(1);
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
        SortColumn::Scope => a
            .scope
            .to_lowercase()
            .cmp(&b.scope.to_lowercase())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        SortColumn::Registry => a
            .registry
            .to_lowercase()
            .cmp(&b.registry.to_lowercase())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        SortColumn::Type => a
            .comp_type
            .to_lowercase()
            .cmp(&b.comp_type.to_lowercase())
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
            expanded: true, // categories start expanded
            children: build_stateful_children(&root.children, 1),
        })
        .collect()
}

fn build_stateful_children(children: &[TreeNode], depth: usize) -> Vec<StatefulNode> {
    children
        .iter()
        .map(|child| StatefulNode {
            label: child.label.clone(),
            bom_ref: child.bom_ref.clone(),
            is_category: false,
            expanded: depth < 1, // only first level under categories is visible
            children: build_stateful_children(&child.children, depth + 1),
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
