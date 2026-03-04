//! Application state and input handling.

use crate::sbom::{SBOMData, TreeNode};
use ratatui::widgets::TableState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Table,
    Tree,
}

impl Tab {
    pub fn next(self) -> Self {
        match self {
            Tab::Table => Tab::Tree,
            Tab::Tree => Tab::Table,
        }
    }
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

    /// Recursively set expanded state on this node and all descendants.
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
    /// Path of indices into the StatefulNode tree so we can find it for toggling.
    pub path: Vec<usize>,
    /// For each ancestor depth (1..depth), whether to draw a vertical guide `│`.
    /// `guides[i]` is true if the ancestor at depth `i+1` is NOT the last child
    /// (i.e. there are more siblings below, so the vertical line continues).
    pub guides: Vec<bool>,
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub struct App {
    pub sbom: SBOMData,
    pub active_tab: Tab,
    pub table_state: TableState,
    pub tree_selected: usize,
    pub tree_scroll_offset: usize,
    /// The persistent stateful tree (nodes remember expanded state).
    pub tree_roots: Vec<StatefulNode>,
    /// Flattened visible lines, rebuilt after every expand/collapse.
    pub flat_tree: Vec<FlatTreeLine>,
    pub should_quit: bool,
}

impl App {
    pub fn new(sbom: SBOMData) -> Self {
        let tree_roots = build_stateful_tree(&sbom.tree_roots);
        let flat_tree = flatten_visible(&tree_roots);
        let mut table_state = TableState::default();
        if !sbom.sorted_components.is_empty() {
            table_state.select(Some(0));
        }
        App {
            sbom,
            active_tab: Tab::Table,
            table_state,
            tree_selected: 0,
            tree_scroll_offset: 0,
            tree_roots,
            flat_tree,
            should_quit: false,
        }
    }

    pub fn table_len(&self) -> usize {
        self.sbom.sorted_components.len()
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
                .sbom
                .sorted_components
                .get(self.table_selected())
                .map(|s| s.as_str()),
            Tab::Tree => self
                .flat_tree
                .get(self.tree_selected)
                .filter(|l| !l.bom_ref.is_empty())
                .map(|l| l.bom_ref.as_str()),
        }
    }

    // -- Tree expand/collapse -----------------------------------------------

    /// Toggle the currently selected tree node between expanded and collapsed.
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

    /// Expand the currently selected node (no-op if leaf or already expanded).
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

    /// Collapse the currently selected node. If it's a leaf or already collapsed,
    /// jump to and collapse the parent instead.
    pub fn collapse_selected(&mut self) {
        if let Some(line) = self.flat_tree.get(self.tree_selected) {
            let path = line.path.clone();

            // If it's expanded and has children, collapse it.
            if line.has_children && line.expanded {
                if let Some(node) = self.node_at_path_mut(&path) {
                    node.expanded = false;
                }
                self.rebuild_flat_tree();
                return;
            }

            // Otherwise, jump to parent and collapse it.
            if path.len() > 1 {
                let parent_path = &path[..path.len() - 1];
                if let Some(node) = self.node_at_path_mut(parent_path) {
                    node.expanded = false;
                }
                self.rebuild_flat_tree();
                // Find the parent line and select it
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

    /// Expand all nodes in the tree.
    pub fn expand_all(&mut self) {
        for root in &mut self.tree_roots {
            root.set_expanded_recursive(true);
        }
        self.rebuild_flat_tree();
    }

    /// Collapse all nodes in the tree.
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
        // Clamp selection
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
        }
    }

    pub fn home(&mut self) {
        match self.active_tab {
            Tab::Table => self.table_state.select(Some(0)),
            Tab::Tree => self.tree_selected = 0,
        }
    }

    pub fn end(&mut self) {
        match self.active_tab {
            Tab::Table => self
                .table_state
                .select(Some(self.table_len().saturating_sub(1))),
            Tab::Tree => self.tree_selected = self.tree_len().saturating_sub(1),
        }
    }

    /// Ensure the selected tree row is visible within the given viewport height.
    pub fn adjust_tree_scroll(&mut self, viewport_height: usize) {
        if self.tree_selected < self.tree_scroll_offset {
            self.tree_scroll_offset = self.tree_selected;
        } else if self.tree_selected >= self.tree_scroll_offset + viewport_height {
            self.tree_scroll_offset = self.tree_selected - viewport_height + 1;
        }
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
            // Children of a category root: the guide for depth-0 continues
            // if this root is not the last category.
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

        // Guides for this line: inherit parent guides (they tell us which
        // ancestor columns need a vertical bar), but exclude the current
        // depth — that is rendered as ├/└ by the drawing code.
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
            // Extend guides for the next depth level: this child's column
            // needs a vertical bar if it is NOT the last sibling.
            let mut child_guides = guides;
            child_guides.push(!is_last);
            flatten_visible_children(&child.children, depth + 1, lines, &path, &child_guides);
        }
    }
}
