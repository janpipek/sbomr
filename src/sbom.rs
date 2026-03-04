//! CycloneDX SBOM parser and data model.

use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Raw CycloneDX JSON structs (serde)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawBom {
    metadata: Option<RawMetadata>,
    #[serde(default)]
    components: Vec<RawComponent>,
    #[serde(default)]
    dependencies: Vec<RawDependency>,
}

#[derive(Deserialize)]
struct RawMetadata {
    component: Option<RawMetaComponent>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetaComponent {
    name: Option<String>,
    version: Option<String>,
    #[serde(default, rename = "bom-ref")]
    bom_ref: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawComponent {
    name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    purl: Option<String>,
    #[serde(default, rename = "bom-ref")]
    bom_ref: Option<String>,
    scope: Option<String>,
    #[serde(default)]
    licenses: Vec<RawLicenseEntry>,
    #[serde(default)]
    properties: Vec<RawProperty>,
}

#[derive(Deserialize)]
struct RawLicenseEntry {
    license: Option<RawLicense>,
    expression: Option<String>,
}

#[derive(Deserialize)]
struct RawLicense {
    id: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct RawProperty {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDependency {
    #[serde(rename = "ref")]
    dep_ref: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

// ---------------------------------------------------------------------------
// Application data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepType {
    Required,
    Dev(String), // group name, e.g. "dev", "type"
    Optional,    // scope=optional without a group
    Transitive,
}

impl DepType {
    pub fn label(&self) -> String {
        match self {
            DepType::Required => "required".into(),
            DepType::Dev(group) => format!("dev ({group})"),
            DepType::Optional => "optional".into(),
            DepType::Transitive => "transitive".into(),
        }
    }

    /// Sort order: required < dev < optional < transitive.
    pub fn sort_key(&self) -> u8 {
        match self {
            DepType::Required => 0,
            DepType::Dev(_) => 1,
            DepType::Optional => 2,
            DepType::Transitive => 3,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub description: String,
    pub purl: String,
    pub bom_ref: String,
    pub licenses: Vec<String>,
    pub scope: String,
    pub dep_group: String,
    pub is_direct: bool,
    pub dep_type: DepType,
}

impl Component {
    pub fn license_str(&self) -> String {
        if self.licenses.is_empty() {
            "(none)".into()
        } else {
            self.licenses.join(", ")
        }
    }
}

/// A node in the dependency tree for the Tree tab.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TreeNode {
    pub label: String,
    pub bom_ref: String,
    pub children: Vec<TreeNode>,
    pub depth: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SBOMData {
    pub root_name: String,
    pub root_version: String,
    pub root_ref: String,
    pub components: BTreeMap<String, Component>, // keyed by bom-ref
    pub dep_graph: HashMap<String, Vec<String>>, // ref -> dependsOn refs
    pub sorted_components: Vec<String>,          // bom-refs sorted for table
    pub tree_roots: Vec<TreeNode>,               // top-level tree categories
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn extract_licenses(raw: &[RawLicenseEntry]) -> Vec<String> {
    let mut result = Vec::new();
    for entry in raw {
        if let Some(expr) = &entry.expression {
            result.push(expr.clone());
        } else if let Some(lic) = &entry.license {
            if let Some(id) = &lic.id {
                result.push(id.clone());
            } else if let Some(name) = &lic.name {
                result.push(name.clone());
            }
        }
    }
    result
}

fn get_property(props: &[RawProperty], name: &str) -> Option<String> {
    props.iter().find_map(|p| {
        if p.name.as_deref() == Some(name) {
            p.value.clone()
        } else {
            None
        }
    })
}

pub fn parse_sbom(path: &Path) -> color_eyre::Result<SBOMData> {
    let content = fs::read_to_string(path)?;
    let raw: RawBom = serde_json::from_str(&content)?;

    // Root component
    let meta_comp = raw.metadata.as_ref().and_then(|m| m.component.as_ref());
    let root_name = meta_comp
        .and_then(|c| c.name.clone())
        .unwrap_or_else(|| "unknown".into());
    let root_version = meta_comp
        .and_then(|c| c.version.clone())
        .unwrap_or_else(|| "0.0.0".into());
    let root_ref = meta_comp
        .and_then(|c| c.bom_ref.clone())
        .unwrap_or_default();

    // Dependency graph
    let mut dep_graph: HashMap<String, Vec<String>> = HashMap::new();
    for dep in &raw.dependencies {
        dep_graph.insert(dep.dep_ref.clone(), dep.depends_on.clone());
    }

    let root_direct: HashSet<String> = dep_graph
        .get(&root_ref)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();

    // Find all refs that are children of some non-root component
    let mut all_child_refs: HashSet<String> = HashSet::new();
    for (ref_key, deps) in &dep_graph {
        if ref_key != &root_ref {
            for d in deps {
                all_child_refs.insert(d.clone());
            }
        }
    }

    // Parse components (dep_type assigned in a second pass once we know all_child_refs)
    let mut components = BTreeMap::new();
    let mut dev_refs: HashSet<String> = HashSet::new();

    for rc in &raw.components {
        let bom_ref = rc
            .bom_ref
            .clone()
            .or_else(|| rc.purl.clone())
            .unwrap_or_default();
        let name = rc.name.clone().unwrap_or_default();
        let version = rc.version.clone().unwrap_or_default();
        let description = rc.description.clone().unwrap_or_default();
        let purl = rc.purl.clone().unwrap_or_default();
        let licenses = extract_licenses(&rc.licenses);
        let scope = rc.scope.clone().unwrap_or_else(|| "required".into());
        let dep_group = get_property(&rc.properties, "cdx:pyproject:group").unwrap_or_default();
        let is_direct = root_direct.contains(&bom_ref);

        if !dep_group.is_empty() {
            dev_refs.insert(bom_ref.clone());
        }

        components.insert(
            bom_ref.clone(),
            Component {
                name,
                version,
                description,
                purl,
                bom_ref: bom_ref.clone(),
                licenses,
                scope,
                dep_group,
                is_direct,
                // Placeholder — resolved below once all_child_refs is available.
                dep_type: DepType::Transitive,
            },
        );
    }

    // Second pass: classify dep_type using all_child_refs to distinguish
    // optional extras from true transitive deps.
    for (bom_ref, comp) in components.iter_mut() {
        comp.dep_type = if !comp.dep_group.is_empty() {
            DepType::Dev(comp.dep_group.clone())
        } else if comp.scope == "optional" {
            DepType::Optional
        } else if comp.is_direct {
            DepType::Required
        } else if !all_child_refs.contains(bom_ref) {
            // Not a direct dep, not dev, not scoped optional, and not a
            // transitive child of any other component — this is an optional
            // extra (e.g. from [project.optional-dependencies]).
            DepType::Optional
        } else {
            DepType::Transitive
        };
    }

    // Sorted component refs for the table display
    let mut sorted_components: Vec<String> = components.keys().cloned().collect();
    sorted_components.sort_by(|a, b| {
        let ca = &components[a];
        let cb = &components[b];
        ca.dep_type
            .sort_key()
            .cmp(&cb.dep_type.sort_key())
            .then_with(|| ca.name.to_lowercase().cmp(&cb.name.to_lowercase()))
    });

    // Build tree structure
    let tree_roots = build_tree(
        &root_ref,
        &root_direct,
        &dev_refs,
        &all_child_refs,
        &components,
        &dep_graph,
    );

    Ok(SBOMData {
        root_name,
        root_version,
        root_ref,
        components,
        dep_graph,
        sorted_components,
        tree_roots,
    })
}

// ---------------------------------------------------------------------------
// Tree building
// ---------------------------------------------------------------------------

fn build_tree(
    _root_ref: &str,
    root_direct: &HashSet<String>,
    dev_refs: &HashSet<String>,
    all_child_refs: &HashSet<String>,
    components: &BTreeMap<String, Component>,
    dep_graph: &HashMap<String, Vec<String>>,
) -> Vec<TreeNode> {
    let mut roots = Vec::new();

    // 1. Required (direct deps of root)
    if !root_direct.is_empty() {
        let mut children = Vec::new();
        let mut sorted_direct: Vec<&String> = root_direct.iter().collect();
        sorted_direct.sort();
        for r in sorted_direct {
            children.push(build_subtree(
                r,
                components,
                dep_graph,
                &mut HashSet::new(),
                1,
            ));
        }
        roots.push(TreeNode {
            label: "required".into(),
            bom_ref: String::new(),
            children,
            depth: 0,
        });
    }

    // 2. Dev groups
    let mut dev_groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (bom_ref, comp) in components {
        if !comp.dep_group.is_empty() {
            dev_groups
                .entry(comp.dep_group.clone())
                .or_default()
                .push(bom_ref.clone());
        }
    }
    for (group_name, refs) in &dev_groups {
        let mut children = Vec::new();
        let mut sorted_refs = refs.clone();
        sorted_refs.sort();
        for r in &sorted_refs {
            children.push(build_subtree(
                r,
                components,
                dep_graph,
                &mut HashSet::new(),
                1,
            ));
        }
        roots.push(TreeNode {
            label: format!("dev ({group_name})"),
            bom_ref: String::new(),
            children,
            depth: 0,
        });
    }

    // 3. Optional extras: not root direct, not dev, not a child of another component
    let mut optional_extras: Vec<String> = Vec::new();
    let grouped_refs: HashSet<&String> = root_direct.iter().chain(dev_refs.iter()).collect();
    for (bom_ref, comp) in components {
        if !grouped_refs.contains(bom_ref)
            && !all_child_refs.contains(bom_ref)
            && comp.dep_group.is_empty()
        {
            optional_extras.push(bom_ref.clone());
        }
    }
    if !optional_extras.is_empty() {
        optional_extras.sort();
        let mut children = Vec::new();
        for r in &optional_extras {
            children.push(build_subtree(
                r,
                components,
                dep_graph,
                &mut HashSet::new(),
                1,
            ));
        }
        roots.push(TreeNode {
            label: "optional extras".into(),
            bom_ref: String::new(),
            children,
            depth: 0,
        });
    }

    roots
}

fn build_subtree(
    bom_ref: &str,
    components: &BTreeMap<String, Component>,
    dep_graph: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    depth: usize,
) -> TreeNode {
    if visited.contains(bom_ref) {
        let label = components
            .get(bom_ref)
            .map(|c| format!("{} {} (circular)", c.name, c.version))
            .unwrap_or_else(|| format!("{bom_ref} (circular)"));
        return TreeNode {
            label,
            bom_ref: bom_ref.to_string(),
            children: vec![],
            depth,
        };
    }

    let comp = components.get(bom_ref);
    let label = comp
        .map(|c| {
            let lic = c.license_str();
            format!("{} {}  [{}]", c.name, c.version, lic)
        })
        .unwrap_or_else(|| bom_ref.to_string());

    let deps = dep_graph.get(bom_ref).cloned().unwrap_or_default();
    let mut children = Vec::new();
    if !deps.is_empty() {
        visited.insert(bom_ref.to_string());
        let mut sorted = deps;
        sorted.sort();
        for child in &sorted {
            children.push(build_subtree(
                child,
                components,
                dep_graph,
                visited,
                depth + 1,
            ));
        }
        visited.remove(bom_ref);
    }

    TreeNode {
        label,
        bom_ref: bom_ref.to_string(),
        children,
        depth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn click_is_optional() {
        let sbom = parse_sbom(Path::new("../bom.json")).expect("failed to parse bom.json");
        // Find click
        let click = sbom
            .components
            .values()
            .find(|c| c.name == "click")
            .expect("click not found in components");
        assert_eq!(
            click.dep_type,
            DepType::Optional,
            "click should be Optional, got {:?}",
            click.dep_type
        );
    }

    #[test]
    fn toolz_is_required() {
        let sbom = parse_sbom(Path::new("../bom.json")).expect("failed to parse bom.json");
        let toolz = sbom
            .components
            .values()
            .find(|c| c.name == "toolz")
            .expect("toolz not found in components");
        assert_eq!(
            toolz.dep_type,
            DepType::Required,
            "toolz should be Required, got {:?}",
            toolz.dep_type
        );
    }

    #[test]
    fn mypy_is_dev() {
        let sbom = parse_sbom(Path::new("../bom.json")).expect("failed to parse bom.json");
        let mypy = sbom
            .components
            .values()
            .find(|c| c.name == "mypy")
            .expect("mypy not found in components");
        assert!(
            matches!(mypy.dep_type, DepType::Dev(_)),
            "mypy should be Dev, got {:?}",
            mypy.dep_type
        );
    }

    #[test]
    fn colorama_is_transitive() {
        let sbom = parse_sbom(Path::new("../bom.json")).expect("failed to parse bom.json");
        let colorama = sbom
            .components
            .values()
            .find(|c| c.name == "colorama")
            .expect("colorama not found in components");
        assert_eq!(
            colorama.dep_type,
            DepType::Transitive,
            "colorama should be Transitive, got {:?}",
            colorama.dep_type
        );
    }
}
