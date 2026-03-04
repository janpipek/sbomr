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

    pub fn registry_url(&self) -> Option<String> {
        purl_to_url(&self.purl)
    }
}

/// Convert a Package URL (purl) to a browsable registry URL.
///
/// Supports the most common purl types:
///   pkg:pypi/NAME@VERSION       -> https://pypi.org/project/NAME/VERSION/
///   pkg:npm/%40SCOPE/NAME@VER   -> https://www.npmjs.com/package/@scope/name/v/VER
///   pkg:npm/NAME@VER            -> https://www.npmjs.com/package/name/v/VER
///   pkg:cargo/NAME@VER          -> https://crates.io/crates/NAME/VER
///   pkg:gem/NAME@VER            -> https://rubygems.org/gems/NAME/versions/VER
///   pkg:maven/GROUP/NAME@VER    -> https://central.sonatype.com/artifact/GROUP/NAME/VER
///   pkg:nuget/NAME@VER          -> https://www.nuget.org/packages/NAME/VER
///   pkg:golang/MODULE@VER       -> https://pkg.go.dev/MODULE@VER
///   pkg:composer/VENDOR/NAME@V  -> https://packagist.org/packages/VENDOR/NAME#VER
///   pkg:hex/NAME@VER            -> https://hex.pm/packages/NAME/VER
///   pkg:cocoapods/NAME@VER      -> https://cocoapods.org/pods/NAME
///   pkg:pub/NAME@VER            -> https://pub.dev/packages/NAME/versions/VER
///   pkg:swift/HOST/OWNER/REPO@V -> https://HOST/OWNER/REPO (tag VER)
///   pkg:hackage/NAME@VER        -> https://hackage.haskell.org/package/NAME-VER
///   pkg:cran/NAME@VER           -> https://cran.r-project.org/package=NAME
fn purl_to_url(purl: &str) -> Option<String> {
    // purl format: pkg:TYPE/[NAMESPACE/]NAME@VERSION[?qualifiers][#subpath]
    let purl = purl.strip_prefix("pkg:")?;

    // Split off qualifiers and subpath
    let purl = purl.split('?').next().unwrap_or(purl);
    let purl = purl.split('#').next().unwrap_or(purl);

    let (pkg_type, rest) = purl.split_once('/')?;
    let pkg_type = pkg_type.to_lowercase();

    // Split name@version (version may be absent)
    let (path, version) = match rest.rsplit_once('@') {
        Some((p, v)) => (p, Some(v)),
        None => (rest, None),
    };

    // URL-decode %40 -> @ for npm scoped packages etc.
    let path_decoded = path.replace("%40", "@");

    match pkg_type.as_str() {
        "pypi" => {
            // PyPI normalises names: underscores -> hyphens, lowercase
            let name = path_decoded.replace('_', "-").to_lowercase();
            match version {
                Some(v) => Some(format!("https://pypi.org/project/{name}/{v}/")),
                None => Some(format!("https://pypi.org/project/{name}/")),
            }
        }
        "npm" => {
            // npm: path may be @scope/name or just name
            let name = path_decoded.to_lowercase();
            match version {
                Some(v) => Some(format!("https://www.npmjs.com/package/{name}/v/{v}")),
                None => Some(format!("https://www.npmjs.com/package/{name}")),
            }
        }
        "cargo" => match version {
            Some(v) => Some(format!("https://crates.io/crates/{path_decoded}/{v}")),
            None => Some(format!("https://crates.io/crates/{path_decoded}")),
        },
        "gem" => match version {
            Some(v) => Some(format!(
                "https://rubygems.org/gems/{path_decoded}/versions/{v}"
            )),
            None => Some(format!("https://rubygems.org/gems/{path_decoded}")),
        },
        "maven" => {
            // Maven purl: pkg:maven/group/artifact@version
            // group uses '/' separators in purl
            match version {
                Some(v) => Some(format!(
                    "https://central.sonatype.com/artifact/{path_decoded}/{v}"
                )),
                None => Some(format!(
                    "https://central.sonatype.com/artifact/{path_decoded}"
                )),
            }
        }
        "nuget" => match version {
            Some(v) => Some(format!("https://www.nuget.org/packages/{path_decoded}/{v}")),
            None => Some(format!("https://www.nuget.org/packages/{path_decoded}")),
        },
        "golang" => {
            // Go modules: pkg:golang/github.com/foo/bar@v1.2.3
            match version {
                Some(v) => Some(format!("https://pkg.go.dev/{path_decoded}@{v}")),
                None => Some(format!("https://pkg.go.dev/{path_decoded}")),
            }
        }
        "composer" => {
            // Packagist: pkg:composer/vendor/package@version
            match version {
                Some(v) => Some(format!("https://packagist.org/packages/{path_decoded}#{v}")),
                None => Some(format!("https://packagist.org/packages/{path_decoded}")),
            }
        }
        "hex" => match version {
            Some(v) => Some(format!("https://hex.pm/packages/{path_decoded}/{v}")),
            None => Some(format!("https://hex.pm/packages/{path_decoded}")),
        },
        "cocoapods" => Some(format!("https://cocoapods.org/pods/{path_decoded}")),
        "pub" => match version {
            Some(v) => Some(format!(
                "https://pub.dev/packages/{path_decoded}/versions/{v}"
            )),
            None => Some(format!("https://pub.dev/packages/{path_decoded}")),
        },
        "swift" => {
            // Swift purl: pkg:swift/github.com/owner/repo@version
            Some(format!("https://{path_decoded}"))
        }
        "hackage" => match version {
            Some(v) => Some(format!(
                "https://hackage.haskell.org/package/{path_decoded}-{v}"
            )),
            None => Some(format!(
                "https://hackage.haskell.org/package/{path_decoded}"
            )),
        },
        "cran" => Some(format!("https://cran.r-project.org/package={path_decoded}")),
        _ => None,
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

    // -- purl_to_url tests --------------------------------------------------

    #[test]
    fn purl_pypi() {
        assert_eq!(
            purl_to_url("pkg:pypi/click@8.3.1"),
            Some("https://pypi.org/project/click/8.3.1/".into())
        );
    }

    #[test]
    fn purl_pypi_normalises_underscores() {
        assert_eq!(
            purl_to_url("pkg:pypi/my_package@1.0"),
            Some("https://pypi.org/project/my-package/1.0/".into())
        );
    }

    #[test]
    fn purl_cargo() {
        assert_eq!(
            purl_to_url("pkg:cargo/serde@1.0.228"),
            Some("https://crates.io/crates/serde/1.0.228".into())
        );
    }

    #[test]
    fn purl_npm_unscoped() {
        assert_eq!(
            purl_to_url("pkg:npm/express@4.18.2"),
            Some("https://www.npmjs.com/package/express/v/4.18.2".into())
        );
    }

    #[test]
    fn purl_npm_scoped() {
        assert_eq!(
            purl_to_url("pkg:npm/%40angular/core@16.0.0"),
            Some("https://www.npmjs.com/package/@angular/core/v/16.0.0".into())
        );
    }

    #[test]
    fn purl_gem() {
        assert_eq!(
            purl_to_url("pkg:gem/rails@7.0.4"),
            Some("https://rubygems.org/gems/rails/versions/7.0.4".into())
        );
    }

    #[test]
    fn purl_maven() {
        assert_eq!(
            purl_to_url("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
            Some(
                "https://central.sonatype.com/artifact/org.apache.commons/commons-lang3/3.12.0"
                    .into()
            )
        );
    }

    #[test]
    fn purl_nuget() {
        assert_eq!(
            purl_to_url("pkg:nuget/Newtonsoft.Json@13.0.1"),
            Some("https://www.nuget.org/packages/Newtonsoft.Json/13.0.1".into())
        );
    }

    #[test]
    fn purl_golang() {
        assert_eq!(
            purl_to_url("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
            Some("https://pkg.go.dev/github.com/gin-gonic/gin@v1.9.1".into())
        );
    }

    #[test]
    fn purl_composer() {
        assert_eq!(
            purl_to_url("pkg:composer/laravel/framework@10.0"),
            Some("https://packagist.org/packages/laravel/framework#10.0".into())
        );
    }

    #[test]
    fn purl_hex() {
        assert_eq!(
            purl_to_url("pkg:hex/phoenix@1.7.7"),
            Some("https://hex.pm/packages/phoenix/1.7.7".into())
        );
    }

    #[test]
    fn purl_cocoapods() {
        assert_eq!(
            purl_to_url("pkg:cocoapods/Alamofire@5.8.0"),
            Some("https://cocoapods.org/pods/Alamofire".into())
        );
    }

    #[test]
    fn purl_pub() {
        assert_eq!(
            purl_to_url("pkg:pub/flutter@3.10.0"),
            Some("https://pub.dev/packages/flutter/versions/3.10.0".into())
        );
    }

    #[test]
    fn purl_hackage() {
        assert_eq!(
            purl_to_url("pkg:hackage/aeson@2.1.0"),
            Some("https://hackage.haskell.org/package/aeson-2.1.0".into())
        );
    }

    #[test]
    fn purl_cran() {
        assert_eq!(
            purl_to_url("pkg:cran/ggplot2@3.4.0"),
            Some("https://cran.r-project.org/package=ggplot2".into())
        );
    }

    #[test]
    fn purl_swift() {
        assert_eq!(
            purl_to_url("pkg:swift/github.com/apple/swift-nio@2.50.0"),
            Some("https://github.com/apple/swift-nio".into())
        );
    }

    #[test]
    fn purl_no_version() {
        assert_eq!(
            purl_to_url("pkg:pypi/requests"),
            Some("https://pypi.org/project/requests/".into())
        );
    }

    #[test]
    fn purl_with_qualifiers() {
        assert_eq!(
            purl_to_url("pkg:cargo/serde@1.0.0?features=derive"),
            Some("https://crates.io/crates/serde/1.0.0".into())
        );
    }

    #[test]
    fn purl_unknown_type() {
        assert_eq!(purl_to_url("pkg:unknown/foo@1.0"), None);
    }

    #[test]
    fn purl_invalid() {
        assert_eq!(purl_to_url("not-a-purl"), None);
    }

    #[test]
    fn parse_own_bom() {
        let sbom = parse_sbom(Path::new("bom.json")).expect("failed to parse own bom.json");
        assert!(!sbom.root_name.is_empty(), "root name should not be empty");
        assert!(!sbom.components.is_empty(), "should have components");
        assert!(!sbom.tree_roots.is_empty(), "should have tree roots");

        // All components should be cargo packages
        for comp in sbom.components.values() {
            assert!(
                comp.purl.starts_with("pkg:cargo/"),
                "{} has unexpected purl: {}",
                comp.name,
                comp.purl
            );
        }

        // ratatui should be a direct (required) dependency
        let ratatui = sbom
            .components
            .values()
            .find(|c| c.name == "ratatui")
            .expect("ratatui not found in components");
        assert_eq!(
            ratatui.dep_type,
            DepType::Required,
            "ratatui should be Required, got {:?}",
            ratatui.dep_type
        );
    }
}
