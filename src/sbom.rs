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
    #[serde(default)]
    vulnerabilities: Vec<RawVulnerability>,
    serial_number: Option<String>,
    spec_version: Option<String>,
    #[serde(default)]
    annotations: Vec<RawAnnotation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMetadata {
    component: Option<RawMetaComponent>,
    timestamp: Option<String>,
    tools: Option<RawTools>,
    #[serde(default)]
    lifecycles: Vec<RawLifecycle>,
    #[serde(default)]
    properties: Vec<RawProperty>,
}

#[derive(Deserialize)]
struct RawTools {
    #[serde(default)]
    components: Vec<RawToolComponent>,
}

#[derive(Deserialize)]
struct RawToolComponent {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Deserialize)]
struct RawLifecycle {
    phase: Option<String>,
}

#[derive(Deserialize)]
struct RawAnnotation {
    text: Option<String>,
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
    evidence: Option<RawEvidence>,
    #[serde(default)]
    hashes: Vec<RawHash>,
    #[serde(default, rename = "externalReferences")]
    external_references: Vec<RawExternalRef>,
}

#[derive(Deserialize)]
struct RawHash {
    alg: Option<String>,
    content: Option<String>,
}

#[derive(Deserialize)]
struct RawExternalRef {
    #[serde(rename = "type")]
    ref_type: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct RawEvidence {
    #[serde(default)]
    identity: Vec<RawEvidenceIdentity>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEvidenceIdentity {
    confidence: Option<f64>,
    concluded_value: Option<String>,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVulnerability {
    id: Option<String>,
    #[serde(default)]
    affects: Vec<RawAffects>,
}

#[derive(Deserialize)]
struct RawAffects {
    #[serde(rename = "ref")]
    affects_ref: Option<String>,
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
    /// Package registry type extracted from purl (e.g. "cargo", "pypi", "npm").
    pub registry: String,
    /// Lock file / source file from evidence (e.g. "Cargo.lock", "uv.lock").
    pub source_file: String,
    /// Latest available version (from `cdx:cargo:latest_version` etc.), empty if unknown.
    pub latest_version: String,
    /// Cryptographic hashes: Vec of (algorithm, hex digest).
    pub hashes: Vec<(String, String)>,
    /// VCS (source repository) URL from externalReferences.
    pub vcs_url: String,
    /// Evidence confidence score (0.0–1.0), or None if unavailable.
    pub confidence: Option<f64>,
    /// Number of known vulnerabilities affecting this component.
    pub vuln_count: usize,
    /// Vulnerability IDs affecting this component.
    pub vuln_ids: Vec<String>,
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

    /// Whether a newer version is known and differs from the current version.
    pub fn is_outdated(&self) -> bool {
        !self.latest_version.is_empty() && self.latest_version != self.version
    }

    /// Whether any license string contains a copyleft identifier.
    pub fn has_copyleft(&self) -> bool {
        const COPYLEFT: &[&str] = &["GPL", "AGPL", "LGPL", "MPL", "EUPL", "CPAL", "OSL", "SSPL"];
        self.licenses.iter().any(|lic| {
            let upper = lic.to_uppercase();
            COPYLEFT.iter().any(|cp| upper.contains(cp))
        })
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

/// SBOM-level provenance and metadata (not per-component).
#[derive(Debug, Clone, Default)]
pub struct SBOMMetadata {
    pub timestamp: String,
    pub tool_name: String,
    pub tool_version: String,
    pub spec_version: String,
    pub serial_number: String,
    pub lifecycle_phase: String,
    pub annotation: String,
    /// From metadata.properties, e.g. "Cargo.lock".
    pub component_src_files: String,
    /// From metadata.properties, e.g. "cargo".
    pub component_types: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SBOMData {
    pub root_name: String,
    pub root_version: String,
    pub root_ref: String,
    pub components: BTreeMap<String, Component>, // keyed by bom-ref
    pub dep_graph: HashMap<String, Vec<String>>, // ref -> dependsOn refs
    pub reverse_deps: HashMap<String, Vec<String>>, // ref -> who depends on it
    pub sorted_components: Vec<String>,          // bom-refs sorted for table
    pub tree_roots: Vec<TreeNode>,               // top-level tree categories
    pub metadata: SBOMMetadata,
    pub json_root: JsonNode, // collapsible JSON tree for the JSON viewer
}

// ---------------------------------------------------------------------------
// Collapsible JSON tree
// ---------------------------------------------------------------------------

/// The kind of JSON container (object or array), or a leaf value.
#[derive(Debug, Clone)]
pub enum JsonNodeKind {
    Object,
    Array,
    Leaf(String), // rendered value text, e.g. `"hello"`, `42`, `true`, `null`
}

/// A node in the collapsible JSON tree.
#[derive(Debug, Clone)]
pub struct JsonNode {
    /// If this node is a value inside an object, the key name (without quotes).
    pub key: Option<String>,
    pub kind: JsonNodeKind,
    pub children: Vec<JsonNode>,
    pub expanded: bool,
    /// Number of leaf descendant nodes (for collapsed summary).
    pub child_count: usize,
}

/// A single visible line produced by flattening the JSON tree.
#[derive(Debug, Clone)]
pub struct FlatJsonLine {
    pub depth: usize,
    /// The key portion, e.g. `"name": ` — empty for array items.
    pub key: String,
    /// The value portion for this line (opening brace, leaf value, closing brace).
    pub value: String,
    /// Whether this node can be expanded/collapsed.
    pub collapsible: bool,
    pub expanded: bool,
    /// Path of child indices from the root to this node, for toggle.
    pub path: Vec<usize>,
    /// Whether a trailing comma should follow this line.
    pub trailing_comma: bool,
}

fn value_to_json_node(key: Option<String>, value: &serde_json::Value, depth: usize) -> JsonNode {
    match value {
        serde_json::Value::Object(map) => {
            let children: Vec<JsonNode> = map
                .iter()
                .map(|(k, v)| value_to_json_node(Some(k.clone()), v, depth + 1))
                .collect();
            let child_count = children.len();
            JsonNode {
                key,
                kind: JsonNodeKind::Object,
                children,
                expanded: depth == 0,
                child_count,
            }
        }
        serde_json::Value::Array(arr) => {
            let children: Vec<JsonNode> = arr
                .iter()
                .map(|v| value_to_json_node(None, v, depth + 1))
                .collect();
            let child_count = children.len();
            JsonNode {
                key,
                kind: JsonNodeKind::Array,
                children,
                expanded: depth == 0,
                child_count,
            }
        }
        other => {
            // Leaf: render as JSON text
            let text = match other {
                serde_json::Value::String(s) => {
                    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
                }
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => "null".to_string(),
                _ => other.to_string(),
            };
            JsonNode {
                key,
                kind: JsonNodeKind::Leaf(text),
                children: Vec::new(),
                expanded: false,
                child_count: 0,
            }
        }
    }
}

pub fn build_json_tree(value: &serde_json::Value) -> JsonNode {
    value_to_json_node(None, value, 0)
}

/// Flatten the JSON tree into visible lines, respecting collapsed state.
pub fn flatten_json(node: &JsonNode) -> Vec<FlatJsonLine> {
    let mut lines = Vec::new();
    flatten_json_node(node, 0, &[], false, &mut lines);
    lines
}

fn flatten_json_node(
    node: &JsonNode,
    depth: usize,
    path: &[usize],
    trailing_comma: bool,
    lines: &mut Vec<FlatJsonLine>,
) {
    let key_str = node
        .key
        .as_ref()
        .map(|k| format!("\"{k}\": "))
        .unwrap_or_default();

    match &node.kind {
        JsonNodeKind::Leaf(text) => {
            lines.push(FlatJsonLine {
                depth,
                key: key_str,
                value: text.clone(),
                collapsible: false,
                expanded: false,
                path: path.to_vec(),
                trailing_comma,
            });
        }
        JsonNodeKind::Object | JsonNodeKind::Array => {
            let (open, close) = match &node.kind {
                JsonNodeKind::Object => ("{", "}"),
                JsonNodeKind::Array => ("[", "]"),
                _ => unreachable!(),
            };

            if !node.expanded {
                // Collapsed: single line like `{ ... 5 items }` or `[ ... 3 items ]`
                let summary = format!(
                    "{open} ... {} {} {close}",
                    node.child_count,
                    if node.child_count == 1 {
                        "item"
                    } else {
                        "items"
                    }
                );
                lines.push(FlatJsonLine {
                    depth,
                    key: key_str,
                    value: summary,
                    collapsible: true,
                    expanded: false,
                    path: path.to_vec(),
                    trailing_comma,
                });
            } else {
                // Expanded: opening brace, children, closing brace
                lines.push(FlatJsonLine {
                    depth,
                    key: key_str,
                    value: open.to_string(),
                    collapsible: !node.children.is_empty(),
                    expanded: true,
                    path: path.to_vec(),
                    trailing_comma: false,
                });

                let child_count = node.children.len();
                for (i, child) in node.children.iter().enumerate() {
                    let mut child_path = path.to_vec();
                    child_path.push(i);
                    let is_last = i + 1 == child_count;
                    flatten_json_node(child, depth + 1, &child_path, !is_last, lines);
                }

                lines.push(FlatJsonLine {
                    depth,
                    key: String::new(),
                    value: close.to_string(),
                    collapsible: false,
                    expanded: false,
                    path: path.to_vec(),
                    trailing_comma,
                });
            }
        }
    }
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
    // Parse into Value for the JSON viewer tree and pretty-print for copy-all
    let json_value: serde_json::Value = serde_json::from_str(&content)?;
    let json_root = build_json_tree(&json_value);
    let raw: RawBom = serde_json::from_value(json_value)?;

    // --- SBOM-level metadata ---
    let meta = raw.metadata.as_ref();
    let sbom_metadata = {
        let timestamp = meta.and_then(|m| m.timestamp.clone()).unwrap_or_default();
        let (tool_name, tool_version) = meta
            .and_then(|m| m.tools.as_ref())
            .and_then(|t| t.components.first())
            .map(|tc| {
                (
                    tc.name.clone().unwrap_or_default(),
                    tc.version.clone().unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        let lifecycle_phase = meta
            .and_then(|m| m.lifecycles.first())
            .and_then(|l| l.phase.clone())
            .unwrap_or_default();
        let meta_props = meta.map(|m| m.properties.as_slice()).unwrap_or_default();
        let component_src_files =
            get_property(meta_props, "cdx:bom:componentSrcFiles").unwrap_or_default();
        let component_types =
            get_property(meta_props, "cdx:bom:componentTypes").unwrap_or_default();
        let annotation = raw
            .annotations
            .first()
            .and_then(|a| a.text.clone())
            .unwrap_or_default();

        SBOMMetadata {
            timestamp,
            tool_name,
            tool_version,
            spec_version: raw.spec_version.clone().unwrap_or_default(),
            serial_number: raw.serial_number.clone().unwrap_or_default(),
            lifecycle_phase,
            annotation,
            component_src_files,
            component_types,
        }
    };

    // --- Vulnerability index: bom-ref -> list of vuln IDs ---
    let mut vuln_map: HashMap<String, Vec<String>> = HashMap::new();
    for v in &raw.vulnerabilities {
        let vid = v.id.clone().unwrap_or_default();
        for a in &v.affects {
            if let Some(r) = &a.affects_ref {
                vuln_map.entry(r.clone()).or_default().push(vid.clone());
            }
        }
    }

    // Root component
    let meta_comp = meta.and_then(|m| m.component.as_ref());
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

        // Skip the root component itself — it's not a dependency.
        if bom_ref == root_ref {
            continue;
        }

        let name = rc.name.clone().unwrap_or_default();
        let version = rc.version.clone().unwrap_or_default();
        let description = rc.description.clone().unwrap_or_default();
        let purl = rc.purl.clone().unwrap_or_default();
        let licenses = extract_licenses(&rc.licenses);
        let scope = rc.scope.clone().unwrap_or_else(|| "required".into());
        let dep_group = get_property(&rc.properties, "cdx:pyproject:group").unwrap_or_default();
        let is_direct = root_direct.contains(&bom_ref);

        // Extract registry type from purl (e.g. "pkg:cargo/..." -> "cargo")
        let registry = purl
            .strip_prefix("pkg:")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or("")
            .to_string();

        // Extract source/lock file from evidence.identity[].concludedValue
        let source_file = rc
            .evidence
            .as_ref()
            .and_then(|ev| ev.identity.iter().find_map(|id| id.concluded_value.clone()))
            .unwrap_or_default();

        // Latest version from ecosystem-specific properties
        let latest_version = get_property(&rc.properties, "cdx:cargo:latest_version")
            .or_else(|| get_property(&rc.properties, "cdx:python:latest_version"))
            .unwrap_or_default();

        // Hashes
        let hashes: Vec<(String, String)> = rc
            .hashes
            .iter()
            .map(|h| {
                (
                    h.alg.clone().unwrap_or_default(),
                    h.content.clone().unwrap_or_default(),
                )
            })
            .filter(|(a, c)| !a.is_empty() && !c.is_empty())
            .collect();

        // VCS URL from externalReferences
        let vcs_url = rc
            .external_references
            .iter()
            .find(|r| r.ref_type.as_deref() == Some("vcs"))
            .and_then(|r| r.url.clone())
            .unwrap_or_default();

        // Evidence confidence
        let confidence = rc
            .evidence
            .as_ref()
            .and_then(|ev| ev.identity.first())
            .and_then(|id| id.confidence);

        // Vulnerabilities
        let vuln_ids = vuln_map.get(&bom_ref).cloned().unwrap_or_default();
        let vuln_count = vuln_ids.len();

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
                dep_type: DepType::Transitive,
                registry,
                source_file,
                latest_version,
                hashes,
                vcs_url,
                confidence,
                vuln_count,
                vuln_ids,
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

    // Build reverse dependency map (who depends on whom)
    let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();
    for (parent, children) in &dep_graph {
        if parent == &root_ref {
            continue; // skip root -> direct, that's already captured
        }
        for child in children {
            reverse_deps
                .entry(child.clone())
                .or_default()
                .push(parent.clone());
        }
    }

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
        reverse_deps,
        sorted_components,
        tree_roots,
        metadata: sbom_metadata,
        json_root,
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
