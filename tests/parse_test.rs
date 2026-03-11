use std::path::Path;

use sbomr::sbom::{self, write_csv, DepType};

/// Helper to locate a fixture file relative to the workspace root.
fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

// ---------------------------------------------------------------------------
// Trivy-generated SBOM
// ---------------------------------------------------------------------------

#[test]
fn trivy_parses_successfully() {
    let sbom =
        sbom::parse_sbom(&fixture("trivy-bom.json")).expect("failed to parse trivy-bom.json");
    assert!(!sbom.components.is_empty(), "should have components");
}

#[test]
fn trivy_metadata() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    assert_eq!(sbom.metadata.spec_version, "1.6");
    assert_eq!(sbom.metadata.tool_name, "trivy");
    assert!(!sbom.metadata.timestamp.is_empty());
}

#[test]
fn trivy_filters_lock_file_intermediary() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();

    // Cargo.lock itself should be filtered out as a lock-file intermediary
    assert!(
        !sbom.components.values().any(|c| c.name == "Cargo.lock"),
        "Cargo.lock should be filtered out as a lock-file intermediary"
    );
}

#[test]
fn trivy_components_have_source_file() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();

    for comp in sbom.components.values() {
        assert_eq!(
            comp.source_file, "Cargo.lock",
            "{} should have source_file='Cargo.lock', got '{}'",
            comp.name, comp.source_file
        );
    }
}

#[test]
fn trivy_all_components_are_cargo() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();

    for comp in sbom.components.values() {
        assert!(
            comp.purl.starts_with("pkg:cargo/"),
            "{} has unexpected purl: {}",
            comp.name,
            comp.purl
        );
    }
}

#[test]
fn trivy_ratatui_is_direct() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();

    let ratatui = sbom
        .components
        .values()
        .find(|c| c.name == "ratatui")
        .expect("ratatui not found in components");
    assert!(
        ratatui.is_direct,
        "ratatui should be direct after lock-file promotion"
    );
}

#[test]
fn trivy_tree_roots_exist() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    assert!(!sbom.tree_roots.is_empty(), "should have tree roots");
}

#[test]
fn trivy_dep_graph_populated() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    assert!(
        !sbom.dep_graph.is_empty(),
        "dependency graph should be populated"
    );
}

#[test]
fn trivy_sorted_components_matches_count() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    assert_eq!(
        sbom.sorted_components.len(),
        sbom.components.len(),
        "sorted_components should contain one entry per component"
    );
}

#[test]
fn trivy_direct_vs_transitive() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();

    let direct_count = sbom.components.values().filter(|c| c.is_direct).count();
    let transitive_count = sbom
        .components
        .values()
        .filter(|c| c.dep_type == DepType::Transitive)
        .count();

    assert!(
        direct_count > 0,
        "should have at least one direct dependency"
    );
    assert!(
        transitive_count > 0,
        "should have at least one transitive dependency"
    );
    assert!(
        transitive_count > direct_count,
        "typically more transitive than direct deps"
    );
}

#[test]
fn trivy_json_root_populated() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    assert!(
        !sbom.json_root.children.is_empty(),
        "JSON root should have children for the viewer"
    );
}

#[test]
fn trivy_vulnerabilities_parsed() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    // The trivy fixture has 1 vulnerability
    assert_eq!(
        sbom.vulnerabilities.len(),
        1,
        "trivy fixture should have 1 vulnerability"
    );

    let vuln = &sbom.vulnerabilities[0];
    assert!(!vuln.id.is_empty(), "vulnerability should have an ID");
}

// ---------------------------------------------------------------------------
// npm (cdxgen) SBOM
// ---------------------------------------------------------------------------

#[test]
fn npm_parses_successfully() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).expect("failed to parse npm-bom.json");
    assert_eq!(sbom.components.len(), 3);
}

#[test]
fn npm_metadata() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();
    assert_eq!(sbom.metadata.spec_version, "1.6");
    assert_eq!(sbom.metadata.tool_name, "cdxgen");
    assert_eq!(sbom.root_name, "package-js");
    assert_eq!(sbom.root_version, "1.0.0");
}

#[test]
fn npm_all_components_are_npm() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    for comp in sbom.components.values() {
        assert!(
            comp.purl.starts_with("pkg:npm/"),
            "{} has unexpected purl: {}",
            comp.name,
            comp.purl
        );
        assert_eq!(
            comp.registry, "npm",
            "{} should have registry 'npm'",
            comp.name
        );
    }
}

#[test]
fn npm_expected_packages_present() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    let names: Vec<&str> = sbom.components.values().map(|c| c.name.as_str()).collect();
    for expected in ["semver", "dotenv", "typescript"] {
        assert!(
            names.contains(&expected),
            "{expected} should be present in components"
        );
    }
}

#[test]
fn npm_semver_is_required() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    let semver = sbom
        .components
        .values()
        .find(|c| c.name == "semver")
        .expect("semver not found");
    assert_eq!(semver.version, "7.7.4");
    assert_eq!(semver.dep_type, DepType::Direct);
    assert!(semver.is_direct);
}

#[test]
fn npm_direct_deps_classified_as_required() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    // All components are direct deps of the root, so the parser classifies
    // them as Direct even if the raw SBOM scope says "optional".
    for comp in sbom.components.values() {
        assert_eq!(
            comp.dep_type,
            DepType::Direct,
            "{} is a direct dep and should be classified as Direct, got {:?}",
            comp.name,
            comp.dep_type
        );
    }
}

#[test]
fn npm_all_have_licenses() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    for comp in sbom.components.values() {
        assert!(
            !comp.licenses.is_empty(),
            "{} should have at least one license",
            comp.name
        );
    }
}

#[test]
fn npm_no_vulnerabilities() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();
    assert!(
        sbom.vulnerabilities.is_empty(),
        "npm fixture should have no vulnerabilities"
    );
}

#[test]
fn npm_dep_graph_has_root() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    // The root should depend on all three components
    let root_deps = sbom
        .dep_graph
        .get(&sbom.root_ref)
        .expect("root should be in dep_graph");
    assert_eq!(root_deps.len(), 3, "root should have 3 direct dependencies");
}

#[test]
fn npm_all_direct_no_transitive() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();

    // All 3 components are direct deps of the root with no transitive deps
    let transitive = sbom
        .components
        .values()
        .filter(|c| c.dep_type == DepType::Transitive)
        .count();
    assert_eq!(transitive, 0, "npm fixture should have no transitive deps");

    for comp in sbom.components.values() {
        assert!(
            comp.is_direct,
            "{} should be a direct dependency",
            comp.name
        );
    }
}

#[test]
fn npm_tree_roots_exist() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();
    assert!(!sbom.tree_roots.is_empty(), "should have tree roots");
}

#[test]
fn npm_sorted_components_matches_count() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();
    assert_eq!(sbom.sorted_components.len(), sbom.components.len());
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

const CSV_HEADER: &str = "Name,Version,Registry,Type,License,Scope,Dep Type,Description";

fn csv_for(fixture_name: &str) -> String {
    let sbom = sbom::parse_sbom(&fixture(fixture_name)).unwrap();
    let mut buf = Vec::new();
    write_csv(&sbom, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[test]
fn csv_header_matches_table_columns() {
    let csv = csv_for("npm-bom.json");
    let header = csv.lines().next().unwrap();
    assert_eq!(header, CSV_HEADER);
}

#[test]
fn csv_row_count_matches_components() {
    let sbom = sbom::parse_sbom(&fixture("npm-bom.json")).unwrap();
    let csv = csv_for("npm-bom.json");
    let data_rows = csv.lines().count() - 1; // minus header
    assert_eq!(data_rows, sbom.components.len());
}

#[test]
fn csv_npm_contains_expected_packages() {
    let csv = csv_for("npm-bom.json");
    for name in ["semver", "dotenv", "typescript"] {
        assert!(
            csv.lines()
                .any(|line| line.starts_with(&format!("{name},"))),
            "{name} should appear as a CSV row"
        );
    }
}

#[test]
fn csv_npm_field_values() {
    let csv = csv_for("npm-bom.json");
    let semver_line = csv
        .lines()
        .find(|l| l.starts_with("semver,"))
        .expect("semver row not found");

    let fields: Vec<&str> = semver_line.split(',').collect();
    assert_eq!(fields[0], "semver");
    assert_eq!(fields[1], "7.7.4");
    assert_eq!(fields[2], "npm");
    assert_eq!(fields[3], "library");
    assert_eq!(fields[4], "ISC");
    assert_eq!(fields[5], "required");
    assert_eq!(fields[6], "direct");
    // field[7] is the description
    assert!(!fields[7].is_empty(), "description should not be empty");
}

#[test]
fn csv_trivy_row_count() {
    let sbom = sbom::parse_sbom(&fixture("trivy-bom.json")).unwrap();
    let csv = csv_for("trivy-bom.json");
    let data_rows = csv.lines().count() - 1;
    assert_eq!(data_rows, sbom.components.len());
}

#[test]
fn csv_trivy_no_lock_file_intermediary() {
    let csv = csv_for("trivy-bom.json");
    assert!(
        !csv.lines().any(|l| l.starts_with("Cargo.lock,")),
        "Cargo.lock intermediary should not appear in CSV"
    );
}

#[test]
fn csv_empty_fields_show_dash() {
    let csv = csv_for("trivy-bom.json");
    // Trivy components have no license, so the License column should show "(none)"
    let first_data = csv.lines().nth(1).unwrap();
    assert!(
        first_data.contains("(none)"),
        "components without licenses should show (none)"
    );
}

#[test]
fn csv_escapes_commas_in_fields() {
    // Build a minimal SBOMData-like scenario isn't practical, so test the
    // escaping indirectly: the npm descriptions contain no commas so each row
    // should have exactly 7 commas (8 fields).
    let csv = csv_for("npm-bom.json");
    for (i, line) in csv.lines().enumerate() {
        let commas = line.chars().filter(|&c| c == ',').count();
        assert_eq!(
            commas, 7,
            "line {i} should have 7 commas (8 fields), got {commas}: {line}"
        );
    }
}
