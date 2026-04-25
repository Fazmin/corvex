//! package-lock.json, yarn.lock, and package.json parsers for
//! JavaScript/Node.js dependencies.

use crate::sca::component::{Component, Ecosystem};
use crate::sca::parsers::ManifestParser;
use std::path::Path;

pub struct NpmParser;

impl ManifestParser for NpmParser {
    fn file_names(&self) -> &[&str] {
        // package.json is last on purpose: if both it and a lockfile
        // exist in the same directory, the scanner already prefers
        // the lockfile (lockfile names match first in the parser
        // loop). package.json is the fallback for pre-install trees.
        &["package-lock.json", "yarn.lock", "package.json"]
    }

    fn parse(&self, path: &Path) -> Result<Vec<Component>, String> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match name {
            "yarn.lock" => parse_yarn_lock(path),
            "package.json" => parse_package_json(path),
            _ => parse_package_lock(path),
        }
    }
}

fn parse_package_lock(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("json parse: {e}"))?;

    let mut components = Vec::new();

    // package-lock.json v2/v3 format: "packages" object
    if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in packages {
            // Skip the root package (empty key or ".")
            if key.is_empty() || key == "." {
                continue;
            }
            // Extract name from the key (node_modules/name or node_modules/@scope/name)
            let pkg_name = key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(key)
                .to_string();
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !pkg_name.is_empty() && !version.is_empty() {
                components.push(
                    Component::new(&pkg_name, &version, Ecosystem::Npm)
                        .with_source(path.to_path_buf()),
                );
            }
        }
    }
    // package-lock.json v1 format: "dependencies" object
    else if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
        parse_npm_deps_recursive(deps, path, &mut components);
    }

    Ok(components)
}

fn parse_npm_deps_recursive(
    deps: &serde_json::Map<String, serde_json::Value>,
    path: &Path,
    components: &mut Vec<Component>,
) {
    for (name, val) in deps {
        let version = val
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !version.is_empty() {
            components.push(
                Component::new(name, &version, Ecosystem::Npm).with_source(path.to_path_buf()),
            );
        }
        // Recurse into nested dependencies
        if let Some(nested) = val.get("dependencies").and_then(|d| d.as_object()) {
            parse_npm_deps_recursive(nested, path, components);
        }
    }
}

/// Parse a plain `package.json`. Only runs when there's no sibling
/// lockfile — if `package-lock.json`, `yarn.lock`, or
/// `pnpm-lock.yaml` is present, the lockfile is authoritative and
/// this parser returns no components (to avoid double-counting, and
/// because the lockfile has exact resolved versions whereas
/// package.json only has semver ranges).
///
/// For pre-install trees (newly cloned repo, CI cache miss) where
/// only `package.json` exists, we fall back to the manifest's own
/// `dependencies` + `devDependencies` and strip the `^`, `~`, `>=`
/// range prefixes to get a concrete version we can match a CVE
/// against. Version ranges that can't be resolved to a single
/// concrete version are best-effort — matches may over-report.
fn parse_package_json(path: &Path) -> Result<Vec<Component>, String> {
    // Skip if a lockfile sibling exists; the lockfile parser will
    // produce richer, more accurate components.
    if let Some(dir) = path.parent() {
        for lock in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"] {
            if dir.join(lock).exists() {
                return Ok(Vec::new());
            }
        }
    }

    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("json parse: {e}"))?;

    let mut components = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (name, val) in deps {
                let raw = val.as_str().unwrap_or("").trim();
                let version = strip_range_prefix(raw);
                if !version.is_empty() {
                    components.push(
                        Component::new(name, version, Ecosystem::Npm)
                            .with_source(path.to_path_buf()),
                    );
                }
            }
        }
    }
    Ok(components)
}

/// Best-effort conversion of a semver range like `^4.18.2` or
/// `~1.0.0` or `>=3.2.1 <4` into a concrete-looking version. We take
/// the first numeric token — it's what npm would resolve to as a
/// lower bound, which is the pessimistic choice for CVE matching.
fn strip_range_prefix(raw: &str) -> &str {
    let trimmed = raw.trim_start_matches(|c: char| {
        matches!(c, '^' | '~' | '=' | '>' | '<' | ' ' | 'v' | 'V')
    });
    // Cut off at the first whitespace (handles "1.0.0 || 2.0.0",
    // ">=1.0.0 <2.0.0"). Non-numeric prefixes (git URL, file:, etc.)
    // are skipped by the caller because the resulting `version` ends
    // up empty.
    let end = trimmed
        .find(|c: char| c.is_whitespace() || c == '|')
        .unwrap_or(trimmed.len());
    let candidate = &trimmed[..end];
    // If it doesn't start with a digit, treat as unresolvable (e.g.
    // "workspace:*", "file:...", "git+ssh://..."). Caller filters on
    // empty.
    if candidate.chars().next().map(|c| c.is_ascii_digit()) != Some(true) {
        return "";
    }
    candidate
}

fn parse_yarn_lock(path: &Path) -> Result<Vec<Component>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    let mut components = Vec::new();
    let mut current_name: Option<String> = None;

    for line in content.lines() {
        // Package header lines look like: "express@^4.18.0, express@~4.18.2":
        // or: express@^4.18.0:
        if !line.starts_with(' ') && !line.starts_with('#') && line.contains('@') && line.ends_with(':') {
            let header = line.trim_end_matches(':').trim_matches('"');
            // Take the first specifier and extract the name
            if let Some(spec) = header.split(',').next() {
                let spec = spec.trim().trim_matches('"');
                // Find the last @ that separates name from version spec
                if let Some(at_pos) = spec.rfind('@') {
                    if at_pos > 0 {
                        current_name = Some(spec[..at_pos].to_string());
                    }
                }
            }
        }
        // Version line: "  version "1.2.3""
        if let Some(ref name) = current_name {
            let trimmed = line.trim();
            if let Some(ver_str) = trimmed.strip_prefix("version ") {
                let version = ver_str.trim().trim_matches('"').to_string();
                if !version.is_empty() {
                    components.push(
                        Component::new(name, &version, Ecosystem::Npm)
                            .with_source(path.to_path_buf()),
                    );
                }
                current_name = None;
            }
        }
    }

    Ok(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_range_prefix_handles_common_forms() {
        assert_eq!(strip_range_prefix("^4.18.2"), "4.18.2");
        assert_eq!(strip_range_prefix("~1.0.0"), "1.0.0");
        assert_eq!(strip_range_prefix(">=3.2.1 <4"), "3.2.1");
        assert_eq!(strip_range_prefix("= 2.0.0"), "2.0.0");
        assert_eq!(strip_range_prefix("1.2.3"), "1.2.3");
        // Unresolvable: git URL, file:, workspace:*, latest
        assert_eq!(strip_range_prefix("workspace:*"), "");
        assert_eq!(strip_range_prefix("file:../local"), "");
        assert_eq!(strip_range_prefix("git+ssh://example"), "");
        assert_eq!(strip_range_prefix("latest"), "");
    }

    #[test]
    fn package_json_parses_when_no_lockfile() {
        let dir = std::env::temp_dir().join(format!(
            "corvex-pkgjson-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = dir.join("package.json");
        std::fs::write(
            &pkg,
            r#"{
              "name": "fake",
              "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
              "devDependencies": {"jest": "29.0.0"}
            }"#,
        )
        .unwrap();
        let rows = parse_package_json(&pkg).unwrap();
        let names: Vec<_> = rows.iter().map(|c| (c.name.as_str(), c.version.as_str())).collect();
        assert!(names.contains(&("express", "4.18.2")));
        assert!(names.contains(&("lodash", "4.17.21")));
        assert!(names.contains(&("jest", "29.0.0")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_json_defers_to_sibling_lockfile() {
        let dir = std::env::temp_dir().join(format!(
            "corvex-pkgjson-defer-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let pkg = dir.join("package.json");
        std::fs::write(
            &pkg,
            r#"{"dependencies": {"express": "^4.18.2"}}"#,
        )
        .unwrap();
        std::fs::write(dir.join("package-lock.json"), "{}").unwrap();
        let rows = parse_package_json(&pkg).unwrap();
        assert!(rows.is_empty(), "package.json should defer when lockfile is present");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
