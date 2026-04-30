//! Parse the on-disk YAML signature files into a compact in-memory
//! catalog. Each file declares one device family with one or more
//! discovery clauses.
//!
//! The YAML schema is intentionally a strict subset of the LibreNMS
//! `os_detection` shape so future bulk imports of additional vendor
//! signatures parse cleanly without code changes. Only the four fields
//! the matcher actually uses are deserialised — everything else
//! (poller_modules, icon, hardware_regex, …) is silently ignored.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml in {file}: {source}")]
    Yaml {
        file: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid regex in {file}: {pattern}: {source}")]
    Regex {
        file: PathBuf,
        pattern: String,
        #[source]
        source: fancy_regex::Error,
    },
}

/// Raw YAML schema. Permissive so unknown / future fields don't break
/// loading. Exposed publicly so the builder crate (`corvex-devicedb-builder`)
/// can parse the same YAML schema without duplicating the deserialization
/// types.
#[derive(Debug, Deserialize)]
pub struct RawDef {
    pub os: String,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default, rename = "type")]
    pub device_type: Option<String>,
    #[serde(default)]
    pub discovery: Vec<RawDiscovery>,
}

/// Permissive deserializer — the upstream YAML schema is duck-typed
/// PHP. Most fields here use `Option<OneOrMany>` because callers
/// inconsistently spell single values as scalars or one-element lists.
#[derive(Debug, Deserialize)]
pub struct RawDiscovery {
    /// Either a single string or a list of strings — upstream YAMLs
    /// inconsistently use both forms.
    #[serde(default, rename = "sysObjectID")]
    pub sys_object_id: OneOrMany,
    #[serde(default, rename = "sysObjectID_except")]
    pub sys_object_id_except: OneOrMany,
    #[serde(default, rename = "sysObjectID_regex")]
    pub sys_object_id_regex: OneOrMany,
    #[serde(default, rename = "sysDescr")]
    pub sys_descr: OneOrMany,
    #[serde(default, rename = "sysDescr_regex")]
    pub sys_descr_regex: OneOrMany,
    #[serde(default, rename = "sysDescr_except")]
    pub sys_descr_except: OneOrMany,
    #[serde(default, rename = "sysDescr_regex_except")]
    pub sys_descr_regex_except: OneOrMany,
    /// Active OID query for further disambiguation. We can't issue
    /// extra GETs from the matcher, so the presence of this field
    /// disables the entire clause (other clauses in the same file
    /// still fire normally).
    #[serde(default, rename = "snmpget")]
    pub snmpget: Option<serde_yaml::Value>,
    #[serde(default, rename = "snmpget_except")]
    pub snmpget_except: Option<serde_yaml::Value>,
    #[serde(default, rename = "snmpget_oid")]
    pub snmpget_oid: Option<serde_yaml::Value>,
}

/// Accept either `field: foo` or `field: [foo, bar]` for any of the
/// list-typed discovery fields. Empty / missing → empty Vec.
#[derive(Debug, Default)]
pub struct OneOrMany(Vec<String>);

impl<'de> Deserialize<'de> for OneOrMany {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let v = serde_yaml::Value::deserialize(d)?;
        let out = match v {
            serde_yaml::Value::Null => Vec::new(),
            serde_yaml::Value::String(s) => vec![s],
            serde_yaml::Value::Sequence(seq) => seq
                .into_iter()
                .map(|elem| match elem {
                    serde_yaml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "expected string element, got {other:?}"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?,
            other => {
                return Err(D::Error::custom(format!(
                    "expected string or sequence, got {other:?}"
                )))
            }
        };
        Ok(OneOrMany(out))
    }
}

impl OneOrMany {
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// One discovery clause inside a device file. A clause "fires" when
/// any positive condition matches AND no `_except` filter rejects.
#[derive(Debug)]
pub struct DiscoveryClause {
    pub sys_object_id_prefixes: Vec<String>,
    pub sys_object_id_except_prefixes: Vec<String>,
    pub sys_object_id_regexes: Vec<fancy_regex::Regex>,
    pub sys_descr_substrings: Vec<String>,
    pub sys_descr_regexes: Vec<fancy_regex::Regex>,
    /// Lower-cased substrings. If any appears in sysDescr, the clause
    /// is rejected even when its positive conditions matched.
    pub sys_descr_except: Vec<String>,
    /// Compiled regex variants of the above.
    pub sys_descr_regex_except: Vec<fancy_regex::Regex>,
    /// Set when the clause requires an active SNMP GET we cannot
    /// issue. Such clauses never fire — but other clauses in the same
    /// file still run normally.
    pub disabled: bool,
}

/// One compiled entry in the catalog. Holds every clause from the
/// source file in the order the file declared them.
#[derive(Debug)]
pub struct DeviceEntry {
    pub os: String,
    pub vendor: String,
    pub device_type: String,
    /// Discovery clauses in file order.
    pub clauses: Vec<DiscoveryClause>,
    /// Length of the longest sysObjectID prefix anywhere in this
    /// entry. Used by the global sort so the catalog tries longest
    /// prefixes first.
    pub max_oid_prefix_len: usize,
}

#[derive(Debug, Default)]
pub struct DeviceCatalog {
    pub entries: Vec<DeviceEntry>,
}

impl DeviceCatalog {
    /// Walk a directory of `*.yaml` / `*.yml` files and parse each one.
    /// Files that fail to parse are logged and skipped — one malformed
    /// signature shouldn't keep the rest of the catalog from loading.
    pub fn load_dir<P: AsRef<Path>>(dir: P) -> Result<Self, LoadError> {
        let dir = dir.as_ref();
        let mut entries = Vec::new();
        if !dir.is_dir() {
            tracing::warn!(target: "devicedb", "catalog dir missing: {}", dir.display());
            return Ok(Self { entries });
        }
        for ent in std::fs::read_dir(dir)? {
            let ent = ent?;
            let path = ent.path();
            if !path.is_file() {
                continue;
            }
            match path.extension().and_then(|s| s.to_str()) {
                Some("yaml") | Some("yml") => {}
                _ => continue,
            }
            match Self::load_file(&path) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!(
                        target: "devicedb",
                        "skipping {}: {}",
                        path.display(),
                        e
                    );
                }
            }
        }
        finalize(&mut entries);
        Ok(Self { entries })
    }

    fn load_file(path: &Path) -> Result<DeviceEntry, LoadError> {
        let raw = std::fs::read_to_string(path)?;
        let parsed: RawDef =
            serde_yaml::from_str(&raw).map_err(|source| LoadError::Yaml {
                file: path.to_path_buf(),
                source,
            })?;
        compile_entry(path, parsed)
    }
}

fn compile_entry(file_label: &Path, parsed: RawDef) -> Result<DeviceEntry, LoadError> {
    let vendor = parsed.group.unwrap_or_else(|| parsed.os.clone());
    let device_type = parsed.device_type.unwrap_or_else(|| "other".to_string());

    let mut clauses = Vec::with_capacity(parsed.discovery.len());
    let mut max_oid_prefix_len = 0usize;
    for d in parsed.discovery {
        let normalize_oid = |s: String| {
            let t = s.trim_start_matches('.').trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        };
        let mut sys_object_id_prefixes: Vec<String> = d
            .sys_object_id
            .into_vec()
            .into_iter()
            .filter_map(normalize_oid)
            .collect();
        for p in &sys_object_id_prefixes {
            if p.len() > max_oid_prefix_len {
                max_oid_prefix_len = p.len();
            }
        }
        sys_object_id_prefixes.sort_by_key(|p| std::cmp::Reverse(p.len()));

        let sys_object_id_except_prefixes: Vec<String> = d
            .sys_object_id_except
            .into_vec()
            .into_iter()
            .filter_map(normalize_oid)
            .collect();

        let compile_regex = |raw_list: Vec<String>| -> Result<Vec<fancy_regex::Regex>, LoadError> {
            raw_list
                .into_iter()
                .map(|pat| {
                    let stripped = strip_pcre_delimiters(&pat);
                    fancy_regex::Regex::new(&stripped).map_err(|source| LoadError::Regex {
                        file: file_label.to_path_buf(),
                        pattern: pat.clone(),
                        source,
                    })
                })
                .collect()
        };

        let sys_object_id_regexes = compile_regex(d.sys_object_id_regex.into_vec())?;
        let sys_descr_regexes = compile_regex(d.sys_descr_regex.into_vec())?;
        let sys_descr_regex_except = compile_regex(d.sys_descr_regex_except.into_vec())?;

        let sys_descr_substrings: Vec<String> = d
            .sys_descr
            .into_vec()
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let sys_descr_except: Vec<String> = d
            .sys_descr_except
            .into_vec()
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let disabled = d.snmpget.is_some() || d.snmpget_except.is_some() || d.snmpget_oid.is_some();

        clauses.push(DiscoveryClause {
            sys_object_id_prefixes,
            sys_object_id_except_prefixes,
            sys_object_id_regexes,
            sys_descr_substrings,
            sys_descr_regexes,
            sys_descr_except,
            sys_descr_regex_except,
            disabled,
        });
    }

    Ok(DeviceEntry {
        os: parsed.os,
        vendor,
        device_type,
        clauses,
        max_oid_prefix_len,
    })
}

/// Sort the catalogue so the matcher's outer loop tries the most
/// specific entries first. Within an entry, clauses are kept in file
/// order — upstream YAMLs intentionally list more-specific clauses
/// first so the file's first-hit semantics match.
pub(crate) fn finalize(entries: &mut Vec<DeviceEntry>) {
    entries.sort_by(|a, b| b.max_oid_prefix_len.cmp(&a.max_oid_prefix_len));
}

/// Upstream YAMLs wrap regexes in `/.../i` Perl-style delimiters. Strip
/// them so `fancy-regex` (which doesn't accept the wrapper) can compile
/// the inner pattern. A trailing `i` flag is converted to `(?i)`.
pub(crate) fn strip_pcre_delimiters(pat: &str) -> String {
    let trimmed = pat.trim();
    if !trimmed.starts_with('/') {
        return trimmed.to_string();
    }
    if let Some(end) = trimmed.rfind('/') {
        if end > 0 {
            let inner = &trimmed[1..end];
            let flags = &trimmed[end + 1..];
            let mut out = String::new();
            if flags.contains('i') {
                out.push_str("(?i)");
            }
            out.push_str(inner);
            return out;
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_pcre_delimiters() {
        assert_eq!(strip_pcre_delimiters("/foo/"), "foo");
        assert_eq!(strip_pcre_delimiters("/foo/i"), "(?i)foo");
        assert_eq!(strip_pcre_delimiters("foo"), "foo");
    }
}
