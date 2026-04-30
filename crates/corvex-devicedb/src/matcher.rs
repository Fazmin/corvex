//! Match a (sysObjectID, sysDescr) pair against the device catalog.
//!
//! Semantics mirror the upstream YAML schema:
//!   - A device file declares one or more **discovery clauses**.
//!   - Within a clause, each *condition type* present (sysObjectID,
//!     sysObjectID_regex, sysDescr, sysDescr_regex) must yield at
//!     least one positive match — i.e. AND across condition types,
//!     OR within a list.
//!   - Any `_except` filter that hits causes the clause to be
//!     rejected even if every positive condition matched.
//!   - A file matches when any of its clauses fires.
//!
//! Catalog walk order: entries are pre-sorted by longest sysObjectID
//! prefix declared anywhere in the file, so vendor-specific signatures
//! get the first attempt before catch-all fallbacks.

use crate::loader::{DeviceCatalog, DeviceEntry, DiscoveryClause};
use crate::types::{DeviceMatch, MatchSource};

pub fn identify(
    sys_object_id: Option<&str>,
    sys_descr: Option<&str>,
    catalog: &DeviceCatalog,
) -> Option<DeviceMatch> {
    let oid = sys_object_id
        .map(|s| s.trim_start_matches('.').trim())
        .filter(|s| !s.is_empty());
    let descr_lower = sys_descr.map(|s| s.to_lowercase());

    for entry in &catalog.entries {
        for clause in &entry.clauses {
            if let Some(source) =
                clause_matches(clause, oid, sys_descr, descr_lower.as_deref())
            {
                return Some(make_match(entry, source));
            }
        }
    }
    None
}

/// `Some(source)` if every present positive condition type matched
/// and no except filter hit. `None` otherwise.
fn clause_matches(
    clause: &DiscoveryClause,
    oid: Option<&str>,
    descr: Option<&str>,
    descr_lower: Option<&str>,
) -> Option<MatchSource> {
    if clause.disabled {
        return None;
    }

    // Each positive condition type that is *present* must produce a
    // hit. Track the first present type for the source label.
    let mut source: Option<MatchSource> = None;

    let oid_present = !clause.sys_object_id_prefixes.is_empty()
        || !clause.sys_object_id_regexes.is_empty();
    if oid_present {
        let Some(o) = oid else { return None };
        let prefix_hit = clause
            .sys_object_id_prefixes
            .iter()
            .any(|p| oid_starts_with(o, p));
        let regex_hit = clause
            .sys_object_id_regexes
            .iter()
            .any(|re| re.is_match(o).unwrap_or(false));
        if !(prefix_hit || regex_hit) {
            return None;
        }
        source.get_or_insert(MatchSource::SysObjectId);
    }

    if !clause.sys_descr_substrings.is_empty() {
        let Some(d) = descr_lower else { return None };
        if !clause.sys_descr_substrings.iter().any(|s| d.contains(s)) {
            return None;
        }
        source.get_or_insert(MatchSource::SysDescr);
    }

    if !clause.sys_descr_regexes.is_empty() {
        let Some(d) = descr else { return None };
        if !clause
            .sys_descr_regexes
            .iter()
            .any(|re| re.is_match(d).unwrap_or(false))
        {
            return None;
        }
        source.get_or_insert(MatchSource::SysDescrRegex);
    }

    // No positive condition was present — empty clause never fires.
    source?;

    // Negative filters.
    if let Some(d) = descr_lower {
        if clause.sys_descr_except.iter().any(|s| d.contains(s)) {
            return None;
        }
    }
    if let Some(d) = descr {
        if clause
            .sys_descr_regex_except
            .iter()
            .any(|re| re.is_match(d).unwrap_or(false))
        {
            return None;
        }
    }
    if let Some(o) = oid {
        if clause
            .sys_object_id_except_prefixes
            .iter()
            .any(|p| oid_starts_with(o, p))
        {
            return None;
        }
    }

    source
}

fn make_match(entry: &DeviceEntry, source: MatchSource) -> DeviceMatch {
    DeviceMatch {
        os: entry.os.clone(),
        vendor: entry.vendor.clone(),
        device_type: entry.device_type.clone(),
        source,
    }
}

/// "starts with" on dotted OIDs, but only at OID-component boundaries
/// so `1.3.6.1.4.1.99` does not falsely match prefix `1.3.6.1.4.1.9`.
fn oid_starts_with(oid: &str, prefix: &str) -> bool {
    if !oid.starts_with(prefix) {
        return false;
    }
    let rest = &oid[prefix.len()..];
    rest.is_empty() || rest.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_boundaries() {
        assert!(oid_starts_with("1.3.6.1.4.1.9.1.123", "1.3.6.1.4.1.9"));
        assert!(oid_starts_with("1.3.6.1.4.1.9", "1.3.6.1.4.1.9"));
        // Different vendor — must not match.
        assert!(!oid_starts_with("1.3.6.1.4.1.99", "1.3.6.1.4.1.9"));
    }
}
