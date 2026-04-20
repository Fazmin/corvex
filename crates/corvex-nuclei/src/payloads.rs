//! Payload attack-mode expansion.
//!
//! Given a `payloads` map and an `attack` mode, generate the list of
//! per-request variable bindings the executor iterates over. A template
//! with no payloads produces exactly one empty binding.

use indexmap::IndexMap;

use crate::schema::{AttackMode, PayloadValue};

/// Expand a payload map into concrete per-request variable bindings.
pub fn expand(
    payloads: &IndexMap<String, PayloadValue>,
    attack: AttackMode,
) -> Vec<IndexMap<String, String>> {
    if payloads.is_empty() {
        return vec![IndexMap::new()];
    }

    // Gather name + list-of-values tuples in declaration order. File
    // payloads are pre-filtered out at load time; treat them as empty.
    let cols: Vec<(String, Vec<String>)> = payloads
        .iter()
        .map(|(k, v)| match v {
            PayloadValue::List(items) => (k.clone(), items.clone()),
            PayloadValue::File(_) => (k.clone(), Vec::new()),
        })
        .filter(|(_, v)| !v.is_empty())
        .collect();

    if cols.is_empty() {
        return vec![IndexMap::new()];
    }

    match attack {
        AttackMode::BatteringRam => battering_ram(&cols),
        AttackMode::Pitchfork => pitchfork(&cols),
        AttackMode::ClusterBomb => cluster_bomb(&cols),
    }
}

/// All position placeholders advance through the SAME list in lockstep.
/// Nuclei's batteringram mode takes the first payload set as the driver
/// and binds its ith entry to every key.
fn battering_ram(cols: &[(String, Vec<String>)]) -> Vec<IndexMap<String, String>> {
    let driver = &cols[0].1;
    let mut out = Vec::with_capacity(driver.len());
    for val in driver {
        let mut map = IndexMap::new();
        for (name, _) in cols {
            map.insert(name.clone(), val.clone());
        }
        out.push(map);
    }
    out
}

/// Parallel iteration: position i of every list is used together. If
/// lists have unequal length, iteration stops at the shortest.
fn pitchfork(cols: &[(String, Vec<String>)]) -> Vec<IndexMap<String, String>> {
    let min_len = cols.iter().map(|(_, v)| v.len()).min().unwrap_or(0);
    let mut out = Vec::with_capacity(min_len);
    for i in 0..min_len {
        let mut map = IndexMap::new();
        for (name, values) in cols {
            map.insert(name.clone(), values[i].clone());
        }
        out.push(map);
    }
    out
}

/// Full cartesian product of every payload list.
fn cluster_bomb(cols: &[(String, Vec<String>)]) -> Vec<IndexMap<String, String>> {
    let total: usize = cols.iter().map(|(_, v)| v.len()).product();
    let mut out = Vec::with_capacity(total);
    let mut idx = vec![0usize; cols.len()];
    loop {
        let mut map = IndexMap::new();
        for (i, (name, values)) in cols.iter().enumerate() {
            map.insert(name.clone(), values[idx[i]].clone());
        }
        out.push(map);

        // Increment the odometer.
        let mut i = cols.len();
        while i > 0 {
            i -= 1;
            idx[i] += 1;
            if idx[i] < cols[i].1.len() {
                break;
            }
            idx[i] = 0;
            if i == 0 {
                return out;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(pairs: &[(&str, &[&str])]) -> IndexMap<String, PayloadValue> {
        let mut m = IndexMap::new();
        for (k, v) in pairs {
            m.insert(
                (*k).to_string(),
                PayloadValue::List(v.iter().map(|s| s.to_string()).collect()),
            );
        }
        m
    }

    #[test]
    fn cluster_bomb_product() {
        let p = make(&[("u", &["a", "b"]), ("p", &["1", "2", "3"])]);
        let out = expand(&p, AttackMode::ClusterBomb);
        assert_eq!(out.len(), 6);
    }

    #[test]
    fn pitchfork_min_len() {
        let p = make(&[("u", &["a", "b"]), ("p", &["1", "2", "3"])]);
        let out = expand(&p, AttackMode::Pitchfork);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["u"], "a");
        assert_eq!(out[0]["p"], "1");
    }

    #[test]
    fn battering_ram_single_driver() {
        let p = make(&[("u", &["a", "b"]), ("p", &["1", "2", "3"])]);
        let out = expand(&p, AttackMode::BatteringRam);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["u"], "a");
        assert_eq!(out[0]["p"], "a");
    }
}
