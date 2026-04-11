//! Variable expansion for test URIs and messages.
//!
//! Supports:
//!   @IP, @HOSTNAME, @PORT
//!   @JUNK(n)       — n random alphanumeric chars
//!   @CGIDIRS       — expanded by iterating db_variables
//!   Any key from db_variables (e.g. @ADMIN, @USERS, @PHPMYADMIN)
//!
//! The Nikto tests DB has a concept where @VAR expansion produces *multiple*
//! test URIs (one per value in the variable). That fan-out is handled by
//! `expand_all`, which returns a Vec<String>.

use crate::db::Databases;
use crate::target::Mark;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;

static VAR_RX: Lazy<Regex> = Lazy::new(|| Regex::new(r"@([A-Z0-9_]+)(?:\(([0-9]+)\))?").unwrap());

/// Look up a fixed single-value expansion for host scope (@IP/@HOSTNAME/@PORT).
fn host_value(var: &str, mark: &Mark) -> Option<String> {
    match var {
        "IP" => mark.ip.map(|ip| ip.to_string()),
        "HOSTNAME" => Some(mark.hostname.clone()),
        "PORT" => Some(mark.port.to_string()),
        _ => None,
    }
}

/// Expand a single input into the full Cartesian product of all @VAR
/// substitutions, returning every resulting concrete string.
pub fn expand_all(input: &str, mark: &Mark, dbs: &Databases) -> Vec<String> {
    let mut frontier = vec![input.to_string()];
    loop {
        let mut any = false;
        let mut next: Vec<String> = Vec::new();
        for s in &frontier {
            if let Some(m) = VAR_RX.find(s) {
                any = true;
                let name = VAR_RX.captures(m.as_str()).unwrap();
                let var_name = name.get(1).unwrap().as_str();
                let arg = name.get(2).map(|a| a.as_str().to_string());
                let before = &s[..m.start()];
                let after = &s[m.end()..];

                // @JUNK(n) — random N-length string, single expansion
                if var_name == "JUNK" {
                    if let Some(nstr) = arg {
                        if let Ok(n) = nstr.parse::<usize>() {
                            let junk = random_alnum(n);
                            next.push(format!("{before}{junk}{after}"));
                            continue;
                        }
                    }
                    next.push(format!("{before}{after}"));
                    continue;
                }

                // Host-scoped single-value variables
                if let Some(val) = host_value(var_name, mark) {
                    next.push(format!("{before}{val}{after}"));
                    continue;
                }

                // Fan out from db_variables
                if let Some((_, values)) =
                    dbs.variables.entries.iter().find(|(n, _)| n == var_name)
                {
                    if values.is_empty() {
                        next.push(format!("{before}{after}"));
                    } else {
                        for v in values {
                            next.push(format!("{before}{v}{after}"));
                        }
                    }
                    continue;
                }

                // Unknown var: drop it
                next.push(format!("{before}{after}"));
            } else {
                next.push(s.clone());
            }
        }
        frontier = next;
        if !any {
            break;
        }
    }
    frontier
}

fn random_alnum(n: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
