//! Variable expansion for test URIs and messages.
//!
//! Supports:
//!   @IP, @HOSTNAME, @PORT
//!   @JUNK(n)           — n random alphanumeric chars
//!   @LFI(nix|win|abs|url, ...) — LFI path generator (see `expand_lfi`)
//!   @CGIDIRS           — expanded by iterating db_variables
//!   Any key from db_variables (e.g. @ADMIN, @USERS, @PHPMYADMIN)
//!
//! The Nikto tests DB has a concept where @VAR expansion produces *multiple*
//! test URIs (one per value in the variable). That fan-out is handled by
//! `expand_all`, which returns a Vec<String>.

use crate::db::Databases;
use crate::target::{Mark, Platform};
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;

/// Matches any `@NAME` or `@NAME(args)` token. Args are captured verbatim
/// (including commas and letters), so `@LFI(nix,url)` and `@JUNK(20)` both work.
static VAR_RX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"@([A-Z0-9_]+)(?:\(([^)]*)\))?").unwrap());

/// Look up a fixed single-value expansion for host scope (@IP/@HOSTNAME/@PORT).
fn host_value(var: &str, mark: &Mark) -> Option<String> {
    match var {
        "IP" => mark.ip.map(|ip| ip.to_string()),
        "HOSTNAME" => Some(mark.hostname.clone()),
        "PORT" => Some(mark.port.to_string()),
        _ => None,
    }
}

/// Look up a scalar db_variables entry (takes the first value, or `default`).
fn scalar_var(dbs: &Databases, name: &str, default: &str) -> String {
    dbs.variables
        .entries
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| v.first().cloned())
        .unwrap_or_else(|| default.to_string())
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
                let cap = VAR_RX.captures(m.as_str()).unwrap();
                let var_name = cap.get(1).unwrap().as_str();
                let arg = cap.get(2).map(|a| a.as_str().to_string());
                let before = &s[..m.start()];
                let after = &s[m.end()..];

                // @JUNK(n) — random N-length string, single expansion
                if var_name == "JUNK" {
                    if let Some(nstr) = arg {
                        if let Ok(n) = nstr.trim().parse::<usize>() {
                            let junk = random_alnum(n);
                            next.push(format!("{before}{junk}{after}"));
                            continue;
                        }
                    }
                    next.push(format!("{before}{after}"));
                    continue;
                }

                // @LFI(...) — returns one URI per target platform
                if var_name == "LFI" {
                    let args = arg.as_deref().unwrap_or("");
                    let payloads = expand_lfi(args, mark, dbs);
                    if payloads.is_empty() {
                        next.push(format!("{before}{after}"));
                    } else {
                        for p in payloads {
                            next.push(format!("{before}{p}{after}"));
                        }
                    }
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

                // Unknown var: drop the token and continue
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

/// Generate LFI path payloads for the given argument string.
///
/// `args` is a comma-separated list of flags:
///   - `nix` / `win` — platform selector
///   - `abs`         — use the absolute target path, skip traversal
///   - `url`         — percent-encode the final path
///
/// Returns one path per target platform (typically 1 or 2).
pub fn expand_lfi(args: &str, mark: &Mark, dbs: &Databases) -> Vec<String> {
    let opts: Vec<&str> = args
        .split(|c| c == ',' || c == ' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let want_nix = opts.iter().any(|o| o.eq_ignore_ascii_case("nix"));
    let want_win = opts.iter().any(|o| o.eq_ignore_ascii_case("win"));
    let use_abs = opts.iter().any(|o| o.eq_ignore_ascii_case("abs"));
    let use_url = opts.iter().any(|o| o.eq_ignore_ascii_case("url"));

    // Decide target platforms.
    let mut platforms: Vec<Platform> = Vec::new();
    let explicit = want_nix || want_win;
    if explicit {
        match mark.platform {
            Platform::All => {
                if want_nix {
                    platforms.push(Platform::Unix);
                }
                if want_win {
                    platforms.push(Platform::Windows);
                }
            }
            Platform::Unix if want_nix => platforms.push(Platform::Unix),
            Platform::Windows if want_win => platforms.push(Platform::Windows),
            _ => return Vec::new(), // test platform filter excludes this target
        }
    } else {
        match mark.platform {
            Platform::Unix => platforms.push(Platform::Unix),
            Platform::Windows => platforms.push(Platform::Windows),
            Platform::All => {
                platforms.push(Platform::Unix);
                platforms.push(Platform::Windows);
            }
        }
    }

    let depth_raw = scalar_var(dbs, "LFIDEPTH", "5");
    let depth: usize = depth_raw
        .trim()
        .parse()
        .unwrap_or(5)
        .clamp(1, 20);

    let mut out = Vec::new();
    for platform in platforms {
        let is_nix = platform == Platform::Unix;
        let target = if is_nix {
            scalar_var(dbs, "LFITGTNIX", "/etc/hosts")
        } else {
            scalar_var(dbs, "LFITGTWIN", "\\Windows\\win.ini")
        };
        let step = if is_nix {
            scalar_var(dbs, "LFIPATHNIX", "../")
        } else {
            scalar_var(dbs, "LFIPATHWIN", "..\\")
        };

        let raw = if use_abs {
            // Force an absolute path with the right leading separator.
            let mut s = target.clone();
            if is_nix {
                if !s.starts_with('/') {
                    s.insert(0, '/');
                }
            } else {
                let has_drive = s.len() >= 2
                    && s.as_bytes()[1] == b':'
                    && s.as_bytes()[0].is_ascii_alphabetic();
                if !has_drive && !s.starts_with('\\') {
                    s.insert(0, '\\');
                }
            }
            s
        } else {
            let mut traversal = step.repeat(depth);
            let mut target = target.clone();
            // Avoid doubled separators between traversal and target.
            if is_nix && traversal.ends_with('/') && target.starts_with('/') {
                traversal.pop();
            }
            if !is_nix && traversal.ends_with('\\') && target.starts_with('\\') {
                traversal.pop();
            }
            // If the target has no leading separator we still need one.
            if is_nix && !traversal.is_empty() && !traversal.ends_with('/')
                && !target.starts_with('/')
            {
                target.insert(0, '/');
            }
            format!("{traversal}{target}")
        };

        let payload = if use_url { percent_encode(&raw) } else { raw };
        out.push(payload);
    }
    out
}

/// Build a DSL expression fragment that matches the contents of `/etc/hosts`
/// or `win.ini` on either platform. Mirrors Perl `expand_lfi_dsl`.
pub fn lfi_dsl_replacement(dbs: &Databases) -> Option<String> {
    let win = scalar_var(dbs, "LFIMATCHWIN", "");
    let nix = scalar_var(dbs, "LFIMATCHNIX", "");
    match (win.is_empty(), nix.is_empty()) {
        (true, true) => None,
        (false, true) => Some(win),
        (true, false) => Some(nix),
        (false, false) => Some(format!("({win}|{nix})")),
    }
}

/// Replace `@LFI()` tokens inside a DSL string with the platform match
/// fragment. Returns the original string unchanged if no token is present.
pub fn expand_lfi_dsl(dsl: &str, dbs: &Databases) -> String {
    if !dsl.contains("LFI()") {
        return dsl.to_string();
    }
    let replacement = match lfi_dsl_replacement(dbs) {
        Some(r) => r,
        None => return dsl.to_string(),
    };
    let rx = Regex::new(r"@?LFI\(\)").unwrap();
    rx.replace_all(dsl, replacement.as_str()).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn random_alnum(n: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..n)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_mark(platform: Platform) -> Mark {
        let mut m = Mark::new("h:80".into(), "h".into(), 80, false, "/".into());
        m.platform = platform;
        m.ip = Some("127.0.0.1".parse().unwrap());
        m
    }

    fn stub_dbs() -> Databases {
        Databases {
            tests: crate::db::types::TestDb { rows: vec![] },
            outdated: crate::db::types::OutdatedDb { rows: vec![] },
            favicon: crate::db::types::FaviconDb { rows: vec![] },
            server_msgs: crate::db::types::ServerMsgsDb { rows: vec![] },
            realms: crate::db::types::RealmsDb { rows: vec![] },
            variables: crate::db::types::VariablesDb {
                entries: vec![
                    ("LFITGTNIX".to_string(), vec!["/etc/hosts".to_string()]),
                    ("LFITGTWIN".to_string(), vec![r"\Windows\win.ini".to_string()]),
                    ("LFIPATHNIX".to_string(), vec!["../".to_string()]),
                    ("LFIPATHWIN".to_string(), vec![r"..\".to_string()]),
                    ("LFIDEPTH".to_string(), vec!["3".to_string()]),
                ],
            },
            content_search: crate::db::types::ContentSearchDb { rows: vec![] },
            headers_common: crate::db::types::HeadersCommonDb { headers: vec![] },
            headers_suggested: crate::db::types::HeadersSuggestedDb { rows: vec![] },
            multiple_index: crate::db::types::MultipleIndexDb { names: vec![] },
            options: crate::db::types::OptionsDb { rows: vec![] },
            useragents: crate::db::types::UseragentsDb { agents: vec![] },
            dictionary: crate::db::types::DictionaryDb { entries: vec![] },
            fourohfour: crate::db::types::FourOhFourDb { signatures: vec![] },
        }
    }

    #[test]
    fn lfi_nix_traversal() {
        let mark = stub_mark(Platform::Unix);
        let dbs = stub_dbs();
        let out = expand_lfi("nix", &mark, &dbs);
        // depth=3, step="../" → "../../../"; target="/etc/hosts".
        // Double '/' between them is collapsed.
        assert_eq!(out, vec!["../../../etc/hosts".to_string()]);
    }

    #[test]
    fn lfi_abs_nix() {
        let mark = stub_mark(Platform::Unix);
        let dbs = stub_dbs();
        let out = expand_lfi("nix,abs", &mark, &dbs);
        assert_eq!(out, vec!["/etc/hosts".to_string()]);
    }

    #[test]
    fn lfi_url_encoded() {
        let mark = stub_mark(Platform::Unix);
        let dbs = stub_dbs();
        let out = expand_lfi("nix,abs,url", &mark, &dbs);
        assert_eq!(out, vec!["%2Fetc%2Fhosts".to_string()]);
    }

    #[test]
    fn lfi_both_platforms_when_all() {
        let mark = stub_mark(Platform::All);
        let dbs = stub_dbs();
        let out = expand_lfi("", &mark, &dbs);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn lfi_excludes_mismatched_platform() {
        let mark = stub_mark(Platform::Unix);
        let dbs = stub_dbs();
        let out = expand_lfi("win", &mark, &dbs);
        assert!(out.is_empty());
    }

    #[test]
    fn lfi_dsl_expansion() {
        let mut dbs = stub_dbs();
        dbs.variables
            .entries
            .push(("LFIMATCHNIX".into(), vec!["BODY:localhost".into()]));
        dbs.variables
            .entries
            .push(("LFIMATCHWIN".into(), vec![r"BODY:\[fonts\]".into()]));
        let out = expand_lfi_dsl("CODE:200&&@LFI()", &dbs);
        assert_eq!(out, r"CODE:200&&(BODY:\[fonts\]|BODY:localhost)");
    }
}
