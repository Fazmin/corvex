//! Allowlisted DSL helper functions.
//!
//! This is the single source of truth for "supported DSL helpers" —
//! `parser::referenced_functions` cross-checks every function name in a
//! template against [`is_known`] at load time.

use crate::dsl::eval::{EvalError, Value};
use base64::Engine;
use md5::Digest;

/// True if `name` is a DSL helper we can evaluate.
pub fn is_known(name: &str) -> bool {
    KNOWN.contains(&name)
}

const KNOWN: &[&str] = &[
    // hashing
    "md5",
    "sha256",
    // encoding
    "base64",
    "base64_decode",
    "hex_encode",
    "hex_decode",
    "url_encode",
    "url_decode",
    "html_escape",
    "html_unescape",
    // strings
    "contains",
    "starts_with",
    "ends_with",
    "to_lower",
    "to_upper",
    "trim",
    "trim_left",
    "trim_right",
    "replace",
    "len",
    "regex",
    // numbers
    "rand_int",
    "rand_base",
    // time
    "unix_time",
    "date_time",
    // conversion
    "to_number",
    "to_string",
    // logic (sometimes used as functions in templates)
    "equals",
    "and",
    "or",
    "not",
];

pub fn call(name: &str, args: &[Value]) -> Result<Value, EvalError> {
    match name {
        "md5" => hash_str(args, |b| {
            let mut h = md5::Md5::new();
            h.update(b);
            hex::encode(h.finalize())
        }),
        "sha256" => hash_str(args, |b| {
            let mut h = sha2::Sha256::new();
            h.update(b);
            hex::encode(h.finalize())
        }),
        "base64" => unary_str(args, |s| {
            base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
        }),
        "base64_decode" => unary_str_try(args, |s| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .map_err(|e| EvalError::Arg(format!("base64_decode: {e}")))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }),
        "hex_encode" => unary_str(args, |s| hex::encode(s.as_bytes())),
        "hex_decode" => unary_str_try(args, |s| {
            let bytes = hex::decode(s)
                .map_err(|e| EvalError::Arg(format!("hex_decode: {e}")))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }),
        "url_encode" => unary_str(args, percent_encode),
        "url_decode" => unary_str(args, percent_decode),
        "html_escape" => unary_str(args, html_escape),
        "html_unescape" => unary_str(args, html_unescape),

        "contains" => binary_strs(args, |s, sub| Value::Bool(s.contains(sub))),
        "starts_with" => binary_strs(args, |s, p| Value::Bool(s.starts_with(p))),
        "ends_with" => binary_strs(args, |s, p| Value::Bool(s.ends_with(p))),
        "to_lower" => unary_str(args, |s| s.to_lowercase()),
        "to_upper" => unary_str(args, |s| s.to_uppercase()),
        "trim" => unary_str(args, |s| s.trim().to_string()),
        "trim_left" => unary_str(args, |s| s.trim_start().to_string()),
        "trim_right" => unary_str(args, |s| s.trim_end().to_string()),
        "replace" => {
            require_arity(name, args, 3)?;
            let s = args[0].to_string_lossy();
            let from = args[1].to_string_lossy();
            let to = args[2].to_string_lossy();
            Ok(Value::Str(s.replace(&*from, &to)))
        }
        "len" => {
            require_arity(name, args, 1)?;
            let s = args[0].to_string_lossy();
            Ok(Value::Int(s.len() as i64))
        }
        "regex" => {
            require_arity(name, args, 2)?;
            let pat = args[0].to_string_lossy();
            let hay = args[1].to_string_lossy();
            let re = regex::Regex::new(&pat)
                .map_err(|e| EvalError::Arg(format!("regex: {e}")))?;
            Ok(Value::Bool(re.is_match(&hay)))
        }

        "rand_int" => {
            let (min, max) = match args.len() {
                0 => (0i64, i64::MAX),
                1 => (0i64, args[0].as_int().unwrap_or(0)),
                _ => (
                    args[0].as_int().unwrap_or(0),
                    args[1].as_int().unwrap_or(0),
                ),
            };
            let max = max.max(min + 1);
            let n = min + (rand::random::<u32>() as i64) % (max - min);
            Ok(Value::Int(n))
        }
        "rand_base" => {
            require_arity(name, args, 1)?;
            let n = args[0].as_int().unwrap_or(8).max(1) as usize;
            let alphabet: &[u8] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let mut out = String::with_capacity(n);
            for _ in 0..n {
                let pick = (rand::random::<u32>() as usize) % alphabet.len();
                out.push(alphabet[pick] as char);
            }
            Ok(Value::Str(out))
        }

        "unix_time" => Ok(Value::Int(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        )),
        "date_time" => {
            // `date_time("%Y-%m-%dT%H:%M:%SZ")` → current UTC formatted.
            // If called without args, RFC3339-ish default.
            let fmt = args
                .first()
                .map(|v| v.to_string_lossy().to_string())
                .unwrap_or_else(|| "%Y-%m-%dT%H:%M:%SZ".to_string());
            let now = time::OffsetDateTime::now_utc();
            let formatted = simple_strftime(&fmt, &now);
            Ok(Value::Str(formatted))
        }

        "to_number" => {
            require_arity(name, args, 1)?;
            let s = args[0].to_string_lossy();
            let n: f64 = s
                .parse()
                .map_err(|e| EvalError::Arg(format!("to_number: {e}")))?;
            Ok(Value::Float(n))
        }
        "to_string" => {
            require_arity(name, args, 1)?;
            Ok(Value::Str(args[0].to_string_lossy().to_string()))
        }

        "equals" => {
            require_arity(name, args, 2)?;
            Ok(Value::Bool(args[0] == args[1]))
        }
        "and" => Ok(Value::Bool(args.iter().all(|v| v.truthy()))),
        "or" => Ok(Value::Bool(args.iter().any(|v| v.truthy()))),
        "not" => {
            require_arity(name, args, 1)?;
            Ok(Value::Bool(!args[0].truthy()))
        }

        other => Err(EvalError::UnknownFn(other.to_string())),
    }
}

fn hash_str<F: FnOnce(&[u8]) -> String>(
    args: &[Value],
    f: F,
) -> Result<Value, EvalError> {
    require_arity("<hash>", args, 1)?;
    let s = args[0].to_string_lossy();
    Ok(Value::Str(f(s.as_bytes())))
}

fn unary_str<F: FnOnce(&str) -> String>(
    args: &[Value],
    f: F,
) -> Result<Value, EvalError> {
    require_arity("<unary>", args, 1)?;
    let s = args[0].to_string_lossy();
    Ok(Value::Str(f(&s)))
}

fn unary_str_try<F: FnOnce(&str) -> Result<String, EvalError>>(
    args: &[Value],
    f: F,
) -> Result<Value, EvalError> {
    require_arity("<unary>", args, 1)?;
    let s = args[0].to_string_lossy();
    Ok(Value::Str(f(&s)?))
}

fn binary_strs<F: FnOnce(&str, &str) -> Value>(
    args: &[Value],
    f: F,
) -> Result<Value, EvalError> {
    require_arity("<binary>", args, 2)?;
    let a = args[0].to_string_lossy();
    let b = args[1].to_string_lossy();
    Ok(f(&a, &b))
}

fn require_arity(name: &str, args: &[Value], want: usize) -> Result<(), EvalError> {
    if args.len() == want {
        Ok(())
    } else {
        Err(EvalError::Arg(format!(
            "{name}: expected {want} args, got {}",
            args.len()
        )))
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Tiny strftime subset supporting `%Y %m %d %H %M %S`. Enough for the
/// Nuclei templates we see without pulling a format parser.
fn simple_strftime(fmt: &str, dt: &time::OffsetDateTime) -> String {
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&format!("{:04}", dt.year())),
            Some('m') => out.push_str(&format!("{:02}", u8::from(dt.month()))),
            Some('d') => out.push_str(&format!("{:02}", dt.day())),
            Some('H') => out.push_str(&format!("{:02}", dt.hour())),
            Some('M') => out.push_str(&format!("{:02}", dt.minute())),
            Some('S') => out.push_str(&format!("{:02}", dt.second())),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}
