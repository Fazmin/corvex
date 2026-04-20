//! `{{...}}` variable / DSL substitution into paths, headers, bodies.

use crate::dsl::{eval::eval, parser::parse, Environment, Value};
use rand::Rng;

/// Expand every `{{expr}}` placeholder in `src` against `env`. Plain
/// identifiers are looked up in the environment; expressions that fail a
/// plain-identifier check are evaluated as DSL.
pub fn substitute(src: &str, env: &Environment) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(close) = find_close(bytes, i + 2) {
                let expr = &src[i + 2..close];
                let value = resolve(expr.trim(), env);
                out.push_str(&value);
                i = close + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut j = start;
    while j + 1 < bytes.len() {
        if bytes[j] == b'}' && bytes[j + 1] == b'}' {
            return Some(j);
        }
        j += 1;
    }
    None
}

fn resolve(expr: &str, env: &Environment) -> String {
    // Fast path: plain variable name.
    if is_plain_ident(expr) {
        if let Some(v) = env.get(expr) {
            return v.to_string_lossy().to_string();
        }
        return String::new();
    }
    // DSL path: parse + evaluate. A failure falls back to an empty
    // string rather than leaking `{{...}}` literal text into the
    // outbound request.
    match parse(expr) {
        Ok(ast) => match eval(&ast, env) {
            Ok(v) => v.to_string_lossy().to_string(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    }
}

fn is_plain_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Populate `env` with the standard Nuclei built-ins derived from a
/// target `BaseURL`. Callers add `{{randstr}}`/`{{rand_int}}` families
/// separately because those are per-template cached.
pub fn populate_base_url(env: &mut Environment, base_url: &str) {
    let parsed = url::Url::parse(base_url);
    let (scheme, host, port_num, path) = match parsed.as_ref() {
        Ok(u) => (
            u.scheme().to_string(),
            u.host_str().unwrap_or("").to_string(),
            u.port_or_known_default().unwrap_or(80),
            u.path().to_string(),
        ),
        Err(_) => ("http".to_string(), String::new(), 80u16, "/".to_string()),
    };

    let root_url = format!("{scheme}://{host}");
    let file = path.rsplit('/').next().unwrap_or("").to_string();
    let directory = {
        let mut p = path.clone();
        while p.ends_with(|c: char| c != '/') {
            p.pop();
        }
        p
    };

    env.set("BaseURL", base_url.trim_end_matches('/'));
    env.set("RootURL", root_url);
    env.set("Hostname", format!("{host}:{port_num}"));
    env.set("Host", host);
    env.set("Port", Value::Int(port_num as i64));
    env.set("Scheme", scheme);
    env.set("Path", path);
    env.set("File", file);
    env.set("Directory", directory);
}

/// Create a per-template block of `randstr` / `rand_int` variables so
/// repeated references produce the same value inside one template run.
pub fn populate_randoms(env: &mut Environment) {
    let mut rng = rand::thread_rng();
    let alphabet: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mk = |rng: &mut rand::rngs::ThreadRng, len: usize| -> String {
        (0..len)
            .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
            .collect()
    };
    env.set("randstr", mk(&mut rng, 27));
    for n in 1..=5 {
        env.set(format!("randstr_{n}"), mk(&mut rng, 27));
    }
    env.set("rand_int", Value::Int(rng.gen_range(1_000..1_000_000)));
    for n in 1..=5 {
        env.set(
            format!("rand_int_{n}"),
            Value::Int(rng.gen_range(1_000..1_000_000)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_plain_var() {
        let mut env = Environment::new();
        env.set("Hostname", "example.com:443");
        assert_eq!(
            substitute("https://{{Hostname}}/path", &env),
            "https://example.com:443/path"
        );
    }

    #[test]
    fn substitutes_dsl_expression() {
        let env = Environment::new();
        assert_eq!(substitute("{{md5(\"abc\")}}", &env), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn populates_base_url_parts() {
        let mut env = Environment::new();
        populate_base_url(&mut env, "https://example.com:8443/api/v1/users");
        assert_eq!(env.get("Scheme").unwrap().to_string_lossy(), "https");
        assert_eq!(env.get("Host").unwrap().to_string_lossy(), "example.com");
        assert_eq!(env.get("Port").unwrap().as_int(), Some(8443));
    }
}
