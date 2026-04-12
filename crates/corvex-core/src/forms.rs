//! HTML form extractor.
//!
//! Parses `<form>` elements from a parsed HTML document and produces
//! a `FormDescriptor` with the method, action URL, and every field's
//! name + type + default value. The active fuzzers use these to build
//! `FuzzTarget`s with accurate injection points.

use scraper::{Html, Selector};

#[derive(Debug, Clone)]
pub struct FormField {
    pub name: String,
    pub input_type: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct FormDescriptor {
    pub method: String,
    pub action: String,
    pub fields: Vec<FormField>,
}

/// Extract every `<form>` from the document with its fields.
pub fn extract(doc: &Html, page_url: &str) -> Vec<FormDescriptor> {
    let form_sel = Selector::parse("form").expect("valid");
    let input_sel = Selector::parse("input, select, textarea").expect("valid");

    let mut out = Vec::new();
    for form in doc.select(&form_sel) {
        let method = form
            .value()
            .attr("method")
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let action = form
            .value()
            .attr("action")
            .unwrap_or("")
            .to_string();
        let action = resolve_action(page_url, &action);

        let mut fields = Vec::new();
        for el in form.select(&input_sel) {
            let tag = el.value().name();
            let name = el.value().attr("name").unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let input_type = match tag {
                "input" => el
                    .value()
                    .attr("type")
                    .unwrap_or("text")
                    .to_ascii_lowercase(),
                "textarea" => "textarea".to_string(),
                "select" => "select".to_string(),
                _ => "text".to_string(),
            };
            // Skip submit / button / hidden-csrf tokens for fuzzing.
            if matches!(input_type.as_str(), "submit" | "button" | "image" | "reset") {
                continue;
            }
            let value = el.value().attr("value").unwrap_or("").to_string();
            fields.push(FormField {
                name,
                input_type,
                value,
            });
        }
        out.push(FormDescriptor {
            method,
            action,
            fields,
        });
    }
    out
}

fn resolve_action(base: &str, action: &str) -> String {
    if action.is_empty() {
        return base.to_string();
    }
    if action.starts_with("http://") || action.starts_with("https://") {
        return action.to_string();
    }
    match url::Url::parse(base) {
        Ok(b) => match b.join(action) {
            Ok(u) => u.to_string(),
            Err(_) => action.to_string(),
        },
        Err(_) => action.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_login_form() {
        let html = r#"
        <html><body>
            <form method="POST" action="/login">
                <input type="text" name="user" value="" />
                <input type="password" name="pass" />
                <input type="submit" value="Login" />
            </form>
        </body></html>"#;
        let doc = Html::parse_document(html);
        let forms = extract(&doc, "http://example.com/");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "POST");
        assert_eq!(forms[0].action, "http://example.com/login");
        assert_eq!(forms[0].fields.len(), 2);
        assert_eq!(forms[0].fields[0].name, "user");
        assert_eq!(forms[0].fields[1].name, "pass");
    }

    #[test]
    fn extracts_search_form_with_select() {
        let html = r#"
        <html><body>
            <form action="/search">
                <input type="text" name="q" />
                <select name="lang">
                    <option value="en">English</option>
                    <option value="fr">French</option>
                </select>
            </form>
        </body></html>"#;
        let doc = Html::parse_document(html);
        let forms = extract(&doc, "http://example.com/");
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "GET");
        assert_eq!(forms[0].fields.len(), 2);
        assert_eq!(forms[0].fields[1].input_type, "select");
    }
}
