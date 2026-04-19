use crate::db::{RecogFp, SonarDb};
use crate::types::ProbeMatch;

#[derive(Debug, Default, Clone)]
pub struct RecogHit {
    pub product: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os_product: Option<String>,
    pub os_version: Option<String>,
    pub cpe: Vec<String>,
    pub fp_set: String,
}

impl RecogHit {
    pub fn is_empty(&self) -> bool {
        self.product.is_none()
            && self.version.is_none()
            && self.vendor.is_none()
            && self.info.is_none()
            && self.hostname.is_none()
            && self.os_product.is_none()
            && self.os_version.is_none()
            && self.cpe.is_empty()
    }

    pub fn merge_into(self, out: &mut ProbeMatch) {
        if out.product.is_none() {
            out.product = self.product;
        }
        if out.version.is_none() {
            out.version = self.version;
        }
        if out.vendor.is_none() {
            out.vendor = self.vendor;
        }
        if out.info.is_none() {
            out.info = self.info;
        }
        if out.hostname.is_none() {
            out.hostname = self.hostname;
        }
        if out.os_product.is_none() {
            out.os_product = self.os_product;
        }
        if out.os_version.is_none() {
            out.os_version = self.os_version;
        }
        for c in self.cpe {
            if !out.cpe.contains(&c) {
                out.cpe.push(c);
            }
        }
    }
}

pub fn match_response(db: &SonarDb, fp_sets: &[String], text: &str) -> Option<RecogHit> {
    for set in fp_sets {
        for idx in db.fps_by_set(set) {
            let fp = &db.recog[*idx];
            if let Some(hit) = apply_fp(fp, text) {
                return Some(hit);
            }
        }
    }
    None
}

fn apply_fp(fp: &RecogFp, text: &str) -> Option<RecogHit> {
    let caps = match fp.regex.captures(text) {
        Ok(Some(c)) => c,
        _ => return None,
    };

    let mut captured: Vec<Option<String>> = Vec::with_capacity(caps.len());
    for i in 0..caps.len() {
        captured.push(caps.get(i).map(|m| m.as_str().to_string()));
    }

    let mut hit = RecogHit {
        fp_set: fp.set.clone(),
        ..Default::default()
    };
    let mut fields: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for p in &fp.params {
        let resolved = if p.pos == 0 {
            match &p.value {
                Some(v) => Some(substitute_fields(v, &fields)),
                None => continue,
            }
        } else {
            captured
                .get(p.pos as usize)
                .cloned()
                .flatten()
        };
        let Some(val) = resolved else { continue };
        fields.insert(p.name.clone(), val.clone());
        assign_field(&mut hit, &p.name, val);
    }

    if hit.is_empty() {
        return None;
    }
    Some(hit)
}

fn assign_field(hit: &mut RecogHit, name: &str, value: String) {
    match name {
        "service.product" => hit.product = Some(value),
        "service.version" => hit.version = Some(value),
        "service.vendor" => hit.vendor = Some(value),
        "service.info" => hit.info = Some(value),
        "service.cpe23" => {
            if !hit.cpe.contains(&value) {
                hit.cpe.push(value);
            }
        }
        "host.hostname" => hit.hostname = Some(value),
        "os.product" => hit.os_product = Some(value),
        "os.version" => hit.os_version = Some(value),
        _ => {}
    }
}

fn substitute_fields(
    tpl: &str,
    fields: &std::collections::HashMap<String, String>,
) -> String {
    let mut out = String::with_capacity(tpl.len());
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}') {
                let key = &tpl[i + 1..i + 1 + end];
                if let Some(v) = fields.get(key) {
                    out.push_str(v);
                } else {
                    out.push('{');
                    out.push_str(key);
                    out.push('}');
                }
                i = i + end + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
