use std::net::IpAddr;
use systemstat::{Platform, System};

pub fn select_host_address() -> IpAddr {
    let system = System::new();
    let networks = system.networks().unwrap();

    for net in networks.values() {
        for n in &net.addrs {
            if let systemstat::IpAddr::V4(v) = n.addr {
                if !v.is_loopback() && !v.is_link_local() && !v.is_broadcast() {
                    return IpAddr::V4(v);
                }
            }
        }
    }

    panic!("Found no usable network interface");
}

// ─── Shared JSONC config loader ───────────────────────────
//
// Mirrors the behaviour of the Node.js `config-loader.js` so all apps
// (SFU, Key Distributor, client) read the same config.json. Supports:
//   * repeatable `--config <path>` flags (deep-merged, later wins)
//   * `E2EE_CONFIG` env var fallback
//   * default search paths (./config.json, then ../config.json)
//   * sectioned files (extract the `sfu` section + shared sections) OR a
//     flat file (used as-is)
//   * JSONC: `//` and `/* */` comments and trailing commas

use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Strip `//` and `/* */` comments (string-aware) and trailing commas.
#[allow(dead_code)]
fn strip_jsonc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] as char == '/' {
            while i < bytes.len() && bytes[i] as char != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < bytes.len() && bytes[i + 1] as char == '*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] as char == '*' && bytes[i + 1] as char == '/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }

    // Remove trailing commas before } or ]
    let mut cleaned = String::with_capacity(out.len());
    let ob = out.as_bytes();
    let mut j = 0;
    while j < ob.len() {
        if ob[j] as char == ',' {
            let mut k = j + 1;
            while k < ob.len() && (ob[k] as char).is_whitespace() {
                k += 1;
            }
            if k < ob.len() && (ob[k] as char == '}' || ob[k] as char == ']') {
                j += 1;
                continue;
            }
        }
        cleaned.push(ob[j] as char);
        j += 1;
    }
    cleaned
}

#[allow(dead_code)]
fn deep_merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                deep_merge(b.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (b, o) => *b = o.clone(),
    }
}

#[allow(dead_code)]
fn read_config_file(path: &Path) -> Option<Value> {
    let raw = std::fs::read_to_string(path).ok()?;
    let stripped = strip_jsonc(&raw);
    serde_json::from_str(&stripped).ok()
}

/// Resolve the ordered list of config file paths from CLI args / env / defaults.
#[allow(dead_code)]
fn resolve_config_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--config" && i + 1 < args.len() {
            paths.push(PathBuf::from(&args[i + 1]));
            i += 2;
            continue;
        }
        i += 1;
    }
    if paths.is_empty() {
        if let Ok(p) = std::env::var("E2EE_CONFIG") {
            for part in p.split(';') {
                if !part.is_empty() {
                    paths.push(PathBuf::from(part));
                }
            }
        }
    }
    if paths.is_empty() {
        for cand in ["config.json", "../config.json", "../../config.json"] {
            let p = PathBuf::from(cand);
            if p.exists() {
                paths.push(p);
                break;
            }
        }
    }
    paths
}

/// Load the merged config for the given app section (e.g. "sfu").
/// Returns the app section merged with shared sections (logging/stats/diagnostics),
/// plus the list of source files that were loaded.
#[allow(dead_code)]
pub fn load_config(app_key: &str) -> (Value, Vec<String>) {
    let shared = ["logging", "stats", "diagnostics"];
    let mut merged = Value::Object(Map::new());
    let mut sources = Vec::new();

    for path in resolve_config_paths() {
        if let Some(file) = read_config_file(&path) {
            sources.push(path.display().to_string());
            // Determine if the file is sectioned (contains the app key or a
            // known section) or flat.
            let is_sectioned = file.get(app_key).is_some()
                || shared.iter().any(|s| file.get(*s).is_some())
                || ["sfu", "keyDistributor", "client"]
                    .iter()
                    .any(|s| file.get(*s).is_some());

            let mut piece = Value::Object(Map::new());
            if is_sectioned {
                if let Some(section) = file.get(app_key) {
                    deep_merge(&mut piece, section);
                }
                for s in shared {
                    if let Some(v) = file.get(s) {
                        let mut wrap = Map::new();
                        wrap.insert(s.to_string(), v.clone());
                        deep_merge(&mut piece, &Value::Object(wrap));
                    }
                }
            } else {
                deep_merge(&mut piece, &file);
            }
            deep_merge(&mut merged, &piece);
        }
    }

    (merged, sources)
}

/// Get a dotted-path value as a string.
#[allow(dead_code)]
pub fn cfg_str(cfg: &Value, path: &str, fallback: &str) -> String {
    match cfg_get(cfg, path) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string().trim_matches('"').to_string(),
        None => fallback.to_string(),
    }
}

/// Get a dotted-path value as u64.
#[allow(dead_code)]
pub fn cfg_u64(cfg: &Value, path: &str, fallback: u64) -> u64 {
    match cfg_get(cfg, path) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(fallback),
        Some(Value::String(s)) => s.parse().unwrap_or(fallback),
        _ => fallback,
    }
}

/// Get a dotted-path value as bool.
#[allow(dead_code)]
pub fn cfg_bool(cfg: &Value, path: &str, fallback: bool) -> bool {
    match cfg_get(cfg, path) {
        Some(Value::Bool(b)) => *b,
        _ => fallback,
    }
}

#[allow(dead_code)]
fn cfg_get<'a>(cfg: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = cfg;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}
