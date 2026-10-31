//! Rule loading and validation (CONTRACTS §6).
//!
//! `load_rules(dir)` reads every `*.yaml` in `dir` except `allowlist.yaml`,
//! one rule per file, in file-name order. Each rule is validated against its
//! detector's schema: unknown detectors, unknown params, unknown weight
//! signals, out-of-range numbers and duplicate ids are errors, so a typo in a
//! rule file fails loudly instead of silently disabling a detection.
//! Params a file omits take the defaults below.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use walleye_core::error::ApiResult;
use walleye_core::rules::RuleDef;
use walleye_core::{ApiError, ErrorCode};

/// Largest rule file we read. Rules are tiny; anything bigger is a mistake.
const MAX_RULE_FILE: u64 = 256 * 1024;
const MAX_RULE_FILES: usize = 512;

/// Detector implementations a rule may name.
pub const DETECTORS: &[&str] = &[
    "beaconing",
    "dns_entropy",
    "dns_length",
    "dns_subdomain_rate",
    "dns_nxdomain_burst",
    "dns_tunnel",
    "http_beaconing",
    "http_tls_port",
    "http_post_exfil",
];

/// Default value (and type) of one detector parameter.
#[derive(Debug, Clone, Copy)]
enum Def {
    /// Number with inclusive bounds.
    Num(f64, f64, f64),
    Nums(&'static [f64]),
    Strs(&'static [&'static str]),
}

const IGNORE_SUFFIXES: &[&str] = &[
    "arpa",
    "local",
    "localdomain",
    "lan",
    "home",
    "internal",
    "intranet",
    "corp",
];

const BIG: f64 = 1e12;

/// Ports where a cleartext HTTP request line is out of place.
const TLS_PORTS: &[f64] = &[
    443.0, 8443.0, 465.0, 563.0, 636.0, 853.0, 989.0, 990.0, 993.0, 995.0, 5061.0, 6697.0,
];

/// `(name, default)` per param, per detector. Units: seconds unless `_ms`.
fn param_specs(detector: &str) -> Vec<(&'static str, Def)> {
    match detector {
        // Same series analysis as `beaconing`, over HTTP requests inside
        // connections instead of connection starts.
        "http_beaconing" => {
            let mut v = base_specs("beaconing").to_vec();
            v.extend_from_slice(&[
                ("min_requests_per_flow", Def::Num(2.0, 1.0, BIG)),
                ("named_host_factor", Def::Num(0.35, 0.0, 1.0)),
            ]);
            v
        }
        d => base_specs(d).to_vec(),
    }
}

fn base_specs(detector: &str) -> &'static [(&'static str, Def)] {
    match detector {
        "beaconing" => &[
            ("min_count", Def::Num(8.0, 3.0, BIG)),
            ("count_full", Def::Num(48.0, 3.0, BIG)),
            ("min_duration_s", Def::Num(300.0, 0.0, BIG)),
            ("duration_full_s", Def::Num(3600.0, 1.0, BIG)),
            ("min_interval_s", Def::Num(4.0, 0.0, BIG)),
            ("max_interval_s", Def::Num(21600.0, 0.001, BIG)),
            ("merge_gap_s", Def::Num(1.0, 0.0, 3600.0)),
            ("jitter_full", Def::Num(0.05, 0.0, 10.0)),
            ("max_jitter", Def::Num(0.35, 0.0, 10.0)),
            ("max_payload_cv", Def::Num(1.0, 0.01, 100.0)),
            (
                "ignore_dst_ports",
                Def::Nums(&[
                    53.0, 67.0, 68.0, 123.0, 137.0, 138.0, 1900.0, 5353.0, 5355.0,
                ]),
            ),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            (
                "known_good_suffixes",
                Def::Strs(&[
                    "microsoft.com",
                    "windows.com",
                    "msftncsi.com",
                    "apple.com",
                    "icloud.com",
                    "google.com",
                    "googleapis.com",
                    "gstatic.com",
                    "ubuntu.com",
                    "canonical.com",
                    "mozilla.com",
                    "mozilla.net",
                    "mozilla.org",
                ]),
            ),
            ("known_good_factor", Def::Num(0.35, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
        ],
        "dns_entropy" => &[
            ("min_unique", Def::Num(8.0, 1.0, BIG)),
            ("min_prefix_len", Def::Num(6.0, 0.0, 253.0)),
            ("entropy_low", Def::Num(3.0, 0.0, 8.0)),
            ("entropy_high", Def::Num(4.2, 0.0, 8.0)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
            ("ignore_suffixes", Def::Strs(IGNORE_SUFFIXES)),
        ],
        "dns_length" => &[
            ("min_queries", Def::Num(10.0, 1.0, BIG)),
            ("length_low", Def::Num(35.0, 0.0, 253.0)),
            ("length_high", Def::Num(80.0, 0.0, 253.0)),
            ("label_low", Def::Num(25.0, 0.0, 63.0)),
            ("label_high", Def::Num(63.0, 0.0, 253.0)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
            ("ignore_suffixes", Def::Strs(IGNORE_SUFFIXES)),
        ],
        "dns_subdomain_rate" => &[
            ("min_unique", Def::Num(20.0, 1.0, BIG)),
            ("min_span_s", Def::Num(60.0, 1.0, BIG)),
            ("rate_low", Def::Num(1.0, 0.0, BIG)),
            ("rate_high", Def::Num(10.0, 0.0, BIG)),
            ("ratio_low", Def::Num(0.5, 0.0, 1.0)),
            ("ratio_high", Def::Num(0.95, 0.0, 1.0)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
            ("ignore_suffixes", Def::Strs(IGNORE_SUFFIXES)),
        ],
        "dns_nxdomain_burst" => &[
            ("window_s", Def::Num(60.0, 1.0, 86400.0)),
            ("min_burst", Def::Num(10.0, 2.0, BIG)),
            ("burst_full", Def::Num(30.0, 2.0, BIG)),
            ("repeat_full", Def::Num(3.0, 1.0, BIG)),
            ("entropy_low", Def::Num(2.5, 0.0, 8.0)),
            ("entropy_high", Def::Num(3.5, 0.0, 8.0)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("ignore_suffixes", Def::Strs(IGNORE_SUFFIXES)),
        ],
        "dns_tunnel" => &[
            ("qtypes", Def::Strs(&["TXT", "NULL", "CNAME", "MX"])),
            ("min_queries", Def::Num(10.0, 1.0, BIG)),
            ("volume_full", Def::Num(100.0, 1.0, BIG)),
            ("bytes_low", Def::Num(2000.0, 0.0, BIG)),
            ("bytes_high", Def::Num(50000.0, 0.0, BIG)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
            ("ignore_suffixes", Def::Strs(IGNORE_SUFFIXES)),
        ],
        "http_tls_port" => &[
            ("tls_ports", Def::Nums(TLS_PORTS)),
            ("min_requests", Def::Num(3.0, 1.0, BIG)),
            ("requests_full", Def::Num(20.0, 1.0, BIG)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
        ],
        "http_post_exfil" => &[
            ("min_posts", Def::Num(5.0, 2.0, BIG)),
            ("posts_full", Def::Num(20.0, 2.0, BIG)),
            ("bytes_low", Def::Num(100_000.0, 0.0, BIG)),
            ("bytes_high", Def::Num(5_000_000.0, 0.0, BIG)),
            ("rate_low", Def::Num(2.0, 0.0, BIG)),
            ("rate_high", Def::Num(20.0, 0.0, BIG)),
            ("min_span_s", Def::Num(60.0, 1.0, BIG)),
            ("named_host_factor", Def::Num(0.5, 0.0, 1.0)),
            ("allowlist_factor", Def::Num(0.25, 0.0, 1.0)),
            ("prevalence_min_hosts", Def::Num(3.0, 2.0, BIG)),
            ("prevalence_ratio", Def::Num(0.3, 0.0, 1.0)),
            ("prevalence_factor", Def::Num(0.3, 0.0, 1.0)),
        ],
        _ => &[],
    }
}

/// Signals (weight keys) each detector scores.
fn signal_names(detector: &str) -> &'static [&'static str] {
    match detector {
        "beaconing" => &["regularity", "count", "duration", "payload_uniformity"],
        "dns_entropy" => &["entropy"],
        "dns_length" => &["query_length", "label_length"],
        "dns_subdomain_rate" => &["unique_rate", "unique_ratio"],
        "dns_nxdomain_burst" => &["burst", "repeat", "dga_entropy"],
        "dns_tunnel" => &["record_volume", "byte_volume"],
        "http_beaconing" => &["regularity", "count", "duration", "payload_uniformity"],
        "http_tls_port" => &["cleartext", "ip_host"],
        "http_post_exfil" => &["upload_volume", "ip_host", "repeat", "rate"],
        _ => &[],
    }
}

/// A validated rule with its params resolved (file values over defaults).
#[derive(Debug, Clone)]
pub struct Rule {
    pub def: RuleDef,
    nums: BTreeMap<&'static str, f64>,
    num_lists: BTreeMap<&'static str, Vec<f64>>,
    str_lists: BTreeMap<&'static str, Vec<String>>,
}

impl Rule {
    /// Numeric param. Validation guarantees every spec'd name is present.
    pub(crate) fn num(&self, name: &str) -> f64 {
        debug_assert!(self.nums.contains_key(name), "unknown param {name}");
        self.nums.get(name).copied().unwrap_or(0.0)
    }

    pub(crate) fn nums(&self, name: &str) -> &[f64] {
        self.num_lists.get(name).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn strs(&self, name: &str) -> &[String] {
        self.str_lists.get(name).map_or(&[], Vec::as_slice)
    }

    /// Max points of a signal (0 when the rule leaves it out).
    pub(crate) fn weight(&self, signal: &str) -> f64 {
        self.def.weights.get(signal).copied().unwrap_or(0.0)
    }

    pub fn id(&self) -> &str {
        &self.def.id
    }
}

/// The loaded, validated rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Validate already-parsed rules (ids unique, schemas respected).
    pub fn from_defs(defs: Vec<RuleDef>) -> ApiResult<Self> {
        let mut seen = BTreeSet::new();
        let mut rules = Vec::with_capacity(defs.len());
        for def in defs {
            if !seen.insert(def.id.clone()) {
                return Err(invalid(format!("duplicate rule id {:?}", def.id)));
            }
            rules.push(compile(def)?);
        }
        Ok(Self { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn defs(&self) -> impl Iterator<Item = &RuleDef> {
        self.rules.iter().map(|r| &r.def)
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.def.id == id)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Enabled rules of one detector, with their index in `rules()`.
    pub(crate) fn enabled(&self, detector: &str) -> impl Iterator<Item = (usize, &Rule)> {
        let detector = detector.to_string();
        self.rules
            .iter()
            .enumerate()
            .filter(move |(_, r)| r.def.enabled && r.def.detector == detector)
    }
}

fn invalid(msg: String) -> ApiError {
    ApiError::new(ErrorCode::InvalidArgument, msg)
}

/// Load every `*.yaml` rule in `dir` except `allowlist.yaml`.
pub fn load_rules(dir: &Path) -> ApiResult<RuleSet> {
    let entries = fs::read_dir(dir)
        .map_err(|e| ApiError::new(ErrorCode::Io, format!("rules dir {}: {e}", dir.display())))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".yaml") || name == "allowlist.yaml" || name.starts_with('.') {
            continue;
        }
        if !entry.file_type()?.is_file() {
            continue;
        }
        files.push((name, path));
        if files.len() > MAX_RULE_FILES {
            return Err(invalid(format!("more than {MAX_RULE_FILES} rule files")));
        }
    }
    files.sort();
    if files.is_empty() {
        return Err(invalid(format!(
            "no rule files (*.yaml) in {}",
            dir.display()
        )));
    }
    let mut defs = Vec::with_capacity(files.len());
    for (name, path) in files {
        let len = fs::metadata(&path)?.len();
        if len > MAX_RULE_FILE {
            return Err(invalid(format!(
                "{name}: rule file larger than {MAX_RULE_FILE} bytes"
            )));
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| ApiError::new(ErrorCode::Io, format!("{name}: {e}")))?;
        let def = RuleDef::from_yaml(&text).map_err(|e| invalid(format!("{name}: {e}")))?;
        defs.push(
            compile(def)
                .map_err(|e| invalid(format!("{name}: {}", e.message)))?
                .def,
        );
    }
    RuleSet::from_defs(defs)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// `T1234` or `T1234.567`.
fn valid_technique(t: &str) -> bool {
    let b = t.as_bytes();
    let base = b.len() >= 5 && b[0] == b'T' && b[1..5].iter().all(u8::is_ascii_digit);
    match b.len() {
        5 => base,
        9 => base && b[5] == b'.' && b[6..].iter().all(u8::is_ascii_digit),
        _ => false,
    }
}

fn compile(def: RuleDef) -> ApiResult<Rule> {
    let id = def.id.clone();
    let err = |m: String| invalid(format!("rule {id:?}: {m}"));
    if !valid_id(&def.id) {
        return Err(err("id must be 1-64 chars of [a-z0-9._-]".into()));
    }
    if !DETECTORS.contains(&def.detector.as_str()) {
        return Err(err(format!(
            "unknown detector {:?} (known: {})",
            def.detector,
            DETECTORS.join(", ")
        )));
    }
    if def.title.trim().is_empty() || def.title.len() > 200 {
        return Err(err("title must be 1-200 chars".into()));
    }
    if def.explanation.trim().is_empty() || def.explanation.len() > 2000 {
        return Err(err("explanation must be 1-2000 chars".into()));
    }
    if let Some(t) = &def.attack_technique {
        if !valid_technique(t) {
            return Err(err(format!(
                "attack_technique {t:?} is not T#### or T####.###"
            )));
        }
    }
    if !def.min_score.is_finite() || def.min_score < 0.0 || def.min_score > 100.0 {
        return Err(err("min_score must be in 0..=100".into()));
    }
    let signals = signal_names(&def.detector);
    for (k, w) in &def.weights {
        if !signals.contains(&k.as_str()) {
            return Err(err(format!(
                "unknown weight signal {k:?} for {} (known: {})",
                def.detector,
                signals.join(", ")
            )));
        }
        if !w.is_finite() || *w < 0.0 || *w > 100.0 {
            return Err(err(format!("weight {k} must be in 0..=100")));
        }
    }
    if def.enabled && !def.weights.values().any(|w| *w > 0.0) {
        return Err(err(
            "an enabled rule needs at least one positive weight".into()
        ));
    }

    let specs = param_specs(&def.detector);
    for k in def.params.keys() {
        if !specs.iter().any(|(n, _)| n == k) {
            let known: Vec<&str> = specs.iter().map(|(n, _)| *n).collect();
            return Err(err(format!(
                "unknown param {k:?} for {} (known: {})",
                def.detector,
                known.join(", ")
            )));
        }
    }
    let mut nums = BTreeMap::new();
    let mut num_lists = BTreeMap::new();
    let mut str_lists = BTreeMap::new();
    for &(name, spec) in &specs {
        let given = def.params.get(name);
        match spec {
            Def::Num(default, lo, hi) => {
                let v = match given {
                    None => default,
                    Some(v) => v
                        .as_f64()
                        .ok_or_else(|| err(format!("param {name} must be a number")))?,
                };
                if !v.is_finite() || v < lo || v > hi {
                    return Err(err(format!("param {name} = {v} out of range {lo}..={hi}")));
                }
                nums.insert(name, v);
            }
            Def::Nums(default) => {
                let v = match given {
                    None => default.to_vec(),
                    Some(v) => v
                        .as_array()
                        .and_then(|a| a.iter().map(serde_json::Value::as_f64).collect())
                        .ok_or_else(|| err(format!("param {name} must be a list of numbers")))?,
                };
                num_lists.insert(name, v);
            }
            Def::Strs(default) => {
                let v = match given {
                    None => default.iter().map(|s| s.to_string()).collect(),
                    Some(v) => v
                        .as_array()
                        .and_then(|a| {
                            a.iter()
                                .map(|s| s.as_str().map(str::to_string))
                                .collect::<Option<Vec<_>>>()
                        })
                        .ok_or_else(|| err(format!("param {name} must be a list of strings (quote YAML keywords such as \"NULL\")")))?,
                };
                str_lists.insert(name, v);
            }
        }
    }
    // Cross-field sanity.
    let pairs: &[(&str, &str)] = &[
        ("jitter_full", "max_jitter"),
        ("min_interval_s", "max_interval_s"),
        ("entropy_low", "entropy_high"),
        ("length_low", "length_high"),
        ("label_low", "label_high"),
        ("rate_low", "rate_high"),
        ("ratio_low", "ratio_high"),
        ("bytes_low", "bytes_high"),
        ("min_count", "count_full"),
        ("min_burst", "burst_full"),
    ];
    for (lo, hi) in pairs {
        if let (Some(a), Some(b)) = (nums.get(lo), nums.get(hi)) {
            if a > b {
                return Err(err(format!("param {lo} ({a}) must be <= {hi} ({b})")));
            }
        }
    }
    Ok(Rule {
        def,
        nums,
        num_lists,
        str_lists,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(yaml: &str) -> RuleDef {
        RuleDef::from_yaml(yaml).expect("yaml")
    }

    const OK: &str = "id: beacon.periodic\ntitle: T\ndetector: beaconing\nattack_technique: T1071\n\
                      params: { min_count: 6 }\nweights: { regularity: 50 }\nexplanation: x\n";

    #[test]
    fn compiles_and_fills_defaults() {
        let r = compile(def(OK)).expect("ok");
        assert_eq!(r.num("min_count"), 6.0);
        assert_eq!(r.num("max_jitter"), 0.35);
        assert!(r.nums("ignore_dst_ports").contains(&123.0));
        assert_eq!(r.weight("regularity"), 50.0);
        assert_eq!(r.weight("count"), 0.0);
    }

    #[test]
    fn rejects_bad_rules() {
        let bad = [
            OK.replace("beaconing", "nope"),
            OK.replace("min_count: 6", "min_cuont: 6"),
            OK.replace("min_count: 6", "min_count: \"six\""),
            OK.replace("min_count: 6", "min_count: 1"),
            OK.replace("regularity: 50", "regularty: 50"),
            OK.replace("regularity: 50", "regularity: -1"),
            OK.replace("regularity: 50", "regularity: 0"),
            OK.replace("T1071", "1071"),
            OK.replace("beacon.periodic", "Beacon Periodic"),
            OK.replace(
                "params: { min_count: 6 }",
                "params: { max_jitter: 0.01, jitter_full: 0.5 }",
            ),
            OK.replace(
                "params: { min_count: 6 }",
                "params: { ignore_dst_ports: [a] }",
            ),
        ];
        for y in bad {
            assert!(compile(def(&y)).is_err(), "should reject:\n{y}");
        }
    }

    #[test]
    fn disabled_rule_may_have_no_weights() {
        let y = OK.replace("weights: { regularity: 50 }", "enabled: false");
        assert!(compile(def(&y)).is_ok());
    }

    #[test]
    fn duplicate_ids_rejected() {
        assert!(RuleSet::from_defs(vec![def(OK), def(OK)]).is_err());
    }

    #[test]
    fn technique_pattern() {
        assert!(valid_technique("T1071"));
        assert!(valid_technique("T1071.004"));
        assert!(!valid_technique("T107"));
        assert!(!valid_technique("T1071.04"));
        assert!(!valid_technique("t1071"));
    }
}
