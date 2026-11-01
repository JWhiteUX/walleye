//! Detection rule YAML schema (`rules/*.yaml`, one rule per file, loaded at
//! runtime by walleye-detect). See docs/CONTRACTS.md §6.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One detection rule.
///
/// ```yaml
/// id: beacon.periodic
/// title: Periodic outbound connections
/// detector: beaconing
/// attack_technique: T1071
/// params: { min_count: 8, max_jitter: 0.2, min_duration_s: 600 }
/// weights: { regularity: 50, count: 20, duration: 20, small_payload: 10 }
/// min_score: 30
/// explanation: "{src} contacted {dst} {count} times, every {interval_s}s ±{jitter_pct}%"
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    /// Unique, dotted, stable. Appears in `Reason.rule_id`.
    pub id: String,
    pub title: String,
    /// Detector implementation: `beaconing`, `dns_entropy`, `dns_length`,
    /// `dns_subdomain_rate`, `dns_nxdomain_burst`, `dns_tunnel`.
    pub detector: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub attack_technique: Option<String>,
    /// Detector-specific thresholds. Numbers, strings or lists.
    #[serde(default)]
    pub params: BTreeMap<String, serde_json::Value>,
    /// Signal name → maximum points. A signal scores `weight × strength`,
    /// strength in 0..=1.
    #[serde(default)]
    pub weights: BTreeMap<String, f64>,
    /// Drop the reason if its points are below this.
    #[serde(default)]
    pub min_score: f64,
    /// `{name}` placeholders filled from the detector's measured values.
    /// No logic, no markup. Unknown placeholders render as `{name}`.
    pub explanation: String,
}

fn yes() -> bool {
    true
}

impl RuleDef {
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml_ng::Error> {
        serde_yaml_ng::from_str(text)
    }
}

/// Fill `{name}` placeholders. Values are inserted verbatim (they come from
/// the detector, which must defang domains/IPs itself if needed).
pub fn render_template(template: &str, values: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close)
                if after[..close]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && close > 0 =>
            {
                let key = &after[..close];
                match values.get(key) {
                    Some(v) => out.push_str(v),
                    None => {
                        out.push('{');
                        out.push_str(key);
                        out.push('}');
                    }
                }
                rest = &after[close + 1..];
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rule_yaml() {
        let r = RuleDef::from_yaml(
            "id: beacon.periodic\ntitle: T\ndetector: beaconing\nattack_technique: T1071\n\
             params: { min_count: 8 }\nweights: { regularity: 50 }\nexplanation: \"{src} x\"\n",
        )
        .expect("parse");
        assert!(r.enabled);
        assert_eq!(r.weights["regularity"], 50.0);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(
            RuleDef::from_yaml("id: a\ntitle: t\ndetector: d\nexplanation: e\nbogus: 1\n").is_err()
        );
    }

    #[test]
    fn renders_template() {
        let mut v = BTreeMap::new();
        v.insert("src".to_string(), "10.0.0.5".to_string());
        assert_eq!(
            render_template("{src} -> {dst} {} {", &v),
            "10.0.0.5 -> {dst} {} {"
        );
    }
}
