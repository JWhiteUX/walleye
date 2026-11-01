//! `load_rules(dir)`: every `*.yaml` except `allowlist.yaml`, validated,
//! unique ids, unknown detector → error.

mod common;

use std::fs;
use std::path::PathBuf;

use common::repo_root;
use walleye_detect::{DETECTORS, load_rules};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "walleye-detect-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("mkdir");
        Self(p)
    }
    fn write(&self, name: &str, text: &str) {
        fs::write(self.0.join(name), text).expect("write");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const RULE: &str = "id: x.one\ntitle: T\ndetector: beaconing\nattack_technique: T1071\n\
                    weights: { regularity: 50 }\nexplanation: \"{src}\"\n";

#[test]
fn repo_rules_load_and_cover_every_detector() {
    let rs = load_rules(&repo_root().join("rules")).expect("load");
    assert_eq!(rs.len(), 12, "one rule per detector");
    for d in DETECTORS {
        assert!(
            rs.defs().any(|r| r.detector == *d && r.enabled),
            "no enabled rule for {d}"
        );
    }
    let allowed = [
        "T1071",
        "T1071.001",
        "T1071.004",
        "T1568.002",
        "T1048",
        "T1041",
        "T1498",
        "T1557",
    ];
    for r in rs.defs() {
        let t = r.attack_technique.as_deref().expect("technique");
        assert!(allowed.contains(&t), "{} uses {t}", r.id);
        assert!(r.min_score > 0.0, "{} needs a min_score", r.id);
    }
    assert!(rs.get("beacon.periodic").is_some());
    assert!(rs.get("allowlist").is_none());
}

#[test]
fn skips_allowlist_and_non_yaml() {
    let d = TempDir::new("skip");
    d.write("a.yaml", RULE);
    d.write("allowlist.yaml", "version: 1\ndomains: []\n");
    d.write("notes.txt", "not a rule");
    d.write("b.yml", "garbage: [");
    d.write(".hidden.yaml", "garbage: [");
    let rs = load_rules(&d.0).expect("load");
    assert_eq!(rs.len(), 1);
}

#[test]
fn duplicate_ids_across_files_rejected() {
    let d = TempDir::new("dup");
    d.write("a.yaml", RULE);
    d.write("b.yaml", RULE);
    let e = load_rules(&d.0).expect_err("dup");
    assert!(e.message.contains("duplicate"), "{}", e.message);
}

#[test]
fn unknown_detector_rejected_with_file_name() {
    let d = TempDir::new("unk");
    d.write("bad.yaml", &RULE.replace("beaconing", "telepathy"));
    let e = load_rules(&d.0).expect_err("unknown");
    assert!(e.message.contains("bad.yaml"), "{}", e.message);
    assert!(e.message.contains("telepathy"), "{}", e.message);
}

#[test]
fn malformed_and_unknown_keys_rejected() {
    for (i, text) in [
        "id: [\n".to_string(),
        RULE.replace("weights", "wieghts"),
        RULE.replace(
            "weights: { regularity: 50 }",
            "weights: { regularity: 50 }\nparams: { min_cuont: 3 }",
        ),
        RULE.replace("regularity: 50", "entropy: 50"),
    ]
    .iter()
    .enumerate()
    {
        let d = TempDir::new(&format!("bad{i}"));
        d.write("r.yaml", text);
        assert!(load_rules(&d.0).is_err(), "should reject:\n{text}");
    }
}

#[test]
fn empty_or_missing_dir_is_an_error() {
    let d = TempDir::new("empty");
    assert!(load_rules(&d.0).is_err());
    assert!(load_rules(&d.0.join("missing")).is_err());
}

#[test]
fn oversized_rule_file_rejected() {
    let d = TempDir::new("big");
    let mut text = RULE.to_string();
    text.push_str(&format!("# {}\n", "x".repeat(300 * 1024)));
    d.write("big.yaml", &text);
    assert!(load_rules(&d.0).is_err());
}
