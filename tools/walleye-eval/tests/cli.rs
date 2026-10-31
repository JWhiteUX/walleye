//! Runs the real `walleye-eval` binary on hand-made findings/labels pairs.

use std::path::{Path, PathBuf};
use std::process::Command;

fn finding(entity: &str, score: f64) -> serde_json::Value {
    serde_json::json!({
        "finding_id": format!("{:016x}", entity.bytes().fold(0u64, |h, b| h.wrapping_mul(31) + u64::from(b))),
        "title": "Periodic outbound connections",
        "detector": "beaconing",
        "entity_type": "host",
        "entity": entity,
        "score": score,
        "attack_technique": "T1071",
        "ts_first": 1_773_133_200_000_000i64,
        "ts_last": 1_773_140_400_000_000i64,
        "reasons": [{
            "rule_id": "beacon.periodic", "signal": "regularity", "value": 0.97,
            "unit": "ratio", "weight": score, "explanation": "x",
            "attack_technique": "T1071",
            "evidence": {"flow_ids": [1, 2], "frame_nos": [10, 20], "truncated": false, "total": 2}
        }]
    })
}

fn write(dir: &Path, name: &str, v: &serde_json::Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(v).expect("json")).expect("write");
    p
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("walleye-eval-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

#[test]
fn prints_table_for_several_pairs_and_gates() {
    let d = tmpdir("ok");
    let beacon_f = write(
        &d,
        "beacon.findings.json",
        &serde_json::json!([finding("10.0.0.15", 40.0), finding("10.0.0.23", 88.0)]),
    );
    let beacon_l = write(
        &d,
        "beacon.labels.json",
        &serde_json::json!({"scenario": "beacon", "c2_hosts": ["10.0.0.23"], "benign": false}),
    );
    let office_f = write(
        &d,
        "office.findings.json",
        &serde_json::json!([finding("10.0.0.15", 31.0)]),
    );
    let office_l = write(
        &d,
        "office.labels.json",
        &serde_json::json!({"scenario": "office", "c2_hosts": [], "benign": true}),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_walleye-eval"))
        .args(["--findings"])
        .arg(&beacon_f)
        .arg("--labels")
        .arg(&beacon_l)
        .arg("--findings")
        .arg(&office_f)
        .arg("--labels")
        .arg(&office_l)
        .args(["--k", "5", "--gate"])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("| beacon | malicious | 2 | 1 | yes | 1 | 10% | yes |"),
        "{text}"
    );
    assert!(
        text.contains("| office | benign | 1 | n/a | n/a | 1 | 10% | yes |"),
        "{text}"
    );
    assert!(text.contains("Gates: PASS"));

    // A miss makes --gate exit 1.
    let miss_f = write(
        &d,
        "miss.findings.json",
        &serde_json::json!([finding("10.0.0.9", 50.0)]),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_walleye-eval"))
        .arg("--findings")
        .arg(&miss_f)
        .arg("--labels")
        .arg(&beacon_l)
        .arg("--gate")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Gates: FAIL"));

    // Mismatched pairs are a usage error.
    let out = Command::new(env!("CARGO_BIN_EXE_walleye-eval"))
        .arg("--findings")
        .arg(&miss_f)
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}
