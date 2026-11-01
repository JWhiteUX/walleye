//! Findings (detections) and IOCs. Principle: evidence or it didn't happen.
//! Every `Reason` and every `Ioc` carries `Evidence` that resolves to frames.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{FlowId, FrameNo, Ts};

/// Maximum ids kept per evidence list. Detectors keep the earliest
/// `EVIDENCE_CAP` and set `truncated` with the real `total`.
pub const EVIDENCE_CAP: usize = 200;

/// Pointers back into the index. Must not be empty on any reason or IOC:
/// at least one of `flow_ids` / `frame_nos` is non-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Evidence {
    #[ts(type = "number[]")]
    pub flow_ids: Vec<FlowId>,
    #[ts(type = "number[]")]
    pub frame_nos: Vec<FrameNo>,
    /// True when the lists were capped at `EVIDENCE_CAP`.
    #[serde(default)]
    pub truncated: bool,
    /// Total supporting items before capping.
    #[serde(default)]
    #[ts(type = "number")]
    pub total: u64,
}

impl Evidence {
    pub fn is_empty(&self) -> bool {
        self.flow_ids.is_empty() && self.frame_nos.is_empty()
    }
}

/// One explained contribution to a finding's score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Reason {
    /// Rule that produced this reason (`id` in rules/*.yaml).
    pub rule_id: String,
    /// Signal name, e.g. "interval_regularity", "subdomain_entropy".
    pub signal: String,
    /// Measured value of the signal.
    pub value: f64,
    /// Unit of `value` for display ("s", "bits", "ratio", "count", ...).
    pub unit: Option<String>,
    /// Points this reason contributed to the score.
    pub weight: f64,
    /// Rendered explanation template, human-readable, no markup.
    pub explanation: String,
    pub attack_technique: Option<String>,
    pub evidence: Evidence,
}

/// Analyst verdict on a finding (stored in the case store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum Verdict {
    Suspicious,
    Benign,
    NeedsReview,
}

/// `findings` table row (plus `verdict`, joined from the case store over IPC).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Finding {
    /// Stable across re-runs: hex of hash(detector, entity_type, entity).
    pub finding_id: String,
    pub title: String,
    /// Detector of the highest-weight reason ("beaconing", "dns").
    pub detector: String,
    /// "host" | "pair" | "domain" | "device" (802.11 MAC, contract v2).
    pub entity_type: String,
    /// IP for host, "src->dst" for pair, name for domain, lowercase MAC for
    /// device.
    pub entity: String,
    /// 0..=100. Higher is more suspicious.
    pub score: f64,
    /// ATT&CK technique of the highest-weight reason, e.g. "T1071.004".
    pub attack_technique: Option<String>,
    #[ts(type = "number")]
    pub ts_first: Ts,
    #[ts(type = "number")]
    pub ts_last: Ts,
    /// Sorted by `weight` descending. Never empty.
    pub reasons: Vec<Reason>,
    /// Not stored in the index; filled from the case store over IPC.
    #[serde(default)]
    pub verdict: Option<Verdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum IocType {
    Ip,
    Domain,
    Url,
    Ja4,
    CertSerial,
}

/// `iocs` table row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Ioc {
    /// hex of hash(type, normalized value).
    pub ioc_id: String,
    #[serde(rename = "type")]
    #[ts(rename = "type")]
    pub ioc_type: IocType,
    /// Normalized, live form. Never rendered as a clickable link.
    pub value: String,
    /// Defanged form ("hxxp://evil[.]top/x", "10[.]0[.]0[.]5").
    pub defanged: String,
    pub source_finding_id: Option<String>,
    #[ts(type = "number")]
    pub first_seen: Ts,
    pub evidence: Evidence,
    pub allowlisted: bool,
    /// Allowlist entry reason when `allowlisted`.
    pub allowlist_reason: Option<String>,
}
