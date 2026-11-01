//! Row buffers filled by flow assembly and the protocol parsers.

use walleye_core::{
    DnsRow, FileRow, FlowId, FlowRow, FrameNo, FrameRow, HttpRow, TlsRow, Ts, WifiRow,
};

#[derive(Debug, Default)]
pub struct Out {
    pub frames: Vec<FrameRow>,
    pub flows: Vec<FlowRow>,
    pub dns: Vec<DnsRow>,
    pub http: Vec<HttpRow>,
    pub tls: Vec<TlsRow>,
    pub files: Vec<FileRow>,
    pub wifi: Vec<WifiRow>,
}

impl Out {
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
            && self.flows.is_empty()
            && self.dns.is_empty()
            && self.http.is_empty()
            && self.tls.is_empty()
            && self.files.is_empty()
            && self.wifi.is_empty()
    }
}

/// Where the bytes being fed to an application parser came from.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub flow_id: FlowId,
    pub frame_no: FrameNo,
    pub ts: Ts,
}
