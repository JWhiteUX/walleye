# Fixtures

Generated and downloaded captures live in `$WALLEYE_FIXTURES` (default `~/.walleye-fixtures`), never here. This directory holds only small committed metadata: `LABELS.md` (external samples: source, SHA-256, known-bad hosts) and `labels/*.labels.json` (ground truth for `walleye-eval`). Owner: Agent G. See docs/CONTRACTS.md §9.

## Generated scenarios

```sh
cargo build --release -p walleye-gen
G=${WALLEYE_FIXTURES:-$HOME/.walleye-fixtures}/generated; mkdir -p "$G"
for s in office beacon dns_tunnel dga; do
  target/release/walleye-gen --scenario $s --seed 1 --out "$G/$s.pcap"
done
target/release/walleye-gen --scenario scale --seed 1 --size-gb 10 --out "$G/scale.pcap"
tools/walleye-gen/validate.sh "$G"/office.pcap   # tshark: checksums + malformed count
```

Each run writes `<stem>.labels.json` beside the capture; the same seed gives a byte-identical file (so the SHA-256 in the labels is reproducible). Options: `--duration-min N` (small scenarios; default 120), `--ipv6` (dual-stack macOS hosts and AAAA answers), `--size-gb N` (scale; GiB).

| Scenario | Window (UTC, 2026-03-10) | Infected host (`c2_hosts`) | Malicious behaviour |
|---|---|---|---|
| `office` | 09:00–11:00, 20 hosts | none (`benign: true`) | none. FP traps: 10.0.0.15 polls `ctldl.windowsupdate.com` every 900 s ±1 %; all hosts send NTP every 1024 s; Windows telemetry every 300 s ±50 %; CDN CNAME chains; hash-like CloudFront names |
| `beacon` | same | 10.0.0.23 | TLS 1.2 to `cdn-update.top` / 185.199.110.77 every 60 s ±3 %, self-signed cert, implant ClientHello (no ALPN, no GREASE) |
| `dns_tunnel` | same | 10.0.0.17 | bursts of 100–400 base32 queries under `t.exfil-dns.xyz` (85 % TXT, 5 % NULL, 10 % A) via resolver 10.0.0.2 |
| `dga` | same | 10.0.0.12 | every 300 s ±10 %: 25–60 random-name A queries (NXDOMAIN); one seed-derived domain resolves to 203.0.113.45, followed by TLS |
| `scale` | from 08:00 until the size budget | 10.0.0.23, .17, .12 | 200 hosts, adds bulk video/backup/update transfers, plus all three behaviours above |

Fidelity notes: real TCP handshakes, MSS segmentation, delayed ACKs, and FIN/RST teardown with consistent seq/ack; correct IPv4/IPv6/TCP/UDP lengths and checksums; DNS with name compression, CNAME chains, SOA on NODATA/NXDOMAIN; HTTP/1.1 with Content-Length and Content-Disposition; TLS 1.3 (ServerHello + encrypted remainder) and TLS 1.2 (plaintext Certificate chain). Chrome and Firefox ClientHellos carry an X25519MLKEM768 key share, so they span two TCP segments, as they do in real traffic. Certificates and OCSP/CRL bodies are structurally valid DER; their keys and signatures are random bytes.
