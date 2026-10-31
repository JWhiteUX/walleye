# Walleye case report

Case `a3f1c9e07b5d2e64` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0`

_Every claim below links to frame numbers in this capture; analyst notes and verdicts are marked as such and are not claims._

## Capture

| Field | Value |
|---|---|
| Path | `/cases/office-beacon.pcap` |
| SHA-256 | `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` |
| Capture ID | `a3f1c9e07b5d2e64` |
| Size | 238862 bytes |
| Format | pcap |
| Frames | 2449 |
| Time span | 2026-03-12 09:00:26.906498Z → 2026-03-12 09:58:46.976582Z (58m 20s) |

## Findings

### F1. `Beaconing to 185.199.110.77 (cdn-update.top)` — [frames 23, 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23,100,110,120)

- Score **92** (High) · `host` `10.0.0.23` · detector `beaconing` · ATT&CK `T1071` · seen 2026-03-12 09:01:26.906498Z → 2026-03-12 09:03:26.906498Z · finding `f1b2c3d4e5f60001` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frames 23, 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23,100,110,120)
- **46 pts** · rule `beacon.periodic` · `interval_regularity` = 0.0138 `ratio` · `10.0.0.23 contacted 185.199.110.77 3 times, every 60.0s ±1.4%` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frames 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/100,110,120)
- **20 pts** · rule `http.stage` · `staging_request` = 0.0138 `ratio` · `GET /gate.php?id=7f3a before the first beacon` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frame 23](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23)

> **Analyst verdict (not a claim):** suspicious — Confirmed with the host owner\: \*not\* a sanctioned tool\.

### F2. `DNS tunnel via t.exfil-dns.xyz` — [frames 300, 301, 302, 303, 304, 305, 306, 307, 308, 309](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301,302,303,304,305,306,307,308,309)

- Score **81** (High) · `host` `10.0.0.17` · detector `dns_tunnel` · ATT&CK `T1071.004` · seen 2026-03-12 09:03:46.906498Z → 2026-03-12 09:03:55.906498Z · finding `f1b2c3d4e5f60002` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frames 300, 301, 302, 303, 304, 305, 306, 307, 308, 309](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301,302,303,304,305,306,307,308,309)
- **40 pts** · rule `dns.tunnel` · `subdomain_entropy` = 0.0138 `ratio` · `10 high-entropy subdomains of exfil-dns.xyz` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frames 300, 301, 302, 303, 304, 305, 306, 307, 308, 309](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301,302,303,304,305,306,307,308,309)

### F3. `Periodic connections to Windows Update` — [frame 5](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/5)

- Score **12** (Low) · `host` `10.0.0.15` · detector `beaconing` · seen 2026-03-12 09:00:31.906498Z → 2026-03-12 09:00:32.906498Z · finding `f1b2c3d4e5f60004` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frame 5](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/5)
- **12 pts** · rule `beacon.periodic` · `interval_regularity` = 0.0138 `ratio` · `allowlisted destination (Microsoft Update): down-weighted` · capture SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0` — [frame 5](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/5)

## ATT&CK techniques

- `T1071` Application Layer Protocol · findings F1 — [frames 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/100,110,120)
- `T1071.001` Application Layer Protocol: Web Protocols · findings F1 — [frame 23](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23)
- `T1071.004` Application Layer Protocol: DNS · findings F2 — [frames 300, 301, 302, 303, 304, 305, 306, 307, 308, 309](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301,302,303,304,305,306,307,308,309)

## Indicators of compromise

_Values are defanged. Allowlisted indicators are known-good destinations, kept and flagged._

| Type | Indicator (defanged) | First seen | Evidence | Allowlisted | Finding |
|---|---|---|---|---|---|
| ip | `13[.]107[.]4[.]50` | 2026-03-12 09:00:31.906498Z | [frame 5](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/5) | yes: `Microsoft` | F3 |
| domain | `fe2[.]update[.]microsoft[.]com` | 2026-03-12 09:00:31.906498Z | [frame 7](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/7) | yes: `Microsoft Update` | F3 |
| ja4 | `t13d1516h2_8daaf6152771_02713d6af862` | 2026-03-12 09:00:31.906498Z | [frame 7](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/7) | no | F3 |
| cert_serial | `33000001` | 2026-03-12 09:00:31.906498Z | [frame 7](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/7) | yes: `Microsoft Update` | F3 |
| domain | `cdn-update[.]top` | 2026-03-12 09:00:36.906498Z | [frames 10, 11, 23, 103, 113, 123](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/10,11,23,103,113,123) | no | F1 |
| ip | `185[.]199[.]110[.]77` | 2026-03-12 09:00:37.906498Z | [frames 20, 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/20,100,110,120) | no | F1 |
| url | `hxxp://cdn-update[.]top/gate[.]php?id=7f3a` | 2026-03-12 09:00:37.906498Z | [frame 23](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23) | no | F1 |
| ja4 | `t12d190800_d83cc789557e_7af1ed941c26` | 2026-03-12 09:01:26.906498Z | [frames 103, 113, 123](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/103,113,123) | no | F1 |
| cert_serial | `00d1e2f3a4b5c6d7` | 2026-03-12 09:01:26.906498Z | [frames 103, 113, 123](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/103,113,123) | no | F1 |
| domain | `exfil-dns[.]xyz` | 2026-03-12 09:03:46.906498Z | [frames 300, 301, 302, 303, 304, 305, 306, 307, 308, 309](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301,302,303,304,305,306,307,308,309) | no | F2 |

## Pinned evidence

- **pin-1** · frame 23 · pinned 2026-03-12 10:02:06.906498Z — [frame 23](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23)

> **Analyst note (not a claim):** Staging request\.
>
> See the URI\.

- **pin-2** · finding `f1b2c3d4e5f60001` (F1 `Beaconing to 185.199.110.77 (cdn-update.top)`) · pinned 2026-03-12 10:02:07.906498Z — [frames 23, 100, 110, 120](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/23,100,110,120)
- **pin-4** · query on dns `host 10.0.0.17` · pinned 2026-03-12 10:02:09.906498Z — [frames 300, 301](walleye://sha256/a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0/frames/300,301)

## Analyst notes

> **Analyst note (not a claim), pin-3 at 2026-03-12 10:02:08.906498Z:** Escalated to IR\. \# not a heading \[x\]\(http\:\/\/evil\.example\) \<b\>no html\<\/b\>

## Queries used

_A log of the queries run in this case (a record, not a claim). SQL shows placeholders, never values._

| # | First run | Runs | View | Filter | Time range | Rows | SQL |
|---|---|---|---|---|---|---|---|
| 1 | 2026-03-12 10:00:26.906498Z | 2 | flows | `host 10.0.0.23` | whole capture | 61 | `SELECT * FROM flows WHERE (src_ip = ? OR dst_ip = ?) LIMIT ?` |
| 2 | 2026-03-12 10:00:28.906498Z | 1 | dns | `dns.query ~ "*.exfil-dns.xyz" \| evil` | 2026-03-12 09:00:26.906498Z → 2026-03-12 09:10:26.906498Z | 10 | — |

## About this report

- Evidence links have the form `walleye://sha256/<capture SHA-256>/frames/<n>[,<n>…]` (or `/flows/<id>…` when only flows were recorded). The link text lists the frame numbers; open them in Walleye or Wireshark (Go to packet).
- At most 10 frame numbers are listed per claim; the total is given when there are more.
- Generated by Walleye 0.1.0 from the capture with SHA-256 `a3f1c9e07b5d2e6448c2b1f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0`.
