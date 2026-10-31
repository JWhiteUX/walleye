# External labelled samples

Public malware-traffic captures used for the detection gate ("known C2 in the top 5 on all 3 labelled samples"). The pcaps are **not** in the repo: they live in `$WALLEYE_FIXTURES/external/<name>/` (default `~/.walleye-fixtures`), one per directory, pcap only. Ground truth for `walleye-eval` is in `fixtures/labels/<name>.labels.json`.

All three are by Brad Duncan, malware-traffic-analysis.net. Archives use the site's date password scheme (`infected_YYYYMMDD`). Only the `.pcap` member was extracted (`unzip -P … -j <zip> '<member>.pcap' -d <dir>`), the archive was deleted, and nothing else from the archive was opened. Each file was checked for the classic pcap magic (`d4c3b2a1`, little-endian µs). Known-bad hosts come from the write-up. The infected internal host comes from the headers of the packets to the C2 IP (`tcpdump -nn -q -c 3 -r <pcap> host <c2>`, read-only).

| Name | Source URL | File | Size (bytes) | SHA-256 | Infected host | Known-bad hosts |
|---|---|---|---:|---|---|---|
| `mta-2024-12-17-netsupport` | https://www.malware-traffic-analysis.net/2024/12/17/index.html | `2024-12-17-SmartApeSG-to-NetSupport-RAT.pcap` | 23115175 | `3d4d0b98311d7edd4e00def085450db692e62ba3f626075e7cd633f0cc340b86` | 10.12.17.101 | C2 `194.180.191[.]64:443` (POST /fakeurl.htm); `depostsolo[.]biz`, `tactlat[.]xyz` (SmartApeSG delivery) |
| `mta-2025-12-29-netsupport` | https://www.malware-traffic-analysis.net/2025/12/29/index.html | `2025-12-29-ClickFix-page-sends-NetSupportRAT.pcap` | 41119671 | `7b18868c20aff09e15c6bc68806a304b45af6f33d4776834238388a0666c660f` | 10.12.29.101 | C2 `185.39.19[.]96:443` (POST /fakeurl.htm); payload host `80.253.249[.]145`; `ivanstonework[.]com`, `extracareliving[.]com`, `relativegoingplanning[.]net` |
| `mta-2025-12-22-stealc` | https://www.malware-traffic-analysis.net/2025/12/22/index.html | `2025-12-22-post-infection-traffic-for-StealC.pcap` (from `2025-12-22-traffic-from-StealC-infection.zip`) | 6118121 | `2d2bb58112caf0a5f8c76a50b868d2586ea6d421f2c31571a80ba5de5e3cca62` | 10.12.22.101 | C2 `hxxp://37.221.66[.]166/4a815a53876a4172.php` |

Notes:
- `geo.netsupportsoftware[.]com` (sample 1) is NetSupport's own geolocation lookup, and `104.21.96[.]46` (sample 2) is a Cloudflare front. Neither is labelled bad.
- Two samples are NetSupport RAT, whose C2 is HTTP-over-443 polling (beacon-like). StealC is short-lived HTTP C2, which is harder for interval-based beacon detection. Replace a sample here (and its labels file) if the lead wants more family diversity.
