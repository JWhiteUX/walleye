#!/usr/bin/env python3
"""Write the hand-built seed corpora under fuzz/seeds/<target>/.

Every seed here is synthetic and tiny, built byte by byte from RFC layouts.
None comes from a real capture, and none contains a payload. Run with
`python3 -I fuzz/tools/make_seeds.py`. The output is deterministic, and the
committed seeds are its output.

Seed files use a `.bin` extension: the repo .gitignore ignores *.pcap.
"""

import json
import os
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seeds")


def put(target, name, data):
    d = os.path.join(ROOT, target)
    os.makedirs(d, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)


# ---- packet building ------------------------------------------------------

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
                      bytes(src), bytes(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def eth(payload, ethertype=0x0800):
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack("!H", ethertype) + payload


A = [10, 0, 0, 5]
B = [192, 0, 2, 10]  # TEST-NET-1


def dns_name(n):
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def dns_query(name="example.com", qtype=1, tid=0x1234):
    return struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def dns_response(name="example.com", tid=0x1234):
    q = dns_name(name) + struct.pack("!HH", 1, 1)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 1])
    return struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0) + q + ans


def dns_nxdomain(name="qz7x1k.example.net"):
    return struct.pack("!HHHHHH", 7, 0x8183, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_txt_response():
    q = dns_name("t.example.org") + struct.pack("!HH", 16, 1)
    txt = b"\x05hello"
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(txt)) + txt
    return struct.pack("!HHHHHH", 9, 0x8180, 1, 1, 0, 0) + q + ans


def dns_pointer_loop():
    # Answer name is a compression pointer to itself: a classic infinite loop.
    q = dns_name("a.example") + struct.pack("!HH", 1, 1)
    off = 12 + len(q)
    ans = struct.pack("!H", 0xC000 | off) + struct.pack("!HHIH", 1, 1, 1, 4) + b"\0\0\0\0"
    return struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + q + ans


HTTP_REQ = (b"GET /index.html?q=1 HTTP/1.1\r\nHost: www.example.com\r\n"
            b"User-Agent: walleye-seed/1.0\r\nAccept: */*\r\n\r\n")
HTTP_RESP = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
             b"Content-Length: 4\r\nContent-Disposition: attachment; filename=\"a.txt\"\r\n\r\nabcd")
HTTP_POST = (b"POST /up HTTP/1.0\r\nHost: 192.0.2.10:8080\r\nContent-Length: 0\r\n"
             b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")


def tls_ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def client_hello(sni="www.example.com"):
    name = sni.encode()
    sni_ext = tls_ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    groups = tls_ext(10, struct.pack("!H", 4) + struct.pack("!HH", 0x001D, 0x0017))
    alpn_list = b"\x02h2\x08http/1.1"
    alpn = tls_ext(16, struct.pack("!H", len(alpn_list)) + alpn_list)
    sigalgs = tls_ext(13, struct.pack("!H", 4) + struct.pack("!HH", 0x0403, 0x0804))
    versions = tls_ext(43, b"\x04\x03\x04\x03\x03")
    grease = tls_ext(0x0A0A, b"")
    exts = grease + sni_ext + groups + sigalgs + alpn + versions
    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0xC02F, 0x0A0A)
    body = (b"\x03\x03" + bytes(range(32)) + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def server_hello():
    exts = tls_ext(43, b"\x03\x04") + tls_ext(16, b"\x00\x03\x02h2")
    body = (b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


# ---- minimal DER certificate (structure only; signature bytes are zeros) ---

def der(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    elif n < 0x100:
        ln = b"\x81" + bytes([n])
    else:
        ln = b"\x82" + struct.pack("!H", n)
    return bytes([tag]) + ln + body


def name(cn):
    oid_cn = der(0x06, b"\x55\x04\x03")
    return der(0x30, der(0x31, der(0x30, oid_cn + der(0x0C, cn.encode()))))


def certificate(subject="seed.example", issuer="seed.example"):
    alg = der(0x30, der(0x06, b"\x2a\x86\x48\xce\x3d\x04\x03\x02"))  # ecdsa-with-SHA256
    validity = der(0x30, der(0x17, b"260101000000Z") + der(0x17, b"270101000000Z"))
    spki = der(0x30, der(0x30, der(0x06, b"\x2a\x86\x48\xce\x3d\x02\x01")
                         + der(0x06, b"\x2a\x86\x48\xce\x3d\x03\x01\x07"))
               + der(0x03, b"\x00\x04" + bytes(64)))
    tbs = der(0x30, der(0xA0, der(0x02, b"\x02")) + der(0x02, b"\x01\x23\x45") + alg
              + name(issuer) + validity + name(subject) + spki)
    return der(0x30, tbs + alg + der(0x03, b"\x00" + der(0x30, der(0x02, b"\x01") + der(0x02, b"\x01"))))


def tls_certificate_msg(cert):
    entry = struct.pack("!I", len(cert))[1:] + cert
    body = struct.pack("!I", len(entry))[1:] + entry
    hs = b"\x0b" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


# ---- capture files ---------------------------------------------------------

def frames():
    t = []
    t.append(eth(ipv4(A, B, 17, udp(53000, 53, dns_query()))))
    t.append(eth(ipv4(B, A, 17, udp(53, 53000, dns_response()))))
    t.append(eth(ipv4(A, B, 6, tcp(50000, 80, 1, 0, 0x02))))
    t.append(eth(ipv4(B, A, 6, tcp(80, 50000, 100, 2, 0x12))))
    t.append(eth(ipv4(A, B, 6, tcp(50000, 80, 2, 101, 0x18, HTTP_REQ))))
    t.append(eth(ipv4(B, A, 6, tcp(80, 50000, 101, 2 + len(HTTP_REQ), 0x18, HTTP_RESP))))
    t.append(eth(ipv4(A, B, 6, tcp(50001, 443, 1, 0, 0x18, client_hello()))))
    t.append(eth(ipv4(B, A, 6, tcp(443, 50001, 1, 1, 0x18, server_hello()))))
    return t


# ---- 802.11 (synthetic addresses only) --------------------------------------

AP = bytes([0x02, 0x00, 0x5e, 0x00, 0x00, 0x01])
STA = bytes([0x02, 0x00, 0x5e, 0x00, 0x00, 0x02])
GW = bytes([0x02, 0x00, 0x5e, 0x00, 0x00, 0x03])
BCAST = b"\xff" * 6


def radiotap(flags=0x10, freq=2437, signal=-50, tsft=True):
    """TSFT + Flags + Rate + Channel + dBm signal (present 0x2f), or without
    TSFT (0x2e) so Channel needs a pad byte."""
    if tsft:
        body = struct.pack("<QBBHHb", 123456, flags, 2, freq, 0x00A0, signal)
        return struct.pack("<BBHI", 0, 0, 8 + len(body), 0x2F) + body
    body = struct.pack("<BBHHb", flags, 2, freq, 0x00A0, signal)
    return struct.pack("<BBHI", 0, 0, 8 + len(body), 0x2E) + body


def dot11(fc0, fc1, a1, a2, a3, seq=1, a4=None, qos=None):
    h = bytes([fc0, fc1]) + b"\0\0" + a1 + a2 + a3 + struct.pack("<H", seq << 4)
    if a4 is not None:
        h += a4
    if qos is not None:
        h += struct.pack("<H", qos)
    return h


def tag(i, data):
    return bytes([i, len(data)]) + data


def rsn(akms):
    r = b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04" + struct.pack("<H", len(akms))
    for a in akms:
        r += b"\x00\x0f\xac" + bytes([a])
    return tag(48, r + b"\x00\x00")


def beacon(ssid=b"SeedNet", akms=(2,)):
    body = struct.pack("<QHH", 0, 100, 0x0431) + tag(0, ssid) + tag(1, b"\x82\x84\x8b\x96")
    body += tag(3, b"\x06") + tag(5, b"\x00\x01\x00\x00") + (rsn(list(akms)) if akms else b"")
    return dot11(0x80, 0, BCAST, AP, AP) + body


def wifi_frames():
    """(name, 802.11 frame) pairs."""
    llc = lambda et: b"\xaa\xaa\x03\x00\x00\x00" + struct.pack("!H", et)
    dns = ipv4(A, B, 17, udp(53000, 53, dns_query()))
    eapol = b"\x02\x03\x00\x5f\x02\x00\x8a\x00\x10" + bytes(8 + 32 + 16 + 8 + 8 + 16) + b"\x00\x00"
    ccmp = b"\x01\x00\x00\x20\x00\x00\x00\x00" + bytes(40) + bytes(8)
    return [
        ("beacon-wpa2", beacon()),
        ("beacon-wpa3", beacon(b"SeedSAE", (8,))),
        ("beacon-open-hidden", beacon(b"\0\0\0\0", ())),
        ("probe-req", dot11(0x40, 0, BCAST, STA, BCAST) + tag(0, b"SeedNet") + tag(1, b"\x82\x84")),
        ("deauth", dot11(0xC0, 0, STA, AP, AP) + b"\x07\x00"),
        ("auth", dot11(0xB0, 0, AP, STA, AP) + b"\x00\x00\x01\x00\x00\x00"),
        ("qos-data-dns", dot11(0x88, 0x01, AP, STA, GW, qos=0) + llc(0x0800) + dns),
        ("eapol-m1", dot11(0x88, 0x02, STA, AP, AP, qos=7) + llc(0x888E) + eapol),
        ("protected-data", dot11(0x88, 0x41, AP, STA, GW, qos=0) + ccmp),
        ("wds-data", dot11(0x08, 0x03, AP, GW, BCAST, a4=STA) + llc(0x0800) + dns),
        ("ack", b"\xd4\x00\x00\x00" + STA),
        ("awdl-data", dot11(0x08, 0, BCAST, STA, AP) + b"\xaa\xaa\x03\x00\x17\xf2\x08\x00"
            + b"\x03\x04\x05\x00\x00\x00\x08\x00" + dns),
    ]


def fcs(frame):
    import zlib
    return struct.pack("<I", zlib.crc32(frame) & 0xFFFFFFFF)


def pcap(pkts, linktype=1, nano=False):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack("<IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for i, p in enumerate(pkts):
        out += struct.pack("<IIII", 1767225600 + i, 1000 * i, len(p), len(p)) + p
    return out


def pcapng(pkts):
    def block(btype, body):
        pad = (4 - len(body) % 4) % 4
        body += b"\0" * pad
        n = 12 + len(body)
        return struct.pack("<II", btype, n) + body + struct.pack("<I", n)

    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", 1, 0, 65535))
    out = shb + idb
    for i, p in enumerate(pkts):
        ts = (1767225600 + i) * 1_000_000
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(p), len(p)) + p)
    return out


def main():
    fr = frames()

    # ingest_read_capture
    put("ingest_read_capture", "small.pcap.bin", pcap(fr))
    put("ingest_read_capture", "small-nanosecond.pcap.bin", pcap(fr[:3], nano=True))
    put("ingest_read_capture", "small.pcapng.bin", pcapng(fr))
    raw = [p[14:] for p in fr[:2]]
    put("ingest_read_capture", "raw-ip.pcap.bin", pcap(raw, linktype=101))
    put("ingest_read_capture", "header-only.pcap.bin", pcap([]))
    big = bytearray(pcap(fr[:1]))
    struct.pack_into("<I", big, 24 + 8, 0xFFFFFFFF)  # caplen far past the end
    put("ingest_read_capture", "caplen-overflow.pcap.bin", bytes(big))
    put("ingest_read_capture", "truncated.pcapng.bin", pcapng(fr)[:-7])

    # ingest_decode_frame: 4-byte little-endian link type, then the frame.
    # Seeds pick selector 0 (Ethernet) and 1 (raw IP); see the target.
    for i, p in enumerate(fr):
        put("ingest_decode_frame", f"eth-{i}.bin", struct.pack("<I", 0) + p)
    put("ingest_decode_frame", "rawip-dns.bin", struct.pack("<I", 1) + fr[0][14:])
    v6 = (struct.pack("!IHBB", 0x60000000, 8 + len(dns_query()), 17, 64)
          + bytes(15) + b"\x01" + bytes(15) + b"\x02" + udp(5353, 53, dns_query()))
    put("ingest_decode_frame", "eth-ipv6.bin", struct.pack("<I", 0) + eth(v6, 0x86DD))
    vlan = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x81\x00\x00\x64\x08\x00" + fr[0][14:]
    put("ingest_decode_frame", "eth-vlan.bin", struct.pack("<I", 0) + vlan)
    # 802.11: selector 8 = link type 105 (bare 802.11), 9 = 127 (radiotap).
    wf = wifi_frames()
    for nm, f in wf:
        put("ingest_decode_frame", f"radiotap-{nm}.bin", struct.pack("<I", 9) + radiotap() + f + fcs(f))
    put("ingest_decode_frame", "dot11-qos-data-dns.bin", struct.pack("<I", 8) + wf[6][1])
    put("ingest_decode_frame", "radiotap-nofcs-pad.bin",
        struct.pack("<I", 9) + radiotap(flags=0, tsft=False) + wf[0][1])
    put("ingest_decode_frame", "radiotap-badfcs.bin",
        struct.pack("<I", 9) + radiotap(flags=0x50) + wf[4][1] + b"\0\0\0\0")
    # Extended present bitmap (two words) before the fields.
    ext = struct.pack("<BBHII", 0, 0, 12 + 9, 0x8000002E, 0x00000020) + struct.pack("<BBHHbb", 0x10, 2, 2412, 0xA0, -60, -61)
    ext = ext[:2] + struct.pack("<H", len(ext)) + ext[4:]
    put("ingest_decode_frame", "radiotap-ext-present.bin", struct.pack("<I", 9) + ext + wf[3][1] + fcs(wf[3][1]))
    put("ingest_read_capture", "radiotap.pcap.bin",
        pcap([radiotap() + f + fcs(f) for _, f in wf], linktype=127))

    # ingest_dns: first byte bit 0 = TCP framing.
    for nm, m in [("query", dns_query()), ("response", dns_response()), ("nxdomain", dns_nxdomain()),
                  ("txt", dns_txt_response()), ("pointer-loop", dns_pointer_loop()),
                  ("aaaa-query", dns_query("ipv6.example.com", 28))]:
        put("ingest_dns", f"udp-{nm}.bin", b"\x00" + m)
    put("ingest_dns", "tcp-response.bin", b"\x01" + struct.pack("!H", len(dns_response())) + dns_response())

    # ingest_http
    put("ingest_http", "get.bin", HTTP_REQ)
    put("ingest_http", "response.bin", HTTP_RESP)
    put("ingest_http", "post-chunked.bin", HTTP_POST)
    put("ingest_http", "pipelined.bin", HTTP_REQ + HTTP_REQ)

    # TLS
    put("ingest_tls_client_hello", "client-hello.bin", client_hello())
    put("ingest_tls_client_hello", "client-hello-no-sni.bin", client_hello(""))
    put("ingest_tls_server_hello", "server-hello.bin", server_hello())
    put("ingest_tls_server_hello", "server-hello-then-cert.bin", server_hello() + tls_certificate_msg(certificate()))
    put("ingest_certificate", "self-signed.der.bin", certificate())
    put("ingest_certificate", "issued.der.bin", certificate("host.example", "Seed CA"))

    # index_filter: filter-language text
    filters = [
        'host 10.0.0.5 and dns.query ~ "*.top" and bytes_up > 1MB and not app_proto == tls',
        "src 10.0.0.0/8 or dst 2001:db8::/32",
        "port 443 and tls.sni ~ \"*.example\"",
        "(dns or http) and !(tcp)",
        'http.user_agent ~ "curl*" and http.status >= 400',
        "duration > 10m and bytes < 1KB",
        'dns.answers ~ "192.0.2.*"',
        "src_port in [53, 80, 443]",
        'dns.query == "a\\"b\\\\c"',
        "frame.tcp_flags == 2",
        "",
    ]
    for i, f in enumerate(filters):
        put("index_filter", f"f{i:02}.txt", f)
        put("core_mock_filter", f"f{i:02}.txt", f)
    put("core_mock_filter", "unclosed.txt", "(host 10.0.0.5")
    put("core_mock_filter", "unterminated.txt", 'dns.query ~ "abc')

    # core_allowlist_yaml / core_rule_yaml / core_render_template
    put("core_allowlist_yaml", "basic.yaml",
        "version: 1\ndomains:\n  - { suffix: windowsupdate.com, reason: MS }\n"
        "cidrs:\n  - { cidr: 17.0.0.0/8, reason: Apple }\n  - { cidr: '2606:4700::/32', reason: CF }\n"
        "ja4:\n  - { value: t13d1516h2_8daaf6152771_02713d6af862, reason: Chrome }\n")
    put("core_allowlist_yaml", "aliases.yaml",
        "domains:\n  - &d { suffix: a.example, reason: x }\n  - *d\n  - *d\n")
    put("core_rule_yaml", "beacon.yaml",
        "id: beacon.periodic\ntitle: Periodic outbound connections\ndetector: beaconing\n"
        "enabled: true\nattack_technique: T1071\nparams:\n  min_count: 8\n  max_jitter: 0.2\n"
        "  min_duration_s: 600\n  ports: [80, 443]\nweights:\n  regularity: 50\n  count: 20\n"
        "min_score: 30\nexplanation: \"{src} contacted {dst} {count} times, every {interval_s}s\"\n")
    put("core_rule_yaml", "dns.yaml",
        "id: dns.entropy\ntitle: High-entropy DNS labels\ndetector: dns_entropy\n"
        "attack_technique: T1071.004\nparams: { min_entropy: 3.5, name: \"x\" }\n"
        "weights: { entropy: 60 }\nexplanation: \"{src} queried {count} names under {parent}\"\n")
    put("core_rule_yaml", "anchors.yaml",
        "id: a\ntitle: t\ndetector: d\nexplanation: e\nparams:\n  a: &x [1, 2, 3]\n  b: *x\n")
    put("core_render_template", "basic.bin",
        "{src} contacted {dst} {count} times {} {\0src\x0110.0.0.5\0dst\x01cdn-update[.]top\0count\x0142")
    put("core_render_template", "nested.bin", "{{src}} {src{dst}} }{\0src\x01{dst}\0dst\x01x")

    # core_allowlist_match: op byte + string
    for i, s in enumerate(["download.windowsupdate.com", "notwindowsupdate.com", "EXAMPLE.COM.", ""]):
        put("core_allowlist_match", f"domain{i}.bin", b"\x00" + s.encode())
    for i, s in enumerate(["17.1.2.3", "2606:4700::1", "::ffff:17.0.0.1"]):
        put("core_allowlist_match", f"ip{i}.bin", b"\x01" + s.encode())
    put("core_allowlist_match", "ja4.bin", b"\x02T13D1516H2_8DAAF6152771_02713D6AF862")
    for i, s in enumerate(["10.0.0.0/8", "0.0.0.0/0", "::/0", "2001:db8::1/128", "1.2.3.4/33"]):
        put("core_allowlist_match", f"cidr{i}.bin", b"\x03" + s.encode())

    # core_ipc_json: selector byte + JSON (selectors match the target)
    ipc = {
        0: {"filter": "host 10.0.0.5", "view": "flows", "time_range": {"start": 0, "end": 10},
            "hosts": ["10.0.0.5"], "flow_ids": [1, 2], "sort": {"column": "ts_start", "desc": True},
            "limit": 100, "cursor": "abc"},
        1: {"filter": "", "time_range": None, "bucket_ms": 60000, "max_lanes": 8},
        2: {"min_score": 30.5, "detector": "beaconing", "entity": "10.0.0.23",
            "time_range": {"start": 1, "end": 2}},
        3: {"kind": "query", "filter": "dns", "view": "dns", "time_range": None},
        4: {"name": "n", "filter": "dns", "view": "dns"},
        5: {"column": "bytes_up", "desc": False},
        6: {"start": -9223372036854775808, "end": 9223372036854775807},
        7: "frames", 8: "needs_review", 9: "csv", 10: "markdown",
        11: {"case_id": "0123456789abcdef", "evidence": {"kind": "frame", "frame_no": 7}, "note": "x"},
    }
    for sel, v in ipc.items():
        put("core_ipc_json", f"t{sel:02}.bin", bytes([sel]) + json.dumps(v).encode())

    # core_mock_backend: selector byte + Tauri-style args JSON.
    case = "CASE"  # replaced below with the mock capture id
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "..", "crates", "walleye-core", "mock", "dataset.json")) as f:
            ds = json.load(f)
        case = ds["capture"]["capture_id"]
        fid = ds["findings"][0]["finding_id"]
        t0, t1 = ds["capture"]["first_ts"], ds["capture"]["last_ts"]
    except (OSError, KeyError, IndexError, ValueError):
        fid, t0, t1 = "0" * 16, 0, 1
    q = {"filter": "host 10.0.0.23", "view": "flows", "limit": 50,
         "sort": {"column": "bytes_down", "desc": True}}
    mock = {
        0: {"path": "/mock/a.pcap"}, 1: {"job_id": "job-1"}, 2: {"job_id": "job-1"}, 3: {},
        4: {"req": q},
        5: {"req": {"filter": "", "time_range": {"start": t0, "end": t1}, "bucket_ms": 60000, "max_lanes": 5}},
        6: {"flow_id": 1}, 7: {"frame_no": 1},
        8: {"partial_filter": "host 10.0.0.2", "cursor_pos": 13}, 9: {},
        10: {"query": {"name": "x", "filter": "dns", "view": "dns"}}, 11: {"name": "x"},
        12: {"filter": {"min_score": 10}},
        13: {"finding_id": fid, "verdict": "benign", "note": ""},
        14: {"case_id": case}, 15: {"case_id": case},
        16: {"case_id": case, "evidence": {"kind": "finding", "finding_id": fid}, "note": "n"},
        17: {"case_id": case, "pin_id": "pin-1"},
    }
    for sel, v in mock.items():
        put("core_mock_backend", f"c{sel:02}.bin", bytes([sel]) + json.dumps(v).encode())
    # Known-crash reproducers from the review (kept out of seeds/ so the smoke
    # run keeps exploring). Replay: cargo fuzz run core_mock_backend <file>.
    q2 = dict(q, cursor="18446744073709551615")
    put("../repro/core_mock_backend", "query-cursor-overflow.bin", bytes([4]) + json.dumps({"req": q2}).encode())
    put("../repro/core_mock_backend", "timeline-range-overflow.bin", bytes([5]) + json.dumps(
        {"req": {"filter": "", "time_range": {"start": -2**63, "end": 2**63 - 1},
                 "bucket_ms": 1, "max_lanes": 1}}).encode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
