//! The five golden capture fixtures, built in code.

use super::*;

pub const T0: i64 = 1_700_000_000_000_000;

pub fn dns_fixture() -> Vec<u8> {
    let c = [10, 0, 0, 5];
    let s = [10, 0, 0, 53];
    let mut p = Pcap::new(1);
    p.packet(
        T0,
        &eth_udp4(c, 51000, s, 53, &dns_query(0x1111, "WWW.Example.com", 1)),
    );
    let cname = vec![3, b'c', b'd', b'n', 0xc0, 0x10]; // cdn + ptr to "example.com"
    let resp = dns_response(
        0x1111,
        "www.example.com",
        1,
        0,
        &[(5, 300, cname), (1, 60, vec![93, 184, 216, 34])],
    );
    p.packet(T0 + 20_000, &eth_udp4(s, 53, c, 51000, &resp));
    p.packet(
        T0 + 1_000_000,
        &eth_udp4(
            c,
            51001,
            s,
            53,
            &dns_query(0x2222, "x7f3.t.exfil-dns.xyz", 16),
        ),
    );
    let nx = dns_response(0x2222, "x7f3.t.exfil-dns.xyz", 16, 3, &[]);
    p.packet(T0 + 1_030_000, &eth_udp4(s, 53, c, 51001, &nx));

    // DNS over TCP: query split over two segments, response in one.
    let mut t = Tcp::new((c, 40000), (s, 53), T0 + 2_000_000);
    t.handshake();
    let q = with_len_prefix(&dns_query(0x3333, "example.net", 16));
    t.client(&q[..5]);
    t.client(&q[5..]);
    let txt = dns_response(
        0x3333,
        "example.net",
        16,
        0,
        &[(16, 30, b"\x05hello\x05world".to_vec())],
    );
    t.server(&with_len_prefix(&txt));
    t.close();
    p.add(&t.frames);

    // IPv6 AAAA.
    let c6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    let s6: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
    ];
    let q6 = udp(51002, 53, &dns_query(0x4444, "v6.example.com", 28));
    p.packet(T0 + 3_000_000, &eth(0x86dd, &ipv6(c6, s6, 17, &q6)));
    let mut a6 = vec![0x20, 0x01, 0x0d, 0xb8];
    a6.extend_from_slice(&[0; 11]);
    a6.push(1);
    let r6 = udp(
        53,
        51002,
        &dns_response(0x4444, "v6.example.com", 28, 0, &[(28, 120, a6)]),
    );
    p.packet(T0 + 3_010_000, &eth(0x86dd, &ipv6(s6, c6, 17, &r6)));
    p.buf
}

pub fn http_fixture() -> Vec<u8> {
    let mut t = Tcp::new(([10, 0, 0, 5], 50000), ([93, 184, 216, 34], 80), T0);
    t.handshake();
    t.client(b"GET /files/report.pdf HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Walleye-Test/1.0\r\n\r\n");
    let mut first =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: 3000\r\n\r\n"
            .to_vec();
    first.extend_from_slice(&[b'%'; 1000]);
    t.server(&first);
    t.server(&[b'x'; 1000]);
    t.server(&[b'y'; 1000]);
    let post = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\nhello=world";
    t.client(post);
    t.client_retransmit(post);
    t.server(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    t.client(b"GET /dl?id=7 HTTP/1.1\r\nHost: example.com\r\n\r\n");
    t.server(b"HTTP/1.1 200 OK\r\nContent-Disposition: attachment; filename=\"payload.bin\"\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\nMZ\x90\x00");
    t.close();
    let mut p = Pcap::new(1);
    p.add(&t.frames);
    p.buf
}

pub fn tls_fixture() -> Vec<u8> {
    let mut ng = Pcapng::new();
    ng.idb(1, None);
    let mut frames = Vec::new();

    // TLS 1.2 with a self-signed certificate; ClientHello split in two.
    let mut a = Tcp::new(([10, 0, 0, 5], 51515), ([198, 51, 100, 7], 443), T0);
    a.handshake();
    let ch = tls_record(
        22,
        &client_hello(&HelloSpec {
            sni: Some("WWW.Example.ORG"),
            alpn: &["h2", "http/1.1"],
            ciphers: &[0x1a1a, 0xc02b, 0xc02f, 0x009c],
            versions: &[],
            sig_algs: &[0x0403, 0x0804],
            other_exts: &[0x0017, 0xff01, 0x000a, 0x000b, 0x0023],
        }),
    );
    a.client(&ch[..40]);
    a.client(&ch[40..]);
    let name = [
        (OID_C, "US"),
        (OID_O, "Walleye Test"),
        (OID_CN, "www.example.org"),
    ];
    let cert = der_cert(
        &name,
        &name,
        &[0x00, 0x9a, 0x3b, 0x01],
        "240101000000Z",
        "340101000000Z",
    );
    let mut flight = tls_record(
        22,
        &server_hello(0xc02f, false, &[0xff01, 0x000b, 0x0023, 0x0010]),
    );
    flight.extend(tls_record(22, &certificate_msg(&cert)));
    flight.extend(tls_record(22, &handshake(14, &[])));
    a.server(&flight);
    a.client(&tls_record(20, &[1]));
    a.server(&tls_record(20, &[1]));
    a.close();
    frames.extend(a.frames);

    // TLS 1.3 (certificate encrypted).
    let mut b = Tcp::new(
        ([10, 0, 0, 5], 51516),
        ([203, 0, 113, 9], 443),
        T0 + 1_000_000,
    );
    b.handshake();
    b.client(&tls_record(
        22,
        &client_hello(&HelloSpec {
            sni: Some("api.example.com"),
            alpn: &["h2"],
            ciphers: &[0x1301, 0x1302, 0x1303],
            versions: &[0x7a7a, 0x0304, 0x0303],
            sig_algs: &[0x0403],
            other_exts: &[0x0033, 0x002d],
        }),
    ));
    let mut sflight = tls_record(22, &server_hello(0x1301, true, &[0x002b, 0x0033]));
    sflight.extend(tls_record(20, &[1]));
    sflight.extend(tls_record(23, &[0xaa; 64]));
    b.server(&sflight);
    b.client(&tls_record(23, &[0xbb; 32]));
    b.close();
    frames.extend(b.frames);

    // ClientHello with no answer (no SNI, no ALPN).
    let mut c = Tcp::new(
        ([10, 0, 0, 6], 40001),
        ([192, 0, 2, 1], 8443),
        T0 + 2_000_000,
    );
    c.handshake();
    c.client(&tls_record(
        22,
        &client_hello(&HelloSpec {
            sni: None,
            alpn: &[],
            ciphers: &[0x002f],
            versions: &[],
            sig_algs: &[],
            other_exts: &[],
        }),
    ));
    frames.extend(c.frames);

    for (ts, f) in &frames {
        ng.epb(0, u64::try_from(*ts).expect("ts"), f);
    }
    ng.buf
}

pub fn malformed_fixture() -> Vec<u8> {
    let c = [10, 9, 0, 1];
    let s = [10, 9, 0, 2];
    let mut p = Pcap::new(1);
    let mut ts = T0;
    let mut add = |p: &mut Pcap, data: &[u8]| {
        p.packet(ts, data);
        ts += 1000;
    };
    add(
        &mut p,
        &eth(
            0x0806,
            &[
                0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 0xa, 10, 9, 0, 1, 0, 0, 0, 0, 0, 0, 10, 9,
                0, 2,
            ],
        ),
    ); // ARP
    add(&mut p, &[1, 2, 3, 4, 5]); // shorter than Ethernet
    let mut bad_ihl = ipv4(c, s, 17, &udp(1, 2, b"x"));
    bad_ihl[0] = 0x43;
    add(&mut p, &eth(0x0800, &bad_ihl));
    add(&mut p, &eth(0x0800, &ipv4(c, s, 6, &[0u8; 10]))); // TCP header cut
    let mut looped = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    looped.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]); // compression loop
    add(&mut p, &eth_udp4(c, 5353, s, 53, &looped));
    add(&mut p, &eth_udp4(c, 5354, s, 53, &[1, 2, 3])); // too short for DNS
    // TLS record claiming 65535 bytes.
    add(
        &mut p,
        &eth(
            0x0800,
            &ipv4(
                c,
                s,
                6,
                &tcp(4000, 443, 1, 0, PSH | ACK, &[22, 3, 1, 0xff, 0xff, 1, 0, 0]),
            ),
        ),
    );
    // HTTP head that never ends, then FIN.
    add(
        &mut p,
        &eth(
            0x0800,
            &ipv4(
                c,
                s,
                6,
                &tcp(4001, 80, 1, 0, PSH | ACK, b"GET \xff\xff\r\nHost: \x00"),
            ),
        ),
    );
    add(
        &mut p,
        &eth(
            0x0800,
            &ipv4(c, s, 6, &tcp(4001, 80, 20, 0, FIN | ACK, &[])),
        ),
    );
    add(
        &mut p,
        &eth(0x0800, &ipv4(c, s, 1, &[8, 0, 0xf7, 0xff, 0, 1, 0, 1])),
    ); // ICMP echo
    let mut frag = ipv4(c, s, 17, &udp(7, 9, &[0u8; 32]));
    frag[6] = 0x20; // MF
    add(&mut p, &eth(0x0800, &frag));
    // DNS response cut by the snap length inside its answer.
    let r = dns_response(9, "cut.example", 1, 0, &[(1, 5, vec![1, 2, 3, 4])]);
    let full = eth_udp4(s, 53, c, 6000, &r);
    p.packet_snap(ts, &full, full.len() - 6);
    // Final record header claims 100 bytes; file ends after 10.
    p.record(1_700_000_100, 0, &[0u8; 10], 100);
    let n = p.buf.len();
    p.buf[n - 18..n - 14].copy_from_slice(&100u32.to_le_bytes());
    p.buf
}

pub fn multi_fixture() -> Vec<u8> {
    let mut ng = Pcapng::new();
    ng.idb(1, None); // if 0: Ethernet, µs
    ng.idb(101, Some(9)); // if 1: raw IP, ns
    let t0 = u64::try_from(T0).expect("ts");
    ng.epb(
        0,
        t0,
        &eth_udp4([10, 1, 0, 1], 5000, [10, 1, 0, 2], 6000, b"a"),
    );
    // SPB: interface 0, inherits the previous timestamp.
    ng.spb(&eth_udp4([10, 1, 0, 2], 6000, [10, 1, 0, 1], 5000, b"cc"));
    let rawpkt = |p: &[u8]| ipv4([10, 2, 0, 1], [10, 2, 0, 2], 17, &udp(7000, 8000, p));
    ng.epb(1, t0 * 1000 + 500_123, &rawpkt(b"b"));
    ng.nrb();
    ng.epb(1, (t0 + 120_000_000) * 1000, &rawpkt(b"bb")); // after the 60 s UDP timeout
    ng.epb(7, t0, &eth_udp4([10, 1, 0, 1], 1, [10, 1, 0, 2], 2, b"?")); // undefined interface
    ng.section(true); // big-endian section, interfaces reset
    ng.idb(1, Some(3)); // ms
    ng.epb(
        0,
        (t0 + 200_000_000) / 1000,
        &eth_udp4([10, 3, 0, 1], 9, [10, 3, 0, 2], 9, b"be"),
    );
    ng.buf
}
