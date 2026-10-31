#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashSet, path::PathBuf};

use walleye_case::load_allowlist;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/allowlist.yaml")
}

#[test]
fn default_allowlist_loads_and_matches_update_hosts() {
    let a = load_allowlist(&path()).unwrap();
    for (name, reason) in [
        ("fe2.update.microsoft.com", "Microsoft Update"),
        ("ctldl.windowsupdate.com", "Microsoft Update"),
        (
            "tlu.dl.delivery.mp.microsoft.com",
            "Microsoft Update delivery",
        ),
        ("swcdn.apple.com", "Apple software update"),
        ("us.archive.ubuntu.com", "Ubuntu archive mirror"),
        ("deb.debian.org", "Debian mirror"),
        ("update.googleapis.com", "Google software update"),
        ("0.pool.ntp.org", "NTP pool"),
        (
            "v10.events.data.microsoft.com",
            "Windows telemetry (Connected User Experiences)",
        ),
        (
            "courier.push.apple.com",
            "Apple Push Notification service (periodic keepalive)",
        ),
        ("xp.apple.com", "Apple analytics/telemetry"),
        ("motd.ubuntu.com", "Ubuntu message-of-the-day check"),
        ("daisy.ubuntu.com", "Ubuntu crash reporting"),
    ] {
        assert_eq!(a.domain(name), Some(reason), "{name}");
    }
    assert_eq!(a.ip("13.107.4.50"), Some("Microsoft"));
    assert_eq!(a.ip("17.253.144.10"), Some("Apple"));
    assert_eq!(a.ip("8.8.8.8"), Some("Google Public DNS"));
}

#[test]
fn default_allowlist_is_conservative() {
    let a = load_allowlist(&path()).unwrap();
    // look-alikes and attacker-controllable names never match
    for name in [
        "evilwindowsupdate.com",
        "windowsupdate.com.evil.top",
        "update-microsoft.com",
        "microsoft.com",
        "apple.com",
        "google.com",
        "ubuntu.com",
        "evil.azurewebsites.net",
        "evil.blob.core.windows.net",
        "evil.herokuapp.com",
        "evil.appspot.com",
        "cdn-update.top",
        "data.microsoft.com",
        "evil-push.apple.com.example",
    ] {
        assert_eq!(a.domain(name), None, "{name}");
    }
    // no bare TLDs or whole vendor apexes
    let forbidden: HashSet<&str> = [
        "com",
        "net",
        "org",
        "io",
        "microsoft.com",
        "apple.com",
        "google.com",
        "googleapis.com",
        "amazonaws.com",
        "windows.net",
        "azureedge.net",
        "github.io",
    ]
    .into();
    let mut seen = HashSet::new();
    for d in &a.domains {
        assert!(d.suffix.contains('.'), "{}", d.suffix);
        assert!(!forbidden.contains(d.suffix.as_str()), "{}", d.suffix);
        assert!(!d.reason.trim().is_empty());
        assert!(seen.insert(d.suffix.clone()), "duplicate {}", d.suffix);
    }
    // only one wide block (Apple's own /8); the rest are host routes
    for c in &a.cidrs {
        let (_, len) = walleye_core::allowlist::parse_cidr(&c.cidr).unwrap();
        let host = if c.cidr.contains(':') { 128 } else { 32 };
        assert!(len == host || c.cidr == "17.0.0.0/8", "{}", c.cidr);
    }
    assert!(a.ja4.is_empty());
}

#[test]
fn rejects_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.yaml");
    std::fs::write(&p, "domains:\n  - { suffix: x.com, reason: r, extra: 1 }\n").unwrap();
    assert!(load_allowlist(&p).is_err());
    std::fs::write(&p, "cidrs:\n  - { cidr: 1.2.3.4/40, reason: r }\n").unwrap();
    assert!(load_allowlist(&p).is_err());
    assert!(load_allowlist(&dir.path().join("missing.yaml")).is_err());
}
