//! DEV/TEST ONLY. Serves `walleye_core::backend::dispatch` over HTTP on
//! 127.0.0.1 so Playwright (which cannot drive Tauri's webview on macOS) can
//! run the UI against the real engine. Never part of the app bundle.
//!
//!   walleye-devbridge --data <dir> [--rules <dir>] [--port 7377] [--origin http://localhost:1420]
//!
//! Protection: binds loopback only; every request must carry the random
//! bearer token printed at startup; CORS allows exactly one origin.
//! UI: open `http://localhost:1420/?bridge=http://127.0.0.1:7377&token=<t>`.

use std::{io::Read, path::PathBuf};

use walleye_core::{ApiError, ErrorCode, backend::dispatch};
use walleye_engine::{Engine, EngineConfig};

const MAX_BODY: u64 = 8 * 1024 * 1024;

fn token() -> String {
    // Test harnesses may fix the token (it must be long enough to be a secret).
    if let Ok(t) = std::env::var("WALLEYE_BRIDGE_TOKEN")
        && t.len() >= 32
    {
        return t;
    }
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).unwrap_or_else(|_| std::process::exit(3));
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut data, mut rules, mut port, mut origin) = (
        None,
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules")),
        7377u16,
        "http://localhost:1420".to_string(),
    );
    while let Some(a) = args.next() {
        let v = args.next();
        match (a.as_str(), v) {
            ("--data", Some(v)) => data = Some(PathBuf::from(v)),
            ("--rules", Some(v)) => rules = PathBuf::from(v),
            ("--port", Some(v)) => port = v.parse().unwrap_or(port),
            ("--origin", Some(v)) => origin = v,
            _ => {
                eprintln!(
                    "usage: walleye-devbridge --data <dir> [--rules <dir>] [--port N] [--origin URL]"
                );
                std::process::exit(2);
            }
        }
    }
    let Some(data) = data else {
        eprintln!("--data is required");
        std::process::exit(2);
    };
    let engine = match Engine::new(EngineConfig::new(data, rules)) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("engine: {e}");
            std::process::exit(1);
        }
    };
    let server = match tiny_http::Server::http(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("bind 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    let tok = token();
    // Machine-readable line for test harnesses.
    println!("BRIDGE_READY http://127.0.0.1:{port} token={tok}");

    let hdr = |k: &str, v: &str| tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).ok();
    for mut req in server.incoming_requests() {
        let cors: Vec<tiny_http::Header> = [
            hdr("Access-Control-Allow-Origin", &origin),
            hdr(
                "Access-Control-Allow-Headers",
                "authorization, content-type",
            ),
            hdr("Access-Control-Allow-Methods", "POST"),
            hdr("Vary", "Origin"),
        ]
        .into_iter()
        .flatten()
        .collect();
        let respond = |req: tiny_http::Request, code: u16, body: String| {
            let mut r = tiny_http::Response::from_string(body).with_status_code(code);
            for h in cors.iter().cloned() {
                r.add_header(h);
            }
            if let Some(h) = hdr("Content-Type", "application/json") {
                r.add_header(h);
            }
            let _ = req.respond(r);
        };
        if req.method() == &tiny_http::Method::Options {
            respond(req, 204, String::new());
            continue;
        }
        let authed = req
            .headers()
            .iter()
            .any(|h| h.field.equiv("authorization") && h.value.as_str() == format!("Bearer {tok}"));
        let cmd = req.url().strip_prefix("/invoke/").map(str::to_string);
        let (Some(cmd), true, true) = (cmd, authed, req.method() == &tiny_http::Method::Post)
        else {
            respond(
                req,
                403,
                r#"{"code":"invalid_argument","message":"forbidden"}"#.into(),
            );
            continue;
        };
        let mut body = String::new();
        if req
            .as_reader()
            .take(MAX_BODY)
            .read_to_string(&mut body)
            .is_err()
        {
            respond(
                req,
                400,
                r#"{"code":"invalid_argument","message":"bad body"}"#.into(),
            );
            continue;
        }
        let args = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        match dispatch(&engine, &cmd, args) {
            Ok(v) => respond(req, 200, v.to_string()),
            Err(e) => respond(req, 400, err_json(&e)),
        }
    }
}

fn err_json(e: &ApiError) -> String {
    serde_json::to_string(e).unwrap_or_else(|_| {
        format!(
            r#"{{"code":"{:?}","message":"error"}}"#,
            ErrorCode::Internal
        )
    })
}
