//! Tauri shell. Keep this layer thin and conventional:
//! * one `#[tauri::command]` per `Backend` method (commands.rs),
//! * all logic lives in the `walleye-*` crates (`walleye-engine` wires them),
//! * the backend is chosen once at startup.
//!
//! `WALLEYE_BACKEND=mock` / `mock-open` selects the mock backend (UI work);
//! anything else (default) is the real engine. `WALLEYE_DATA` overrides the
//! data dir, `WALLEYE_RULES` the rules dir.

mod commands;

use std::{path::PathBuf, sync::Arc};

use tauri::Manager;
use walleye_core::{Backend, mock::MockBackend};
use walleye_engine::{Engine, EngineConfig};

/// Shared state handed to every command via `tauri::State`.
pub struct AppState {
    pub backend: Arc<dyn Backend>,
}

/// Rules ship as bundled resources (tauri.conf.json `bundle.resources`); in
/// `tauri dev` the repo's `rules/` is used directly.
fn rules_dir(app: &tauri::App) -> PathBuf {
    if let Some(p) = std::env::var_os("WALLEYE_RULES") {
        return PathBuf::from(p);
    }
    if let Ok(res) = app.path().resource_dir() {
        let p = res.join("rules");
        if p.join("allowlist.yaml").is_file() {
            return p;
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

fn make_backend(app: &tauri::App) -> Result<Arc<dyn Backend>, Box<dyn std::error::Error>> {
    match std::env::var("WALLEYE_BACKEND").as_deref() {
        Ok("mock") => return Ok(Arc::new(MockBackend::new())),
        Ok("mock-open") => return Ok(Arc::new(MockBackend::preopened())),
        _ => {}
    }
    let data_dir = match std::env::var_os("WALLEYE_DATA") {
        Some(p) => PathBuf::from(p),
        None => app.path().app_data_dir()?,
    };
    let engine = Engine::new(EngineConfig::new(data_dir, rules_dir(app)))?;
    Ok(Arc::new(engine))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(clippy::expect_used)]
    tauri::Builder::default()
        // Native "Open file" dialog for choosing a capture (official plugin).
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // `setup` runs once before any window loads, so commands always
            // find AppState.
            let backend = make_backend(app)?;
            app.manage(AppState { backend });
            Ok(())
        })
        .invoke_handler(commands::handler())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
