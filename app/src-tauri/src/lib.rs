//! Tauri shell. Keep this layer thin and conventional:
//! * one `#[tauri::command]` per `Backend` method (commands.rs),
//! * all logic lives in the `walleye-*` crates,
//! * the backend is chosen once at startup (`WALLEYE_BACKEND`, default `mock`
//!   until integration lands).

mod commands;

use std::sync::Arc;

use walleye_core::{Backend, mock::MockBackend};

/// Shared state handed to every command via `tauri::State`.
pub struct AppState {
    pub backend: Arc<dyn Backend>,
}

fn make_backend() -> Arc<dyn Backend> {
    match std::env::var("WALLEYE_BACKEND").as_deref() {
        Ok("mock-open") => Arc::new(MockBackend::preopened()),
        // "real" is wired by the lead in Phase 2.
        _ => Arc::new(MockBackend::new()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(clippy::expect_used)]
    tauri::Builder::default()
        // Native "Open file" dialog for choosing a capture (official plugin).
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            backend: make_backend(),
        })
        .invoke_handler(commands::handler())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
