mod clipboard;
mod sidecar;
mod window;

use clipboard::ClipboardWatcher;
use parking_lot::Mutex;
use sidecar::PresidioSidecar;
use std::sync::Arc;
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, RunEvent, State,
};

/// Application state shared across the Tauri app
pub struct AppState {
    clipboard_watcher: Mutex<Option<ClipboardWatcher>>,
    sidecar: Arc<Mutex<PresidioSidecar>>,
    last_clipboard_hash: Mutex<u64>,
    clipboard_handled: Mutex<bool>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            clipboard_watcher: Mutex::new(None),
            sidecar: Arc::new(Mutex::new(PresidioSidecar::new())),
            last_clipboard_hash: Mutex::new(0),
            clipboard_handled: Mutex::new(false),
        }
    }
}

/// Start clipboard monitoring
#[tauri::command]
async fn start_monitoring(app_handle: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    log::info!("Starting clipboard monitoring...");

    // Start the sidecar process
    {
        let mut sidecar = state.sidecar.lock();
        sidecar.start(&app_handle).await.map_err(|e| e.to_string())?;
    }

    // Start clipboard watcher in a background task
    let sidecar = state.sidecar.clone();
    let app_handle_clone = app_handle.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));

        loop {
            interval.tick().await;

            // Get current clipboard content
            if let Some(text) = clipboard::get_clipboard_text() {
                let hash = clipboard::hash_text(&text);

                // Check if we should process this clipboard content
                let should_process = {
                    let state = app_handle_clone.state::<AppState>();
                    let mut last_hash = state.last_clipboard_hash.lock();
                    let mut handled = state.clipboard_handled.lock();

                    if hash != *last_hash {
                        *last_hash = hash;
                        *handled = false;
                        true
                    } else if *handled {
                        false
                    } else {
                        false // Already saw this, waiting for user action
                    }
                };

                if should_process && !text.trim().is_empty() {
                    log::debug!("New clipboard content detected, analyzing...");

                    // Analyze with Presidio
                    let result = {
                        let sidecar = sidecar.lock();
                        sidecar.analyze(&text).await
                    };

                    match result {
                        Ok(analysis) => {
                            if !analysis.entities.is_empty() {
                                log::info!(
                                    "Detected {} PII entities",
                                    analysis.entities.len()
                                );

                                // Emit event to frontend
                                let _ = app_handle_clone.emit("pii-detected", &analysis);
                            } else {
                                // No PII found, just update stats
                                let _ = app_handle_clone.emit("clipboard-scanned", ());
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to analyze clipboard: {}", e);
                            let _ = app_handle_clone.emit(
                                "sidecar-status",
                                serde_json::json!({
                                    "status": "error",
                                    "message": e.to_string()
                                }),
                            );
                        }
                    }
                }
            }

            // Update active window info periodically
            if let Some(window_info) = window::get_active_window() {
                let _ = app_handle_clone.emit("active-window-changed", &window_info);
            }
        }
    });

    Ok(())
}

/// Mark current clipboard content as handled (user clicked anonymize or ignore)
#[tauri::command]
async fn mark_clipboard_handled(state: State<'_, AppState>) -> Result<(), String> {
    let mut handled = state.clipboard_handled.lock();
    *handled = true;
    Ok(())
}

/// Get sidecar status
#[tauri::command]
async fn get_sidecar_status(state: State<'_, AppState>) -> Result<bool, String> {
    let sidecar = state.sidecar.lock();
    Ok(sidecar.is_running())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .setup(|app| {
            // Build system tray
            let quit = MenuItem::with_id(app, "quit", "Quit PII Shield", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;

            let _tray = TrayIconBuilder::new()
                .icon(Image::from_bytes(include_bytes!("../icons/icon.png")).unwrap_or_else(
                    |_| {
                        // Fallback: create a simple colored icon
                        Image::new(&[0x63, 0x66, 0xf1, 0xff], 1, 1)
                    },
                ))
                .menu(&menu)
                .menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            log::info!("PII Shield initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_monitoring,
            mark_clipboard_handled,
            get_sidecar_status,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let RunEvent::ExitRequested { api, .. } = event {
                // Clean up sidecar on exit
                let state = app_handle.state::<AppState>();
                let mut sidecar = state.sidecar.lock();
                sidecar.stop();
            }
        });
}
