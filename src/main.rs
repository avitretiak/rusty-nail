use rfd::FileDialog;
use rusty_nail::*;
use slint::PlatformError;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

slint::include_modules!();

fn main() -> Result<(), PlatformError> {
    let ui = AppWindow::new()?;
    let ui_handle = ui.as_weak();
    let log = Arc::new(Mutex::new(String::new()));

    let _log_clone = log.clone();
    ui.on_select_dif_file({
        let ui_handle = ui_handle.clone();
        move || {
            if let Some(path) = select_file("Select the DIF File", &["dif"]) {
                if let Some(handle) = ui_handle.upgrade() {
                    handle.set_dif_file_path(path.to_string_lossy().as_ref().into());
                }
            }
        }
    });

    let _log_clone = log.clone();
    ui.on_select_exe_file({
        let ui_handle = ui_handle.clone();
        move || {
            if let Some(path) = select_file("Select the EXE to Patch", &["exe"]) {
                if let Some(handle) = ui_handle.upgrade() {
                    handle.set_exe_file_path(path.to_string_lossy().as_ref().into());
                }
            }
        }
    });

    let log_clone = log.clone();
    ui.on_apply_patch({
        let ui_handle = ui_handle.clone();
        move || {
            let ui_handle = ui_handle.clone();
            let dif_path = ui_handle.upgrade().unwrap().get_dif_file_path().to_string();
            let exe_path = ui_handle.upgrade().unwrap().get_exe_file_path().to_string();
            match apply_patches_from_dif(
                Path::new(&dif_path),
                Path::new(&exe_path),
                log_clone.clone(),
            ) {
                Ok(_) => {
                    if let Some(handle) = ui_handle.upgrade() {
                        handle.set_log("File patched successfully!".into());
                    }
                }
                Err(e) => {
                    if let Some(handle) = ui_handle.upgrade() {
                        let log_content = log_clone.lock().unwrap().clone();
                        handle.set_log(
                            format!("Failed to patch file: {}\n{}", e, log_content).into(),
                        );
                    }
                }
            }
        }
    });

    ui.run()
}

// Function to select a file using a dialog
fn select_file(title: &str, filters: &[&str]) -> Option<PathBuf> {
    FileDialog::new()
        .add_filter("Files", filters)
        .set_title(title)
        .pick_file()
}
