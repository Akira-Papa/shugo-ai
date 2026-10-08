fn main() {
    #[cfg(feature = "desktop")]
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "snapshot",
            "scan_start",
            "scan_cancel",
            "set_schedule",
            "set_paused",
            "set_models",
            "register_file",
            "accept_baseline",
            "import_credential",
            "catalog_refresh",
            "cloud_enable",
            "cloud_disable",
            "analyze",
            "analysis_cancel",
            "export_report",
            "acknowledge",
            "delete_history",
            "set_response_policy",
            "revoke_response_policy",
            "execute_response",
            "emergency_lock",
        ]),
    ))
    .expect("Tauri build configuration");
}
