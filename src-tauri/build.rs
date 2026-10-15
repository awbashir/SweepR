use std::{fs, path::Path};

fn main() {
    // `tauri::generate_context!` embeds `build.frontendDist` and fails to compile when the
    // directory is missing. Create it so `cargo build` / `cargo check` (CLI-only workflows)
    // work on a fresh checkout before the frontend has been built.
    let dist = Path::new("..").join("dist");
    if !dist.exists() {
        let _ = fs::create_dir_all(&dist);
    }
    tauri_build::build();
}
