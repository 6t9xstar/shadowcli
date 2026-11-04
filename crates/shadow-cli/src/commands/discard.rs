use anyhow::{bail, Result};
use colored::*;
use shadow_core::SessionStore;
use std::path::Path;
use ulid::Ulid;

pub fn execute(session_id: Option<String>, current_dir: &Path) -> Result<i32> {
    let store = SessionStore::init_default()?;

    let (meta, _paths) = match session_id {
        Some(id_str) => {
            let id = Ulid::from_string(&id_str)?;
            store.load_meta(&id)?
        }
        None => match store.find_latest_unapplied(current_dir)? {
            Some((m, p)) => (m, p),
            None => {
                bail!("No active or unapplied ShadowCLI session found for this project.");
            }
        },
    };

    store.discard_session(&meta.id)?;
    println!(
        "{} Session {} discarded. Project remains completely unchanged.",
        "✔".green(),
        meta.id
    );
    Ok(0)
}
