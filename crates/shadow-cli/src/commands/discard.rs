use anyhow::{bail, Result};
use colored::*;
use shadow_core::SessionStore;
use std::path::Path;
use ulid::Ulid;

pub fn discard_session_mcp(session_id: Option<String>, current_dir: &Path) -> Result<String> {
    let store = SessionStore::init_default()?;

    let id = match session_id {
        Some(id_str) => Ulid::from_string(&id_str)?,
        None => match store.find_latest_unapplied(current_dir)? {
            Some((m, _p)) => m.id,
            None => {
                bail!("No active or unapplied ShadowCLI session found for this project.");
            }
        },
    };

    store.discard_session(&id)?;
    Ok(format!(
        "Session {} discarded. Project remains completely unchanged.",
        id
    ))
}

pub fn execute(session_id: Option<String>, current_dir: &Path) -> Result<i32> {
    let store = SessionStore::init_default()?;

    let id = match session_id {
        Some(id_str) => Ulid::from_string(&id_str)?,
        None => match store.find_latest_unapplied(current_dir)? {
            Some((m, _p)) => m.id,
            None => {
                bail!("No active or unapplied ShadowCLI session found for this project.");
            }
        },
    };

    store.discard_session(&id)?;
    println!(
        "{} Session {} discarded. Project remains completely unchanged.",
        "✔".green(),
        id
    );
    Ok(0)
}
