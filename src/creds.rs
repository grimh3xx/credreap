//! A small on-disk store for recovered credentials.
//!
//! Keeps spray hits and cracked hashes in one JSON file so a later run can
//! reuse them (password reuse is the whole point of credential attacks) and so
//! an operator has a single artefact to hand to the report.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub user: String,
    pub secret: String,
    /// Where it was found/validated, e.g. "http-basic https://portal".
    pub source: String,
    /// "spray" | "crack" | "manual".
    pub kind: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Store {
    pub credentials: Vec<Credential>,
}

impl Store {
    pub fn load(path: &Path) -> Result<Store> {
        if !path.exists() {
            return Ok(Store::default());
        }
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&text).unwrap_or_default())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    /// Add a credential if an identical (user, secret, source) is not present.
    pub fn add(&mut self, c: Credential) -> bool {
        let dup = self.credentials.iter().any(|e| {
            e.user.eq_ignore_ascii_case(&c.user) && e.secret == c.secret && e.source == c.source
        });
        if dup {
            false
        } else {
            self.credentials.push(c);
            true
        }
    }

    /// Group stored secrets by user, to surface reuse across sources.
    pub fn reuse_report(&self) -> BTreeMap<String, Vec<String>> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for c in &self.credentials {
            let entry = map.entry(c.user.to_ascii_lowercase()).or_default();
            if !entry.contains(&c.secret) {
                entry.push(c.secret.clone());
            }
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedups_on_add() {
        let mut s = Store::default();
        let c = Credential {
            user: "alice".into(),
            secret: "pw".into(),
            source: "http".into(),
            kind: "spray".into(),
        };
        assert!(s.add(c.clone()));
        assert!(!s.add(c));
        assert_eq!(s.credentials.len(), 1);
    }
}
