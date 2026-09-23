use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

/// Durable bytes for one scope. The product verifier runs before any write;
/// the mesh protocol only acknowledges after this method returns success.
pub struct FileScopeStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl FileScopeStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    pub fn read(&self) -> Result<Option<Vec<u8>>, String> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Read scope document: {error}")),
        }
    }

    pub fn write_validated(
        &self,
        candidate: &[u8],
        proof: Option<&Value>,
        verify: impl FnOnce(&[u8], Option<&Value>) -> Result<(), String>,
    ) -> Result<(), String> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| "Scope store lock poisoned")?;
        verify(candidate, proof)?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|error| format!("Create scope directory: {error}"))?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("Scope clock: {error}"))?
            .as_nanos();
        let temp = self
            .path
            .with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)
                .map_err(|error| format!("Create temporary scope document: {error}"))?;
            file.write_all(candidate)
                .map_err(|error| format!("Write scope document: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("Sync scope document: {error}"))?;
            fs::rename(&temp, &self.path)
                .map_err(|error| format!("Commit scope document: {error}"))?;
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("Sync scope directory: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_candidate_keeps_last_durable_document_after_restart() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("meta-mesh-scope-{}-{nonce}", std::process::id()));
        let path = directory.join("board.automerge");
        let store = FileScopeStore::new(&path);
        store
            .write_validated(b"accepted", None, |_, _| Ok(()))
            .unwrap();
        assert_eq!(
            store.write_validated(b"forged", None, |_, _| Err("invalid proof".into())),
            Err("invalid proof".into())
        );
        assert_eq!(
            FileScopeStore::new(&path).read().unwrap().as_deref(),
            Some(b"accepted".as_slice())
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
