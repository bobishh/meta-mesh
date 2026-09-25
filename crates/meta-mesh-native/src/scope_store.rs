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
    #[cfg(test)]
    fail_after_file_sync: Mutex<bool>,
}

impl FileScopeStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
            #[cfg(test)]
            fail_after_file_sync: Mutex::new(false),
        }
    }

    #[cfg(test)]
    fn fail_after_file_sync_once(&self) {
        *self.fail_after_file_sync.lock().unwrap() = true;
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
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|error| format!("Create temporary scope document: {error}"))?;
            file.write_all(candidate)
                .map_err(|error| format!("Write scope document: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("Sync scope document: {error}"))?;
            #[cfg(test)]
            if std::mem::take(&mut *self.fail_after_file_sync.lock().unwrap()) {
                return Err("Injected failure after scope document sync".into());
            }
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

    #[test]
    fn synced_but_uncommitted_write_and_crash_residue_keep_last_document_after_reopen() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "meta-mesh-scope-failure-{}-{nonce}",
            std::process::id()
        ));
        let path = directory.join("board.automerge");
        let store = FileScopeStore::new(&path);
        store
            .write_validated(b"previous", None, |_, _| Ok(()))
            .unwrap();

        store.fail_after_file_sync_once();
        assert_eq!(
            store.write_validated(b"uncommitted", None, |_, _| Ok(())),
            Err("Injected failure after scope document sync".into())
        );
        drop(store);

        // A process crash before rename can leave an unrelated temporary file.
        // Reopening reads only the committed path and a later retry replaces it.
        fs::write(path.with_extension("tmp-crash-residue"), b"orphan").unwrap();
        let reopened = FileScopeStore::new(&path);
        assert_eq!(
            reopened.read().unwrap().as_deref(),
            Some(b"previous".as_slice())
        );
        reopened
            .write_validated(b"retried", None, |_, _| Ok(()))
            .unwrap();
        drop(reopened);
        assert_eq!(
            FileScopeStore::new(&path).read().unwrap().as_deref(),
            Some(b"retried".as_slice())
        );

        fs::remove_dir_all(directory).unwrap();
    }
}
