use super::{
    HistoryArchiveCatalogue, HistoryArchiveObjectBinding, HistoryArchiveWriter,
    VerifiedHistoryArchiveCapture,
};
use crate::{
    history_archive::history_archive_object_id,
    history_archive_crypto::{
        EncryptedHistoryArchiveObject, HistoryArchiveEncryptionBinding,
        HistoryArchiveEncryptionScope, open_history_archive_object,
    },
    history_locator::{
        HistoryArchiveLocatorPage, HistoryArchiveLocatorRoot, open_history_locator_page,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub trait HistoryArchiveEncryptedReader {
    fn ensure_current(&mut self) -> Result<(), String>;
    fn download(&mut self, ciphertext_id: &str) -> Result<EncryptedHistoryArchiveObject, String>;
}

/// Private Native evidence of exact content correspondence, not storage coverage or baseline authority.
pub struct VerifiedHistoryArchiveStorage {
    catalogue: HistoryArchiveCatalogue,
    locator_root: HistoryArchiveLocatorRoot,
    scope_id: String,
    key_epoch: u64,
    key_digest: String,
    catalogue_ciphertext_id: String,
    data_ciphertext_ids: BTreeSet<String>,
    directory_ciphertext_ids: BTreeSet<String>,
}
impl VerifiedHistoryArchiveStorage {
    pub fn catalogue(&self) -> &HistoryArchiveCatalogue {
        &self.catalogue
    }
    pub fn locator_root(&self) -> &HistoryArchiveLocatorRoot {
        &self.locator_root
    }
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
    pub fn key_digest(&self) -> &str {
        &self.key_digest
    }
    pub fn catalogue_ciphertext_id(&self) -> &str {
        &self.catalogue_ciphertext_id
    }
    pub fn data_ciphertext_ids(&self) -> &BTreeSet<String> {
        &self.data_ciphertext_ids
    }
    pub fn directory_ciphertext_ids(&self) -> &BTreeSet<String> {
        &self.directory_ciphertext_ids
    }
}
impl VerifiedHistoryArchiveCapture {
    pub fn verify_storage_directory(
        &self,
        scope: &HistoryArchiveEncryptionScope,
        root: &HistoryArchiveLocatorRoot,
        reader: &mut impl HistoryArchiveEncryptedReader,
    ) -> Result<VerifiedHistoryArchiveStorage, String> {
        if root.context.workspace_id != self.preparation().source().snapshot.workspace_id
            || root.context.history_epoch != self.history_epoch()
        {
            return Err("Archive locator root differs from Native capture context".into());
        }
        reader.ensure_current()?;
        let mut verifier = StorageVerifier {
            scope,
            root,
            reader,
            bindings: BTreeMap::new(),
            data_ids: BTreeSet::new(),
            directory_ids: BTreeSet::new(),
        };
        // Re-derive content from the private capture token, never a host catalogue or claimed classification.
        let catalogue = self.write_catalogue(&mut verifier)?;
        if verifier.bindings.len() as u64 != root.root.count
            || !verifier.data_ids.is_disjoint(&verifier.directory_ids)
        {
            return Err("Archive locator directory does not exactly cover Native capture".into());
        }
        let root_key = binding_key(&HistoryArchiveEncryptionBinding {
            workspace_id: catalogue.context.workspace_id.clone(),
            history_epoch: catalogue.context.history_epoch,
            index_id: catalogue.context.index_id.clone(),
            object_id: catalogue.root.object_id.clone(),
            object_kind: "page".into(),
            part_index: 0,
            part_count: 1,
        })?;
        let catalogue_ciphertext_id = verifier
            .bindings
            .get(&root_key)
            .ok_or("Native catalogue root locator missing")?
            .clone();
        verifier.reader.ensure_current()?;
        Ok(VerifiedHistoryArchiveStorage {
            catalogue,
            locator_root: root.clone(),
            scope_id: scope.scope_id.clone(),
            key_epoch: scope.key_epoch,
            key_digest: history_archive_object_id(&scope.key),
            catalogue_ciphertext_id,
            data_ciphertext_ids: verifier.data_ids,
            directory_ciphertext_ids: verifier.directory_ids,
        })
    }
}

fn binding_key(binding: &HistoryArchiveEncryptionBinding) -> Result<String, String> {
    let value = serde_json::to_value(binding).map_err(|_| "Invalid archive storage binding")?;
    Ok(history_archive_object_id(
        crate::canonicalize_json(&value)?.as_bytes(),
    ))
}

struct StorageVerifier<'a, R> {
    scope: &'a HistoryArchiveEncryptionScope,
    root: &'a HistoryArchiveLocatorRoot,
    reader: &'a mut R,
    bindings: BTreeMap<String, String>,
    data_ids: BTreeSet<String>,
    directory_ids: BTreeSet<String>,
}
impl<R: HistoryArchiveEncryptedReader> StorageVerifier<'_, R> {
    fn lookup(&mut self, key: &str) -> Result<String, String> {
        let mut pointer = self.root.root.clone();
        let mut visited = HashSet::new();
        for _ in 0..32 {
            if !visited.insert(pointer.ciphertext_id.clone()) {
                return Err("Archive locator cycle".into());
            }
            self.reader.ensure_current()?;
            let encrypted = self.reader.download(&pointer.ciphertext_id)?;
            self.reader.ensure_current()?;
            let page = open_history_locator_page(self.scope, self.root, &pointer, &encrypted)?;
            self.reader.ensure_current()?;
            self.directory_ids.insert(pointer.ciphertext_id);
            match page {
                HistoryArchiveLocatorPage::Leaf(leaf) => {
                    return leaf
                        .entries
                        .into_iter()
                        .find(|entry| entry.key == key)
                        .map(|entry| entry.ciphertext_id)
                        .ok_or("Native archive binding absent from directory".into());
                }
                HistoryArchiveLocatorPage::Branch(branch) => {
                    pointer = branch
                        .children
                        .into_iter()
                        .find(|child| {
                            child.first.as_deref().is_some_and(|first| first <= key)
                                && child.last.as_deref().is_some_and(|last| key <= last)
                        })
                        .ok_or("Native archive binding outside locator ranges")?;
                }
            }
        }
        Err("Archive locator depth exceeded".into())
    }
}
impl<R: HistoryArchiveEncryptedReader> HistoryArchiveWriter for StorageVerifier<'_, R> {
    fn write(
        &mut self,
        object_id: &str,
        bytes: &[u8],
        binding: &HistoryArchiveObjectBinding,
    ) -> Result<(), String> {
        let binding = HistoryArchiveEncryptionBinding {
            workspace_id: binding.context.workspace_id.clone(),
            history_epoch: binding.context.history_epoch,
            index_id: binding.context.index_id.clone(),
            object_id: object_id.into(),
            object_kind: binding.object_kind.clone(),
            part_index: binding.part_index,
            part_count: binding.part_count,
        };
        let key = binding_key(&binding)?;
        // Repeated Native writes of an identical content-addressed binding are one directory entry.
        if self.bindings.contains_key(&key) {
            return self.reader.ensure_current();
        }
        if self.bindings.len() >= 1_048_576 {
            return Err("Native archive object count exceeds limit".into());
        }
        let ciphertext_id = self.lookup(&key)?;
        self.reader.ensure_current()?;
        let encrypted = self.reader.download(&ciphertext_id)?;
        self.reader.ensure_current()?;
        let opened = open_history_archive_object(self.scope, &binding, &ciphertext_id, &encrypted)?;
        self.reader.ensure_current()?;
        if opened != bytes || !self.data_ids.insert(ciphertext_id.clone()) {
            return Err("Stored archive differs from exact Native capture".into());
        }
        self.bindings.insert(key, ciphertext_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
