use super::{
    HistoryArchiveCatalogue, HistoryArchiveObjectBinding, HistoryArchiveWriter,
    VerifiedHistoryArchiveCapture, HistoryArchiveBytesReference,
};
use crate::{
    history_archive::{
        HistoryArchiveIndexPage, HistoryArchiveIndexRoot, HistoryArchiveTreeContext,
        history_archive_object_id, verify_history_archive_index_page,
    },
    history_archive_crypto::{
        EncryptedHistoryArchiveObject, HistoryArchiveEncryptionBinding,
        HistoryArchiveEncryptionScope, open_history_archive_object,
    },
    history_locator::{
        HistoryArchiveLocatorPage, HistoryArchiveLocatorRoot,
        open_history_locator_page,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

const MAX_HISTORY_CONTROL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HISTORY_SOURCE_DOCUMENT_BYTES: u64 = 256 * 1024 * 1024;
const HISTORY_ARCHIVE_PART_BYTES: u64 = 256 * 1024;

pub trait HistoryArchiveEncryptedReader {
    fn ensure_current(&mut self) -> Result<(), String>;
    fn download(&mut self, ciphertext_id: &str) -> Result<EncryptedHistoryArchiveObject, String>;
}

/// Cold archive read port. This authenticates archive bytes and locator paths;
/// it does not establish historical admission or authorize baseline activation.
pub fn read_history_archive_control(
    scope: &HistoryArchiveEncryptionScope,
    catalogue: &HistoryArchiveCatalogue,
    locator_root: &HistoryArchiveLocatorRoot,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    read_history_archive_source_bytes(scope, catalogue, locator_root, "control", reader)
}

/// Read the original source Automerge save for control-frontier verification.
/// Callers must treat this as untrusted historical evidence, not an active basis.
pub fn read_history_archive_source_document(
    scope: &HistoryArchiveEncryptionScope,
    catalogue: &HistoryArchiveCatalogue,
    locator_root: &HistoryArchiveLocatorRoot,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    read_history_archive_source_bytes(scope, catalogue, locator_root, "document", reader)
}

/// Resolve the opaque archive address for an exact plaintext binding. The
/// returned address is routing data only; callers still verify encrypted bytes.
pub fn resolve_history_archive_ciphertext_id(
    scope: &HistoryArchiveEncryptionScope,
    locator_root: &HistoryArchiveLocatorRoot,
    binding: &HistoryArchiveObjectBinding,
    object_id: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<String, String> {
    locate_history_archive_binding(scope, locator_root, binding, object_id, reader)
}

fn read_history_archive_source_bytes(
    scope: &HistoryArchiveEncryptionScope,
    catalogue: &HistoryArchiveCatalogue,
    locator_root: &HistoryArchiveLocatorRoot,
    field: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    let (entry_key, bytes_index_id, max_bytes) = match field {
        "control" => ("control", "source-control", MAX_HISTORY_CONTROL_BYTES),
        "document" => ("document", "source-document", MAX_HISTORY_SOURCE_DOCUMENT_BYTES),
        _ => return Err("Unsupported archived source field".into()),
    };
    if catalogue.kind != "workspace-history-catalogue"
        || catalogue.version != 1
        || catalogue.context.workspace_id != locator_root.context.workspace_id
        || catalogue.context.history_epoch != locator_root.context.history_epoch
        || catalogue.context.index_id != "catalogue"
        || scope.key_epoch == 0
        || locator_root.kind != "workspace-history-locator-root"
        || locator_root.version != 1
        || locator_root.context.index_id != "archive-locators"
        || locator_root.context.workspace_id != catalogue.context.workspace_id
        || locator_root.context.history_epoch != catalogue.context.history_epoch
    {
        return Err("Cold archive context does not match catalogue".into());
    }
    reader.ensure_current()?;
    let reference_bytes = read_history_archive_index_record(
        scope,
        locator_root,
        &catalogue.context,
        &catalogue.root,
        entry_key,
        reader,
    )?;
    let reference: HistoryArchiveBytesReference = serde_json::from_slice(&reference_bytes)
        .map_err(|_| "Invalid archived control bytes reference")?;
    if reference.kind != "workspace-history-bytes"
        || reference.version != 1
        || reference.byte_length > max_bytes
    {
        return Err("Archived control bytes exceed supported bounds".into());
    }
    let context = HistoryArchiveTreeContext {
        workspace_id: catalogue.context.workspace_id.clone(),
        history_epoch: catalogue.context.history_epoch,
        index_id: bytes_index_id.into(),
    };
    let result = read_history_archive_bytes(scope, locator_root, &context, &reference, max_bytes, reader)?;
    reader.ensure_current()?;
    Ok(result)
}

pub(super) fn read_history_archive_bytes(
    scope: &HistoryArchiveEncryptionScope,
    locator_root: &HistoryArchiveLocatorRoot,
    context: &HistoryArchiveTreeContext,
    reference: &HistoryArchiveBytesReference,
    max_bytes: u64,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    let expected_parts = reference.byte_length.div_ceil(HISTORY_ARCHIVE_PART_BYTES);
    if reference.kind != "workspace-history-bytes"
        || reference.version != 1
        || reference.byte_length > max_bytes
        || reference.part_count != expected_parts
        || reference.root.count != reference.part_count
        || reference.root.height >= 32
        || context.workspace_id != locator_root.context.workspace_id
        || context.history_epoch != locator_root.context.history_epoch
    {
        return Err("Invalid archived control byte index".into());
    }
    let mut bytes = Vec::with_capacity(reference.byte_length as usize);
    for index in 0..reference.part_count {
        let key = format!("{index:016x}");
        let part_id = read_history_archive_index_object_id(
            scope,
            locator_root,
            context,
            &reference.root,
            &key,
            reader,
        )?;
        let binding = HistoryArchiveObjectBinding {
            context: context.clone(),
            object_kind: "part".into(),
            part_index: index,
            part_count: reference.part_count,
        };
        let part = read_history_archive_bound_object(scope, locator_root, &binding, &part_id, reader)?;
        let is_last = index + 1 == reference.part_count;
        if part.is_empty()
            || part.len() as u64 > HISTORY_ARCHIVE_PART_BYTES
            || !is_last && part.len() as u64 != HISTORY_ARCHIVE_PART_BYTES
            || bytes.len().checked_add(part.len()).is_none_or(|length| length > max_bytes as usize)
        {
            return Err("Archived control part length is invalid".into());
        }
        bytes.extend_from_slice(&part);
    }
    if bytes.len() as u64 != reference.byte_length {
        return Err("Archived control byte length mismatch".into());
    }
    Ok(bytes)
}

pub(super) fn read_history_archive_index_record(
    scope: &HistoryArchiveEncryptionScope,
    locator_root: &HistoryArchiveLocatorRoot,
    context: &HistoryArchiveTreeContext,
    index_root: &HistoryArchiveIndexRoot,
    key: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    let object_id = read_history_archive_index_object_id(scope, locator_root, context, index_root, key, reader)?;
    read_history_archive_bound_object(
        scope,
        locator_root,
        &HistoryArchiveObjectBinding {
            context: context.clone(),
            object_kind: "record".into(),
            part_index: 0,
            part_count: 1,
        },
        &object_id,
        reader,
    )
}

fn read_history_archive_index_object_id(
    scope: &HistoryArchiveEncryptionScope,
    locator_root: &HistoryArchiveLocatorRoot,
    context: &HistoryArchiveTreeContext,
    index_root: &HistoryArchiveIndexRoot,
    key: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<String, String> {
    if context.workspace_id != locator_root.context.workspace_id
        || context.history_epoch != locator_root.context.history_epoch
        || key.is_empty()
        || key.len() > 512
    {
        return Err("Archive index lookup context mismatch".into());
    }
    let mut pointer = index_root.clone();
    let mut visited = HashSet::new();
    for _ in 0..32 {
        if !visited.insert(pointer.object_id.clone()) {
            return Err("Archive index cycle".into());
        }
        let bytes = read_history_archive_bound_object(
            scope,
            locator_root,
            &HistoryArchiveObjectBinding {
                context: context.clone(),
                object_kind: "page".into(),
                part_index: 0,
                part_count: 1,
            },
            &pointer.object_id,
            reader,
        )?;
        let page = verify_history_archive_index_page(context, &pointer, &bytes)?;
        match page {
            HistoryArchiveIndexPage::Leaf(leaf) => {
                return leaf.entries.into_iter().find(|entry| entry.key == key)
                    .map(|entry| entry.object_id)
                    .ok_or_else(|| "Archive index key is missing".into());
            }
            HistoryArchiveIndexPage::Branch(branch) => {
                pointer = branch.children.into_iter().find(|child| {
                    child.first.as_deref().is_some_and(|first| archive_key_order(first, key).is_le())
                        && child.last.as_deref().is_some_and(|last| archive_key_order(key, last).is_le())
                }).ok_or_else(|| "Archive index key is outside page ranges".to_string())?;
            }
        }
    }
    Err("Archive index depth exceeded".into())
}

fn archive_key_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

pub(super) fn read_history_archive_bound_object(
    scope: &HistoryArchiveEncryptionScope,
    locator_root: &HistoryArchiveLocatorRoot,
    binding: &HistoryArchiveObjectBinding,
    object_id: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<Vec<u8>, String> {
    let ciphertext_id = locate_history_archive_binding(scope, locator_root, binding, object_id, reader)?;
    reader.ensure_current()?;
    let encrypted = reader.download(&ciphertext_id)?;
    reader.ensure_current()?;
    let binding = HistoryArchiveEncryptionBinding {
        workspace_id: binding.context.workspace_id.clone(),
        history_epoch: binding.context.history_epoch,
        index_id: binding.context.index_id.clone(),
        object_id: object_id.into(),
        object_kind: binding.object_kind.clone(),
        part_index: binding.part_index,
        part_count: binding.part_count,
    };
    let bytes = open_history_archive_object(scope, &binding, &ciphertext_id, &encrypted)?;
    reader.ensure_current()?;
    Ok(bytes)
}

fn locate_history_archive_binding(
    scope: &HistoryArchiveEncryptionScope,
    root: &HistoryArchiveLocatorRoot,
    binding: &HistoryArchiveObjectBinding,
    object_id: &str,
    reader: &mut impl HistoryArchiveEncryptedReader,
) -> Result<String, String> {
    if root.kind != "workspace-history-locator-root"
        || root.version != 1
        || root.context.index_id != "archive-locators"
        || binding.context.workspace_id != root.context.workspace_id
        || binding.context.history_epoch != root.context.history_epoch
    {
        return Err("Archive locator lookup context mismatch".into());
    }
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
    let mut pointer = root.root.clone();
    let mut visited = HashSet::new();
    for _ in 0..32 {
        if !visited.insert(pointer.ciphertext_id.clone()) {
            return Err("Archive locator cycle".into());
        }
        reader.ensure_current()?;
        let encrypted = reader.download(&pointer.ciphertext_id)?;
        reader.ensure_current()?;
        match open_history_locator_page(scope, root, &pointer, &encrypted)? {
            HistoryArchiveLocatorPage::Leaf(leaf) => {
                return leaf.entries.into_iter().find(|entry| entry.key == key)
                    .map(|entry| entry.ciphertext_id)
                    .ok_or_else(|| "Archive binding is absent from portable directory".into());
            }
            HistoryArchiveLocatorPage::Branch(branch) => {
                pointer = branch.children.into_iter().find(|child| {
                    child.first.as_deref().is_some_and(|first| first <= key.as_str())
                        && child.last.as_deref().is_some_and(|last| key.as_str() <= last)
                }).ok_or_else(|| "Archive binding is outside locator ranges".to_string())?;
            }
        }
    }
    Err("Archive locator depth exceeded".into())
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
