//! Content proof reader shared by encrypted storage and authorized plaintext peer relay.
use super::{HistoryArchiveBytesReference, HistoryArchiveEncryptedReader, HistoryArchiveObjectBinding};
use crate::{history_archive::{HistoryArchiveIndexPage, HistoryArchiveIndexRoot, HistoryArchiveTreeContext,
    history_archive_object_id, verify_history_archive_index_page}, history_archive_crypto::HistoryArchiveEncryptionScope,
    history_locator::HistoryArchiveLocatorRoot};
use std::collections::BTreeSet;

pub trait HistoryArchivePlaintextReader {
    fn ensure_current(&mut self) -> Result<(), String>;
    fn read(&mut self, object_id: &str) -> Result<Vec<u8>, String>;
}
pub(crate) trait HistoryArchiveSource {
    fn ensure_current(&mut self) -> Result<(), String>;
    fn read_bound(&mut self, binding: &HistoryArchiveObjectBinding, object_id: &str) -> Result<Vec<u8>, String>;
}
pub(crate) struct BoundedSource<'a, R: HistoryArchiveSource> {
    reader: &'a mut R, bytes: usize, objects: usize, maximum_bytes: usize, maximum_objects: usize,
}
impl<'a, R: HistoryArchiveSource> BoundedSource<'a, R> {
    pub fn new(reader: &'a mut R, maximum_bytes: usize, maximum_objects: usize) -> Self {
        Self { reader, bytes: 0, objects: 0, maximum_bytes, maximum_objects }
    }
}
impl<R: HistoryArchiveSource> HistoryArchiveSource for BoundedSource<'_, R> {
    fn ensure_current(&mut self) -> Result<(), String> { self.reader.ensure_current() }
    fn read_bound(&mut self, binding: &HistoryArchiveObjectBinding, id: &str) -> Result<Vec<u8>, String> {
        self.ensure_current()?;
        let bytes = self.reader.read_bound(binding, id)?;
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or("History proof byte count overflow")?;
        self.objects = self.objects.checked_add(1).ok_or("History proof object count overflow")?;
        if self.bytes > self.maximum_bytes || self.objects > self.maximum_objects { return Err("History proof read exceeds its bounded source budget".into()); }
        self.ensure_current()?;
        Ok(bytes)
    }
}
pub(crate) struct PlaintextSource<'a, R: HistoryArchivePlaintextReader> { pub reader: &'a mut R }
impl<R: HistoryArchivePlaintextReader> HistoryArchiveSource for PlaintextSource<'_, R> {
    fn ensure_current(&mut self) -> Result<(), String> { self.reader.ensure_current() }
    fn read_bound(&mut self, binding: &HistoryArchiveObjectBinding, id: &str) -> Result<Vec<u8>, String> {
        self.ensure_current()?;
        let bytes = self.reader.read(id)?;
        self.ensure_current()?;
        let maximum = if binding.object_kind == "part" { 256 * 1024 } else { 64 * 1024 };
        if bytes.len() > maximum || history_archive_object_id(&bytes) != id { return Err("Peer archive plaintext hash or size differs".into()); }
        Ok(bytes)
    }
}
pub(crate) struct EncryptedSource<'a, R: HistoryArchiveEncryptedReader> {
    pub reader: &'a mut R, pub scope: &'a HistoryArchiveEncryptionScope, pub locator_root: &'a HistoryArchiveLocatorRoot,
}
impl<R: HistoryArchiveEncryptedReader> HistoryArchiveSource for EncryptedSource<'_, R> {
    fn ensure_current(&mut self) -> Result<(), String> { self.reader.ensure_current() }
    fn read_bound(&mut self, binding: &HistoryArchiveObjectBinding, id: &str) -> Result<Vec<u8>, String> {
        super::storage::read_history_archive_bound_object(self.scope, self.locator_root, binding, id, self.reader)
    }
}
fn binding(context: &HistoryArchiveTreeContext, kind: &str) -> HistoryArchiveObjectBinding {
    HistoryArchiveObjectBinding { context: context.clone(), object_kind: kind.into(), part_index: 0, part_count: 1 }
}
pub(crate) fn index_object(context: &HistoryArchiveTreeContext, root: &HistoryArchiveIndexRoot, key: &str,
    source: &mut impl HistoryArchiveSource) -> Result<String, String> {
    if key.is_empty() || key.len() > 512 { return Err("Invalid archive lookup key".into()); }
    let mut next = root.clone();
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        if !seen.insert(next.object_id.clone()) { return Err("Archive proof path contains a cycle".into()); }
        let raw = source.read_bound(&binding(context, "page"), &next.object_id)?;
        match verify_history_archive_index_page(context, &next, &raw)? {
            HistoryArchiveIndexPage::Leaf(page) => return page.entries.into_iter().find(|entry| entry.key == key)
                .map(|entry| entry.object_id).ok_or("Required archive proof path is missing".into()),
            HistoryArchiveIndexPage::Branch(page) => next = page.children.into_iter().find(|child|
                child.first.as_deref().is_some_and(|first| first <= key) && child.last.as_deref().is_some_and(|last| key <= last))
                .ok_or("Required archive proof path is outside the signed index".to_string())?,
        }
    }
    Err("Archive proof path exceeds depth limit".into())
}
pub(crate) fn index_record(context: &HistoryArchiveTreeContext, root: &HistoryArchiveIndexRoot, key: &str,
    source: &mut impl HistoryArchiveSource) -> Result<Vec<u8>, String> {
    let id = index_object(context, root, key, source)?;
    source.read_bound(&binding(context, "record"), &id)
}
pub(crate) fn bytes(context: &HistoryArchiveTreeContext, reference: &HistoryArchiveBytesReference, maximum: u64,
    source: &mut impl HistoryArchiveSource) -> Result<Vec<u8>, String> {
    if reference.kind != "workspace-history-bytes" || reference.version != 1 || reference.byte_length > maximum ||
        reference.part_count != reference.byte_length.div_ceil(256 * 1024) || reference.root.count != reference.part_count {
        return Err("Invalid original archive byte reference".into());
    }
    let mut bytes = Vec::with_capacity(reference.byte_length as usize);
    for part in 0..reference.part_count {
        let id = index_object(context, &reference.root, &format!("{part:016x}"), source)?;
        let binding = HistoryArchiveObjectBinding { context: context.clone(), object_kind: "part".into(),
            part_index: part, part_count: reference.part_count };
        let value = source.read_bound(&binding, &id)?;
        if value.is_empty() || value.len() > 256 * 1024 || part + 1 != reference.part_count && value.len() != 256 * 1024 ||
            bytes.len().checked_add(value.len()).is_none_or(|length| length as u64 > reference.byte_length) {
            return Err("Original archive byte parts differ from signed reference".into());
        }
        bytes.extend(value);
    }
    if bytes.len() as u64 != reference.byte_length { return Err("Original archive byte reference is incomplete".into()); }
    Ok(bytes)
}
