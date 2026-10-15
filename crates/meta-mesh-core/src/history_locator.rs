//! Portable encrypted lookup directory for opaque archive-object addresses.
//! Locator integrity is not archive authority or baseline activation authority.
use crate::{
    history_archive::{
        HistoryArchiveTreeContext, MAX_HISTORY_ARCHIVE_CHILDREN, MAX_HISTORY_ARCHIVE_DEPTH,
        MAX_HISTORY_ARCHIVE_KEY_BYTES, MAX_HISTORY_ARCHIVE_PAGE_BYTES, history_archive_object_id,
        valid_context, valid_digest,
    },
    history_archive_crypto::{
        EncryptedHistoryArchiveObject, HistoryArchiveEncryptionBinding,
        HistoryArchiveEncryptionScope, open_history_archive_object,
    },
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

const MAX_LOCATOR_ENTRIES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLocatorPointer {
    pub object_id: String,
    pub ciphertext_id: String,
    pub height: u8,
    pub count: u64,
    #[serde(deserialize_with = "required_nullable_string")]
    pub first: Option<String>,
    #[serde(deserialize_with = "required_nullable_string")]
    pub last: Option<String>,
}

fn required_nullable_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLocatorRoot {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub root: HistoryArchiveLocatorPointer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLocatorEntry {
    pub key: String,
    pub ciphertext_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLocatorLeaf {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub height: u8,
    pub entries: Vec<HistoryArchiveLocatorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLocatorBranch {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub height: u8,
    pub children: Vec<HistoryArchiveLocatorPointer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoryArchiveLocatorPage {
    Leaf(HistoryArchiveLocatorLeaf),
    Branch(HistoryArchiveLocatorBranch),
}

fn valid_locator_context(context: &HistoryArchiveTreeContext) -> Result<(), String> {
    valid_context(context)?;
    if context.index_id != "archive-locators" {
        return Err("Invalid history locator directory context".into());
    }
    Ok(())
}

fn key_order(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

fn valid_key(value: &str) -> Result<(), String> {
    if value.len() > MAX_HISTORY_ARCHIVE_KEY_BYTES {
        return Err("History locator key exceeds size limit".into());
    }
    valid_digest(value)
}

fn valid_pointer(pointer: &HistoryArchiveLocatorPointer) -> Result<(), String> {
    valid_digest(&pointer.object_id)?;
    valid_digest(&pointer.ciphertext_id)?;
    if pointer.height >= MAX_HISTORY_ARCHIVE_DEPTH || pointer.count > MAX_LOCATOR_ENTRIES {
        return Err("Invalid history locator pointer height or count".into());
    }
    if pointer.height == 0 && pointer.count > MAX_HISTORY_ARCHIVE_CHILDREN as u64 {
        return Err("History locator leaf count exceeds fanout".into());
    }
    if pointer.count == 0 {
        if pointer.height != 0 || pointer.first.is_some() || pointer.last.is_some() {
            return Err("Invalid empty history locator pointer".into());
        }
    } else {
        let first = pointer
            .first
            .as_deref()
            .ok_or("Missing history locator range")?;
        let last = pointer
            .last
            .as_deref()
            .ok_or("Missing history locator range")?;
        valid_key(first)?;
        valid_key(last)?;
        if key_order(first, last) == Ordering::Greater || (pointer.count == 1) != (first == last) {
            return Err("Invalid history locator pointer range".into());
        }
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|_| "Invalid history locator encoding")?;
    Ok(crate::canonicalize_json(&value)?.into_bytes())
}

fn page_metadata(
    page: &HistoryArchiveLocatorPage,
) -> Result<
    (
        u8,
        &HistoryArchiveTreeContext,
        u64,
        Option<&str>,
        Option<&str>,
    ),
    String,
> {
    match page {
        HistoryArchiveLocatorPage::Leaf(leaf) => Ok((
            leaf.height,
            &leaf.context,
            leaf.entries.len() as u64,
            leaf.entries.first().map(|entry| entry.key.as_str()),
            leaf.entries.last().map(|entry| entry.key.as_str()),
        )),
        HistoryArchiveLocatorPage::Branch(branch) => {
            let count = branch
                .children
                .iter()
                .try_fold(0u64, |sum, child| sum.checked_add(child.count))
                .ok_or("History locator child count overflow")?;
            Ok((
                branch.height,
                &branch.context,
                count,
                branch
                    .children
                    .first()
                    .and_then(|child| child.first.as_deref()),
                branch
                    .children
                    .last()
                    .and_then(|child| child.last.as_deref()),
            ))
        }
    }
}

fn valid_page(
    page: &HistoryArchiveLocatorPage,
    context: &HistoryArchiveTreeContext,
) -> Result<(), String> {
    let (height, actual_context) = match page {
        HistoryArchiveLocatorPage::Leaf(leaf) => (leaf.height, &leaf.context),
        HistoryArchiveLocatorPage::Branch(branch) => (branch.height, &branch.context),
    };
    if actual_context != context {
        return Err("History locator page context mismatch".into());
    }
    match page {
        HistoryArchiveLocatorPage::Leaf(leaf) => {
            if leaf.kind != "workspace-history-locator-page"
                || leaf.version != 1
                || leaf.height != 0
                || leaf.entries.len() > MAX_HISTORY_ARCHIVE_CHILDREN
            {
                return Err("Invalid history locator leaf schema or size".into());
            }
            for (index, entry) in leaf.entries.iter().enumerate() {
                valid_key(&entry.key)?;
                valid_digest(&entry.ciphertext_id)?;
                if index > 0
                    && key_order(&leaf.entries[index - 1].key, &entry.key) != Ordering::Less
                {
                    return Err("Invalid history locator key order".into());
                }
            }
        }
        HistoryArchiveLocatorPage::Branch(branch) => {
            if branch.kind != "workspace-history-locator-page"
                || branch.version != 1
                || branch.height == 0
                || branch.height >= MAX_HISTORY_ARCHIVE_DEPTH
                || branch.children.is_empty()
                || branch.children.len() > MAX_HISTORY_ARCHIVE_CHILDREN
            {
                return Err("Invalid history locator branch schema or size".into());
            }
            let mut object_ids = std::collections::HashSet::new();
            let mut ciphertext_ids = std::collections::HashSet::new();
            for (index, child) in branch.children.iter().enumerate() {
                valid_pointer(child)?;
                if child.height != branch.height - 1
                    || child.count == 0
                    || !object_ids.insert(&child.object_id)
                    || !ciphertext_ids.insert(&child.ciphertext_id)
                {
                    return Err("Invalid or duplicate history locator child".into());
                }
                if index > 0
                    && key_order(
                        branch.children[index - 1]
                            .last
                            .as_deref()
                            .ok_or("Missing history locator child range")?,
                        child
                            .first
                            .as_deref()
                            .ok_or("Missing history locator child range")?,
                    ) != Ordering::Less
                {
                    return Err("Overlapping history locator child ranges".into());
                }
            }
        }
    }
    let (_, _, count, first, last) = page_metadata(page)?;
    if count > MAX_LOCATOR_ENTRIES {
        return Err("History locator count exceeds limit".into());
    }
    if count == 0 && (height != 0 || first.is_some() || last.is_some()) {
        return Err("Invalid empty history locator page".into());
    }
    Ok(())
}

/// Verify one plaintext page against its root context and pointer metadata.
pub fn verify_history_locator_page(
    root: &HistoryArchiveLocatorRoot,
    pointer: &HistoryArchiveLocatorPointer,
    bytes: &[u8],
) -> Result<HistoryArchiveLocatorPage, String> {
    if root.kind != "workspace-history-locator-root" || root.version != 1 {
        return Err("Unsupported history locator root schema/version".into());
    }
    valid_locator_context(&root.context)?;
    valid_pointer(&root.root)?;
    valid_pointer(pointer)?;
    if bytes.len() > MAX_HISTORY_ARCHIVE_PAGE_BYTES {
        return Err("History locator page exceeds byte limit".into());
    }
    if history_archive_object_id(bytes) != pointer.object_id {
        return Err("History locator page hash mismatch".into());
    }
    let page: HistoryArchiveLocatorPage =
        serde_json::from_slice(bytes).map_err(|_| "Invalid history locator page schema")?;
    valid_page(&page, &root.context)?;
    let (height, _, count, first, last) = page_metadata(&page)?;
    if pointer.height != height
        || pointer.count != count
        || pointer.first.as_deref() != first
        || pointer.last.as_deref() != last
    {
        return Err("History locator page does not match pointer metadata".into());
    }
    if canonical(&page)?.as_slice() != bytes {
        return Err("Non-canonical history locator page encoding".into());
    }
    Ok(page)
}

/// Decrypt and verify a page using its portable opaque locator.
pub fn open_history_locator_page(
    scope: &HistoryArchiveEncryptionScope,
    root: &HistoryArchiveLocatorRoot,
    pointer: &HistoryArchiveLocatorPointer,
    encrypted: &EncryptedHistoryArchiveObject,
) -> Result<HistoryArchiveLocatorPage, String> {
    if encrypted.version != 1 {
        return Err("Unsupported encrypted history locator page version".into());
    }
    let binding = HistoryArchiveEncryptionBinding {
        workspace_id: root.context.workspace_id.clone(),
        history_epoch: root.context.history_epoch,
        index_id: root.context.index_id.clone(),
        object_id: pointer.object_id.clone(),
        object_kind: "page".into(),
        part_index: 0,
        part_count: 1,
    };
    let bytes = open_history_archive_object(scope, &binding, &pointer.ciphertext_id, encrypted)?;
    verify_history_locator_page(root, pointer, &bytes)
}

#[cfg(test)]
mod tests;
