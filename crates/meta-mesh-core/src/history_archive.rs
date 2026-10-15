//! Archive object integrity is distinct from original author and causal admission.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, collections::HashSet};

pub const MAX_HISTORY_ARCHIVE_PAGE_BYTES: usize = 64 * 1024;
pub const MAX_HISTORY_ARCHIVE_CHILDREN: usize = 64;
pub const MAX_HISTORY_ARCHIVE_DEPTH: u8 = 32;
pub const MAX_HISTORY_ARCHIVE_KEY_BYTES: usize = 512;
pub const MAX_HISTORY_ARCHIVE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveTreeContext {
    pub workspace_id: String,
    pub history_epoch: u64,
    pub index_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveIndexRoot {
    pub object_id: String,
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
pub struct HistoryArchiveIndexEntry {
    pub key: String,
    pub object_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveLeaf {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub height: u8,
    pub entries: Vec<HistoryArchiveIndexEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveBranch {
    pub kind: String,
    pub version: u8,
    pub context: HistoryArchiveTreeContext,
    pub height: u8,
    pub children: Vec<HistoryArchiveIndexRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HistoryArchiveIndexPage {
    Leaf(HistoryArchiveLeaf),
    Branch(HistoryArchiveBranch),
}

pub fn history_archive_object_id(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

pub(crate) fn valid_digest(value: &str) -> Result<(), String> {
    if value.len() != 43 {
        return Err("Invalid archive object hash".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Invalid archive object hash")?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err("Non-canonical archive object hash".into());
    }
    Ok(())
}

fn valid_text(value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum {
        return Err("Invalid archive key or context".into());
    }
    Ok(())
}

pub(crate) fn valid_context(value: &HistoryArchiveTreeContext) -> Result<(), String> {
    valid_text(&value.workspace_id, 256)?;
    valid_text(&value.index_id, 128)?;
    if value.history_epoch == 0 || value.history_epoch > MAX_HISTORY_ARCHIVE_INTEGER {
        return Err("Invalid archive epoch".into());
    }
    Ok(())
}

// Browser string order uses UTF-16 code units; Rust scalar/UTF-8 order differs for astral keys.
fn key_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn valid_root(value: &HistoryArchiveIndexRoot) -> Result<(), String> {
    valid_digest(&value.object_id)?;
    if value.height >= MAX_HISTORY_ARCHIVE_DEPTH || value.count > MAX_HISTORY_ARCHIVE_INTEGER {
        return Err("Invalid archive root height/count".into());
    }
    if value.count == 0 {
        if value.height != 0 || value.first.is_some() || value.last.is_some() {
            return Err("Invalid empty archive root metadata".into());
        }
    } else {
        let first = value.first.as_deref().ok_or("Missing archive root range")?;
        let last = value.last.as_deref().ok_or("Missing archive root range")?;
        valid_text(first, MAX_HISTORY_ARCHIVE_KEY_BYTES)?;
        valid_text(last, MAX_HISTORY_ARCHIVE_KEY_BYTES)?;
        if key_order(first, last) == Ordering::Greater {
            return Err("Invalid archive root range".into());
        }
    }
    Ok(())
}

fn page_root(
    page: &HistoryArchiveIndexPage,
    object_id: String,
) -> Result<HistoryArchiveIndexRoot, String> {
    let root = match page {
        HistoryArchiveIndexPage::Leaf(leaf) => HistoryArchiveIndexRoot {
            object_id,
            height: 0,
            count: leaf.entries.len() as u64,
            first: leaf.entries.first().map(|entry| entry.key.clone()),
            last: leaf.entries.last().map(|entry| entry.key.clone()),
        },
        HistoryArchiveIndexPage::Branch(branch) => {
            let count = branch
                .children
                .iter()
                .try_fold(0u64, |sum, child| sum.checked_add(child.count))
                .filter(|count| *count <= MAX_HISTORY_ARCHIVE_INTEGER)
                .ok_or("Archive count exceeds safe integer bound")?;
            HistoryArchiveIndexRoot {
                object_id,
                height: branch.height,
                count,
                first: branch
                    .children
                    .first()
                    .and_then(|child| child.first.clone()),
                last: branch.children.last().and_then(|child| child.last.clone()),
            }
        }
    };
    valid_root(&root)?;
    Ok(root)
}

fn valid_page(
    page: &HistoryArchiveIndexPage,
    expected: &HistoryArchiveTreeContext,
) -> Result<(), String> {
    let (kind, version, context) = match page {
        HistoryArchiveIndexPage::Leaf(leaf) => (&leaf.kind, leaf.version, &leaf.context),
        HistoryArchiveIndexPage::Branch(branch) => (&branch.kind, branch.version, &branch.context),
    };
    if kind != "workspace-history-index-page" || version != 1 {
        return Err("Unsupported archive page schema/version".into());
    }
    if context != expected {
        return Err("Archive page context does not match scope".into());
    }
    match page {
        HistoryArchiveIndexPage::Leaf(leaf) => {
            if leaf.height != 0 || leaf.entries.len() > MAX_HISTORY_ARCHIVE_CHILDREN {
                return Err("Invalid archive leaf height/size".into());
            }
            for (index, entry) in leaf.entries.iter().enumerate() {
                valid_text(&entry.key, MAX_HISTORY_ARCHIVE_KEY_BYTES)?;
                valid_digest(&entry.object_id)?;
                if index > 0
                    && key_order(&leaf.entries[index - 1].key, &entry.key) != Ordering::Less
                {
                    return Err("Invalid archive key order".into());
                }
            }
        }
        HistoryArchiveIndexPage::Branch(branch) => {
            if branch.height == 0
                || branch.height >= MAX_HISTORY_ARCHIVE_DEPTH
                || branch.children.is_empty()
                || branch.children.len() > MAX_HISTORY_ARCHIVE_CHILDREN
            {
                return Err("Invalid archive branch height/size".into());
            }
            let mut seen = HashSet::new();
            for (index, child) in branch.children.iter().enumerate() {
                valid_root(child)?;
                if child.count == 0
                    || child.height != branch.height - 1
                    || !seen.insert(&child.object_id)
                {
                    return Err("Invalid archive child metadata".into());
                }
                if index > 0
                    && key_order(
                        branch.children[index - 1].last.as_deref().unwrap(),
                        child.first.as_deref().unwrap(),
                    ) != Ordering::Less
                {
                    return Err("Invalid overlapping archive ranges".into());
                }
            }
        }
    }
    Ok(())
}

/// Verifies content and index metadata only. The caller still needs original signatures and causal policy before claiming historical admission.
pub fn verify_history_archive_index_page(
    context: &HistoryArchiveTreeContext,
    root: &HistoryArchiveIndexRoot,
    bytes: &[u8],
) -> Result<HistoryArchiveIndexPage, String> {
    valid_context(context)?;
    valid_root(root)?;
    if bytes.len() > MAX_HISTORY_ARCHIVE_PAGE_BYTES {
        return Err("Archive page exceeds byte limit".into());
    }
    if history_archive_object_id(bytes) != root.object_id {
        return Err("Archive page hash integrity failure".into());
    }
    let page: HistoryArchiveIndexPage =
        serde_json::from_slice(bytes).map_err(|_| "Invalid archive page schema")?;
    valid_page(&page, context)?;
    let value = serde_json::to_value(&page).map_err(|_| "Invalid archive page encoding")?;
    let canonical = crate::canonicalize_json(&value)?;
    if canonical.as_bytes() != bytes {
        return Err("Non-canonical archive page encoding".into());
    }
    if page_root(&page, root.object_id.clone())? != *root {
        return Err("Archive root metadata does not match page".into());
    }
    Ok(page)
}

#[cfg(test)]
mod tests;
