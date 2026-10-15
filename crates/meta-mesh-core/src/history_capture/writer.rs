use crate::history_archive::*;
use serde::{Deserialize, Serialize};

const PART_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveBytesReference {
    pub kind: String,
    pub version: u8,
    pub root: HistoryArchiveIndexRoot,
    pub byte_length: u64,
    pub part_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveObjectBinding {
    #[serde(flatten)]
    pub context: HistoryArchiveTreeContext,
    pub object_kind: String,
    pub part_index: u64,
    pub part_count: u64,
}

/// The host stages exactly these Native-derived bytes and bindings. A successful
/// write is not storage coverage or permission to activate a history baseline.
pub trait HistoryArchiveWriter {
    fn write(
        &mut self,
        object_id: &str,
        bytes: &[u8],
        binding: &HistoryArchiveObjectBinding,
    ) -> Result<(), String>;
}

pub(super) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|_| "Invalid history archive encoding")?;
    Ok(crate::canonicalize_json(&value)?.into_bytes())
}

pub(super) fn object(
    writer: &mut impl HistoryArchiveWriter,
    context: &HistoryArchiveTreeContext,
    kind: &str,
    bytes: &[u8],
    part_index: u64,
    part_count: u64,
) -> Result<String, String> {
    if bytes.len() > PART_BYTES || kind != "part" && bytes.len() > MAX_HISTORY_ARCHIVE_PAGE_BYTES {
        return Err("Native archive object exceeds size limit".into());
    }
    let id = history_archive_object_id(bytes);
    writer.write(
        &id,
        bytes,
        &HistoryArchiveObjectBinding {
            context: context.clone(),
            object_kind: kind.into(),
            part_index,
            part_count,
        },
    )?;
    Ok(id)
}

/// Streaming fanout-64 tree builder: one bucket per height, no lifetime-sized
/// page list. Keys in this catalogue are ASCII and therefore share browser order.
pub(super) struct IndexBuilder {
    context: HistoryArchiveTreeContext,
    entries: Vec<HistoryArchiveIndexEntry>,
    levels: Vec<Vec<HistoryArchiveIndexRoot>>,
    previous: Option<String>,
}

impl IndexBuilder {
    pub(super) fn new(context: HistoryArchiveTreeContext) -> Result<Self, String> {
        valid_context(&context)?;
        Ok(Self {
            context,
            entries: Vec::new(),
            levels: Vec::new(),
            previous: None,
        })
    }

    pub(super) fn push(
        &mut self,
        key: String,
        object_id: String,
        writer: &mut impl HistoryArchiveWriter,
    ) -> Result<(), String> {
        if key.is_empty()
            || !key.is_ascii()
            || key.len() > MAX_HISTORY_ARCHIVE_KEY_BYTES
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| previous >= &key)
        {
            return Err("Invalid Native archive catalogue key order".into());
        }
        valid_digest(&object_id)?;
        self.previous = Some(key.clone());
        self.entries
            .push(HistoryArchiveIndexEntry { key, object_id });
        if self.entries.len() == MAX_HISTORY_ARCHIVE_CHILDREN {
            self.flush_leaf(writer)?;
        }
        Ok(())
    }

    fn flush_leaf(&mut self, writer: &mut impl HistoryArchiveWriter) -> Result<(), String> {
        let entries = std::mem::take(&mut self.entries);
        let page = HistoryArchiveLeaf {
            kind: "workspace-history-index-page".into(),
            version: 1,
            context: self.context.clone(),
            height: 0,
            entries,
        };
        let id = object(writer, &self.context, "page", &canonical(&page)?, 0, 1)?;
        self.push_root(
            0,
            HistoryArchiveIndexRoot {
                object_id: id,
                height: 0,
                count: page.entries.len() as u64,
                first: page.entries.first().map(|entry| entry.key.clone()),
                last: page.entries.last().map(|entry| entry.key.clone()),
            },
            writer,
        )
    }

    fn push_root(
        &mut self,
        level: usize,
        root: HistoryArchiveIndexRoot,
        writer: &mut impl HistoryArchiveWriter,
    ) -> Result<(), String> {
        if level >= MAX_HISTORY_ARCHIVE_DEPTH as usize {
            return Err("Native archive depth exceeded".into());
        }
        if self.levels.len() <= level {
            self.levels.resize_with(level + 1, Vec::new);
        }
        self.levels[level].push(root);
        if self.levels[level].len() == MAX_HISTORY_ARCHIVE_CHILDREN {
            self.flush_branch(level, writer)?;
        }
        Ok(())
    }

    fn flush_branch(
        &mut self,
        level: usize,
        writer: &mut impl HistoryArchiveWriter,
    ) -> Result<(), String> {
        let children = std::mem::take(&mut self.levels[level]);
        let height = (level + 1) as u8;
        if height >= MAX_HISTORY_ARCHIVE_DEPTH {
            return Err("Native archive depth exceeded".into());
        }
        let page = HistoryArchiveBranch {
            kind: "workspace-history-index-page".into(),
            version: 1,
            context: self.context.clone(),
            height,
            children,
        };
        let count = page
            .children
            .iter()
            .try_fold(0u64, |total, child| total.checked_add(child.count))
            .filter(|count| *count <= MAX_HISTORY_ARCHIVE_INTEGER)
            .ok_or("Native archive count exceeded")?;
        let id = object(writer, &self.context, "page", &canonical(&page)?, 0, 1)?;
        self.push_root(
            level + 1,
            HistoryArchiveIndexRoot {
                object_id: id,
                height,
                count,
                first: page.children.first().and_then(|child| child.first.clone()),
                last: page.children.last().and_then(|child| child.last.clone()),
            },
            writer,
        )
    }

    pub(super) fn finish(
        mut self,
        writer: &mut impl HistoryArchiveWriter,
    ) -> Result<HistoryArchiveIndexRoot, String> {
        if !self.entries.is_empty() || self.levels.iter().all(Vec::is_empty) {
            self.flush_leaf(writer)?;
        }
        loop {
            let level = self
                .levels
                .iter()
                .position(|bucket| !bucket.is_empty())
                .ok_or("Missing Native archive root")?;
            if self.levels[level].len() == 1
                && self.levels.iter().skip(level + 1).all(Vec::is_empty)
            {
                return Ok(self.levels[level].pop().unwrap());
            }
            self.flush_branch(level, writer)?;
        }
    }
}

pub(super) fn bytes(
    writer: &mut impl HistoryArchiveWriter,
    context: HistoryArchiveTreeContext,
    value: &[u8],
) -> Result<HistoryArchiveBytesReference, String> {
    let count = value.len().div_ceil(PART_BYTES) as u64;
    let mut index = IndexBuilder::new(context.clone())?;
    for (part, value) in value.chunks(PART_BYTES).enumerate() {
        let id = object(writer, &context, "part", value, part as u64, count)?;
        index.push(format!("{part:016x}"), id, writer)?;
    }
    Ok(HistoryArchiveBytesReference {
        kind: "workspace-history-bytes".into(),
        version: 1,
        root: index.finish(writer)?,
        byte_length: value.len() as u64,
        part_count: count,
    })
}
