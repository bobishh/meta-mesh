//! Purpose-bound archive transport; ciphertext integrity grants no historical write authority.
use crate::history_archive::{
    HistoryArchiveTreeContext, MAX_HISTORY_ARCHIVE_INTEGER, MAX_HISTORY_ARCHIVE_PAGE_BYTES,
    history_archive_object_id, valid_context, valid_digest,
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct HistoryArchiveEncryptionScope {
    pub scope_id: String,
    pub key_epoch: u64,
    pub key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryArchiveEncryptionBinding {
    pub workspace_id: String,
    pub history_epoch: u64,
    pub index_id: String,
    pub object_id: String,
    pub object_kind: String,
    pub part_index: u64,
    pub part_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedHistoryArchiveObject {
    pub version: u8,
    pub scope_id: String,
    pub key_epoch: u64,
    pub nonce: String,
    pub ciphertext: String,
}

/// Seal one Native-derived archive object after the host supplies a fresh
/// browser-generated nonce. Ciphertext, never plaintext, crosses the storage
/// sink boundary.
pub fn seal_history_archive_object(
    scope: &HistoryArchiveEncryptionScope,
    binding: &HistoryArchiveEncryptionBinding,
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<(String, EncryptedHistoryArchiveObject), String> {
    let maximum = validate_binding(scope, binding)?;
    if nonce.len() != 12 || plaintext.len() > maximum
        || history_archive_object_id(plaintext) != binding.object_id
    {
        return Err("Invalid archive plaintext, nonce, or binding".into());
    }
    let value = serde_json::to_value(binding).map_err(|_| "Invalid archive encryption binding")?;
    let mut value = value.as_object().cloned().ok_or("Invalid archive encryption binding")?;
    value.insert("purpose".into(), "archive".into());
    value.insert("scopeId".into(), scope.scope_id.clone().into());
    value.insert("keyEpoch".into(), scope.key_epoch.into());
    let aad = format!("MESH-HISTORY/1/archive-object\0{}", crate::canonicalize_json(&value.into())?);
    let ciphertext = Aes256Gcm::new_from_slice(&scope.key)
        .map_err(|_| "Invalid archive encryption key")?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: aad.as_bytes() })
        .map_err(|_| "Archive encryption failed")?;
    let object = EncryptedHistoryArchiveObject { version: 1, scope_id: scope.scope_id.clone(),
        key_epoch: scope.key_epoch, nonce: URL_SAFE_NO_PAD.encode(nonce), ciphertext: URL_SAFE_NO_PAD.encode(ciphertext) };
    let encoded = crate::canonicalize_json(&serde_json::to_value(&object).map_err(|_| "Invalid archive ciphertext envelope")?)?;
    Ok((history_archive_object_id(encoded.as_bytes()), object))
}

pub fn open_history_archive_object(
    scope: &HistoryArchiveEncryptionScope,
    binding: &HistoryArchiveEncryptionBinding,
    ciphertext_id: &str,
    object: &EncryptedHistoryArchiveObject,
) -> Result<Vec<u8>, String> {
    let maximum = validate_binding(scope, binding)?;
    valid_digest(ciphertext_id)?;
    if object.version != 1
        || object.scope_id != scope.scope_id
        || object.key_epoch != scope.key_epoch
    {
        return Err("Encrypted archive object scope or version mismatch".into());
    }
    let nonce = decode_bounded(&object.nonce, 12, 12)?;
    let ciphertext = decode_bounded(&object.ciphertext, 16, maximum + 16)?;
    let value = serde_json::to_value(object).map_err(|_| "Invalid archive ciphertext envelope")?;
    if history_archive_object_id(crate::canonicalize_json(&value)?.as_bytes()) != ciphertext_id {
        return Err("Archive ciphertext hash integrity failure".into());
    }
    let value = serde_json::to_value(binding).map_err(|_| "Invalid archive encryption binding")?;
    let mut value = value
        .as_object()
        .cloned()
        .ok_or("Invalid archive encryption binding")?;
    value.insert("purpose".into(), "archive".into());
    value.insert("scopeId".into(), scope.scope_id.clone().into());
    value.insert("keyEpoch".into(), scope.key_epoch.into());
    let aad = format!(
        "MESH-HISTORY/1/archive-object\0{}",
        crate::canonicalize_json(&value.into())?
    );
    let plaintext = Aes256Gcm::new_from_slice(&scope.key)
        .map_err(|_| "Invalid archive encryption key")?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "Archive ciphertext authentication failed")?;
    if history_archive_object_id(&plaintext) != binding.object_id {
        return Err("Archive plaintext hash integrity failure".into());
    }
    Ok(plaintext)
}

fn validate_binding(
    scope: &HistoryArchiveEncryptionScope,
    binding: &HistoryArchiveEncryptionBinding,
) -> Result<usize, String> {
    if scope.scope_id.is_empty()
        || scope.scope_id.len() > 128
        || !scope
            .scope_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        || scope.key_epoch == 0
        || scope.key_epoch > MAX_HISTORY_ARCHIVE_INTEGER
    {
        return Err("Invalid archive encryption scope".into());
    }
    valid_context(&HistoryArchiveTreeContext {
        workspace_id: binding.workspace_id.clone(),
        history_epoch: binding.history_epoch,
        index_id: binding.index_id.clone(),
    })?;
    valid_digest(&binding.object_id)?;
    if binding.part_count == 0
        || binding.part_count > MAX_HISTORY_ARCHIVE_INTEGER
        || binding.part_index >= binding.part_count
    {
        return Err("Invalid archive encryption part binding".into());
    }
    if binding.object_kind == "part" {
        return Ok(256 * 1024);
    }
    if !matches!(binding.object_kind.as_str(), "page" | "record")
        || binding.part_index != 0
        || binding.part_count != 1
    {
        return Err("Invalid archive encryption object kind or part binding".into());
    }
    Ok(MAX_HISTORY_ARCHIVE_PAGE_BYTES)
}

fn decode_bounded(value: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, String> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err("Archive ciphertext exceeds size limit".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "Invalid archive ciphertext encoding")?;
    if bytes.len() < minimum || bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("Non-canonical archive ciphertext encoding or size limit".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
