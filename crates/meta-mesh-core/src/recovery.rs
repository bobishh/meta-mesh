use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bip39::{Language, Mnemonic};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{canonicalize_json, public_key_from_seed, public_key_id};

pub const RECOVERY_KDF_ITERATIONS: u32 = 600_000;
const EFF_LONG_WORDS: &str = include_str!("eff-long.txt");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentitySecurity {
    Legacy,
    Better,
    Insane,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryKdf {
    pub name: String,
    pub hash: String,
    pub iterations: u32,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCipher {
    pub name: String,
    pub iv: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecoveryEnvelope {
    pub kind: String,
    pub version: u8,
    pub person_id: String,
    pub security: IdentitySecurity,
    pub kdf: RecoveryKdf,
    pub cipher: RecoveryCipher,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityPassphraseEnvelope {
    pub kind: String,
    pub version: u8,
    pub person_id: String,
    pub kdf: RecoveryKdf,
    pub cipher: RecoveryCipher,
    pub ciphertext: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryHeader<'a> {
    kind: &'a str,
    version: u8,
    person_id: &'a str,
    security: IdentitySecurity,
    kdf: &'a RecoveryKdf,
    cipher: &'a RecoveryCipher,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PassphraseHeader<'a> {
    kind: &'a str,
    version: u8,
    person_id: &'a str,
    kdf: &'a RecoveryKdf,
    cipher: &'a RecoveryCipher,
}

pub fn normalize_secret(value: &str) -> String {
    value
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn identity_security_for_recovery(value: &str) -> Option<IdentitySecurity> {
    let normalized = normalize_secret(value);
    if validate_recovery_key(&normalized, IdentitySecurity::Legacy).is_ok() {
        return Some(IdentitySecurity::Legacy);
    }
    if validate_recovery_key(&normalized, IdentitySecurity::Better).is_ok() {
        return Some(IdentitySecurity::Better);
    }
    if validate_recovery_key(&normalized, IdentitySecurity::Insane).is_ok() {
        return Some(IdentitySecurity::Insane);
    }
    None
}

pub fn recovery_phrase_from_entropy(entropy: &[u8]) -> Result<String, String> {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .map(|mnemonic| mnemonic.to_string())
        .map_err(|_| "Invalid recovery entropy".to_string())
}

pub fn recovery_phrase_to_entropy(value: &str) -> Result<Vec<u8>, String> {
    Mnemonic::parse_in(Language::English, normalize_secret(value))
        .map(|mnemonic| mnemonic.to_entropy())
        .map_err(|_| "Invalid identity recovery".to_string())
}

pub fn legacy_recovery_from_samples(samples: &[u16]) -> Result<String, String> {
    const WORD_COUNT: usize = 7_776;
    const UNBIASED_LIMIT: usize = (u16::MAX as usize + 1) / WORD_COUNT * WORD_COUNT;
    let words = EFF_LONG_WORDS.lines().collect::<Vec<_>>();
    let selected = samples
        .iter()
        .copied()
        .filter(|sample| usize::from(*sample) < UNBIASED_LIMIT)
        .take(4)
        .map(|sample| words[usize::from(sample) % WORD_COUNT])
        .collect::<Vec<_>>();
    if selected.len() != 4 {
        return Err("Not enough unbiased recovery entropy".to_string());
    }
    Ok(selected.join(" "))
}

pub fn seal_identity_seed(
    identity_seed: &[u8; 32],
    person_id: &str,
    recovery_key: &str,
    security: IdentitySecurity,
    salt: &[u8; 16],
    iv: &[u8; 12],
) -> Result<IdentityRecoveryEnvelope, String> {
    validate_identity_seed(identity_seed, person_id)?;
    validate_recovery_key(recovery_key, security)?;
    let kdf = recovery_kdf(salt);
    let cipher = recovery_cipher(iv);
    let header = RecoveryHeader {
        kind: "mesh-identity-recovery",
        version: 3,
        person_id,
        security,
        kdf: &kdf,
        cipher: &cipher,
    };
    let aad = canonical_header(&header)?;
    let ciphertext = encrypt_seed(identity_seed, recovery_key, salt, iv, &aad)?;
    Ok(IdentityRecoveryEnvelope {
        kind: header.kind.to_string(),
        version: header.version,
        person_id: person_id.to_string(),
        security,
        kdf,
        cipher,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn open_identity_seed(
    envelope: &IdentityRecoveryEnvelope,
    recovery_key: &str,
) -> Result<[u8; 32], String> {
    let result: Result<[u8; 32], String> = (|| {
        validate_recovery_envelope(envelope)?;
        validate_recovery_key(recovery_key, envelope.security)?;
        let salt = decode_exact::<16>(&envelope.kdf.salt, "Invalid identity recovery envelope")?;
        let iv = decode_exact::<12>(&envelope.cipher.iv, "Invalid identity recovery envelope")?;
        let header = RecoveryHeader {
            kind: &envelope.kind,
            version: envelope.version,
            person_id: &envelope.person_id,
            security: envelope.security,
            kdf: &envelope.kdf,
            cipher: &envelope.cipher,
        };
        let aad = canonical_header(&header)?;
        let seed = decrypt_seed(&envelope.ciphertext, recovery_key, &salt, &iv, &aad)?;
        validate_identity_seed(&seed, &envelope.person_id)?;
        Ok(seed)
    })();
    result.map_err(|_| "Recovery words do not open this identity".to_string())
}

pub fn seal_identity_seed_with_passphrase(
    identity_seed: &[u8; 32],
    person_id: &str,
    passphrase: &str,
    salt: &[u8; 16],
    iv: &[u8; 12],
) -> Result<IdentityPassphraseEnvelope, String> {
    validate_identity_seed(identity_seed, person_id)?;
    let passphrase = validate_passphrase(passphrase)?;
    let kdf = recovery_kdf(salt);
    let cipher = recovery_cipher(iv);
    let header = PassphraseHeader {
        kind: "mesh-identity-passphrase",
        version: 1,
        person_id,
        kdf: &kdf,
        cipher: &cipher,
    };
    let aad = canonical_header(&header)?;
    let ciphertext = encrypt_seed(identity_seed, &passphrase, salt, iv, &aad)?;
    Ok(IdentityPassphraseEnvelope {
        kind: header.kind.to_string(),
        version: header.version,
        person_id: person_id.to_string(),
        kdf,
        cipher,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn open_identity_seed_with_passphrase(
    envelope: &IdentityPassphraseEnvelope,
    passphrase: &str,
) -> Result<[u8; 32], String> {
    let result: Result<[u8; 32], String> = (|| {
        validate_passphrase_envelope(envelope)?;
        let passphrase = validate_passphrase(passphrase)?;
        let salt = decode_exact::<16>(&envelope.kdf.salt, "Invalid identity passphrase envelope")?;
        let iv = decode_exact::<12>(&envelope.cipher.iv, "Invalid identity passphrase envelope")?;
        let header = PassphraseHeader {
            kind: &envelope.kind,
            version: envelope.version,
            person_id: &envelope.person_id,
            kdf: &envelope.kdf,
            cipher: &envelope.cipher,
        };
        let aad = canonical_header(&header)?;
        let seed = decrypt_seed(&envelope.ciphertext, &passphrase, &salt, &iv, &aad)?;
        validate_identity_seed(&seed, &envelope.person_id)?;
        Ok(seed)
    })();
    result.map_err(|_| "Passphrase does not open this identity".to_string())
}

fn validate_identity_seed(seed: &[u8; 32], person_id: &str) -> Result<(), String> {
    let derived = public_key_id(&public_key_from_seed(seed)?)?;
    if derived != person_id {
        return Err("Identity root does not match person ID".to_string());
    }
    Ok(())
}

fn validate_recovery_key(value: &str, security: IdentitySecurity) -> Result<String, String> {
    let normalized = normalize_secret(value);
    let words = normalized.split(' ').collect::<Vec<_>>();
    let valid = match security {
        IdentitySecurity::Legacy => {
            words.len() == 4
                && words
                    .iter()
                    .all(|word| EFF_LONG_WORDS.lines().any(|candidate| candidate == *word))
        }
        IdentitySecurity::Better => {
            words.len() == 12 && Mnemonic::parse_in(Language::English, &normalized).is_ok()
        }
        IdentitySecurity::Insane => {
            words.len() == 24 && Mnemonic::parse_in(Language::English, &normalized).is_ok()
        }
    };
    if !valid {
        return Err("Invalid identity recovery".to_string());
    }
    Ok(normalized)
}

fn validate_passphrase(value: &str) -> Result<String, String> {
    let normalized = normalize_secret(value);
    if normalized.is_empty() {
        Err("Passphrase is empty".to_string())
    } else {
        Ok(normalized)
    }
}

fn validate_recovery_envelope(envelope: &IdentityRecoveryEnvelope) -> Result<(), String> {
    if envelope.kind != "mesh-identity-recovery"
        || envelope.version != 3
        || envelope.person_id.is_empty()
        || !valid_kdf_and_cipher(&envelope.kdf, &envelope.cipher)
        || URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| "Invalid identity recovery envelope".to_string())?
            .len()
            != 48
    {
        return Err("Invalid identity recovery envelope".to_string());
    }
    Ok(())
}

fn validate_passphrase_envelope(envelope: &IdentityPassphraseEnvelope) -> Result<(), String> {
    if envelope.kind != "mesh-identity-passphrase"
        || envelope.version != 1
        || envelope.person_id.is_empty()
        || !valid_kdf_and_cipher(&envelope.kdf, &envelope.cipher)
        || URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| "Invalid identity passphrase envelope".to_string())?
            .len()
            != 48
    {
        return Err("Invalid identity passphrase envelope".to_string());
    }
    Ok(())
}

fn valid_kdf_and_cipher(kdf: &RecoveryKdf, cipher: &RecoveryCipher) -> bool {
    kdf.name == "PBKDF2"
        && kdf.hash == "SHA-256"
        && kdf.iterations == RECOVERY_KDF_ITERATIONS
        && URL_SAFE_NO_PAD
            .decode(&kdf.salt)
            .is_ok_and(|bytes| bytes.len() == 16)
        && cipher.name == "AES-GCM"
        && URL_SAFE_NO_PAD
            .decode(&cipher.iv)
            .is_ok_and(|bytes| bytes.len() == 12)
}

fn recovery_kdf(salt: &[u8; 16]) -> RecoveryKdf {
    RecoveryKdf {
        name: "PBKDF2".to_string(),
        hash: "SHA-256".to_string(),
        iterations: RECOVERY_KDF_ITERATIONS,
        salt: URL_SAFE_NO_PAD.encode(salt),
    }
}

fn recovery_cipher(iv: &[u8; 12]) -> RecoveryCipher {
    RecoveryCipher {
        name: "AES-GCM".to_string(),
        iv: URL_SAFE_NO_PAD.encode(iv),
    }
}

fn derive_key(secret: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0; 32];
    pbkdf2_hmac::<Sha256>(secret.as_bytes(), salt, RECOVERY_KDF_ITERATIONS, &mut key);
    key
}

fn encrypt_seed(
    seed: &[u8; 32],
    secret: &str,
    salt: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive_key(&normalize_secret(secret), salt);
    Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Identity encryption failed".to_string())?
        .encrypt(Nonce::from_slice(iv), Payload { msg: seed, aad })
        .map_err(|_| "Identity encryption failed".to_string())
}

fn decrypt_seed(
    ciphertext: &str,
    secret: &str,
    salt: &[u8; 16],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<[u8; 32], String> {
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| "Identity decryption failed".to_string())?;
    let key = derive_key(&normalize_secret(secret), salt);
    let plaintext = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Identity decryption failed".to_string())?
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .map_err(|_| "Identity decryption failed".to_string())?;
    plaintext
        .try_into()
        .map_err(|_| "Identity decryption failed".to_string())
}

fn canonical_header(header: &impl Serialize) -> Result<Vec<u8>, String> {
    let value =
        serde_json::to_value(header).map_err(|_| "Identity envelope invalid".to_string())?;
    Ok(canonicalize_json(&value)?.into_bytes())
}

fn decode_exact<const N: usize>(value: &str, error: &str) -> Result<[u8; N], String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| error.to_string())?
        .try_into()
        .map_err(|_| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECOVERY_KEY: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn recovery_envelope_matches_webcrypto_golden_vector() {
        let seed = std::array::from_fn(|index| index as u8 + 1);
        let person_id = public_key_id(&public_key_from_seed(&seed).unwrap()).unwrap();
        let salt = std::array::from_fn(|index| index as u8);
        let iv = std::array::from_fn(|index| index as u8 + 16);
        let envelope = seal_identity_seed(
            &seed,
            &person_id,
            RECOVERY_KEY,
            IdentitySecurity::Better,
            &salt,
            &iv,
        )
        .unwrap();
        assert_eq!(person_id, "ZbYGc9btiEvwHCwiLYKtoHQPKawzVdapJcgfF_R6J7g");
        assert_eq!(
            envelope.ciphertext,
            "Uw1-BCfCKhjZemXZWPmTdfJg2X8ljVaRZ8OC2RuHtkW53fJ-EW5ih5A2Rj07xENT"
        );
        assert_eq!(open_identity_seed(&envelope, RECOVERY_KEY).unwrap(), seed);
        assert_eq!(
            open_identity_seed(
                &envelope,
                "legal winner thank year wave sausage worth useful legal winner thank yellow"
            )
            .unwrap_err(),
            "Recovery words do not open this identity"
        );
    }

    #[test]
    fn passphrase_envelope_round_trips_and_binds_person_id() {
        let seed = [73; 32];
        let person_id = public_key_id(&public_key_from_seed(&seed).unwrap()).unwrap();
        let envelope = seal_identity_seed_with_passphrase(
            &seed,
            &person_id,
            "  Correct Horse Battery Staple  ",
            &[9; 16],
            &[7; 12],
        )
        .unwrap();
        assert_eq!(
            open_identity_seed_with_passphrase(&envelope, "correct horse battery staple").unwrap(),
            seed
        );
        assert_eq!(
            open_identity_seed_with_passphrase(&envelope, "wrong passphrase").unwrap_err(),
            "Passphrase does not open this identity"
        );
    }

    #[test]
    fn legacy_recovery_requires_four_eff_long_words() {
        assert!(
            validate_recovery_key("abacus abdomen abdominal abide", IdentitySecurity::Legacy)
                .is_ok()
        );
        assert!(
            validate_recovery_key(
                "abacus abdomen abdominal definitely-not-eff",
                IdentitySecurity::Legacy
            )
            .is_err()
        );
        assert_eq!(
            legacy_recovery_from_samples(&[0, 1, 7_775, 7_776]).unwrap(),
            "abacus abdomen zoom abacus"
        );
        assert_eq!(
            identity_security_for_recovery("abacus abdomen zoom abacus"),
            Some(IdentitySecurity::Legacy)
        );
    }

    #[test]
    fn bip39_entropy_round_trips_with_security_classification() {
        let entropy = [0; 16];
        let phrase = recovery_phrase_from_entropy(&entropy).unwrap();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(recovery_phrase_to_entropy(&phrase).unwrap(), entropy);
        assert_eq!(
            identity_security_for_recovery(&phrase),
            Some(IdentitySecurity::Better)
        );
    }
}
