use super::*;
use crate::{
    DeviceCertificatePayload, public_key_from_seed, public_key_id, sign_device_certificate,
};

#[test]
fn given_owner_named_certificate_signed_by_foreign_root_when_preparing_then_reject_chain() {
    let mut f = fixture();
    let foreign_seed = [124; 32];
    let foreign_person = public_key_id(&public_key_from_seed(&foreign_seed).unwrap()).unwrap();
    let cert = sign_device_certificate(
        &foreign_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: f.signer.person_id.clone(),
            device_id: f.signer.device_id.clone(),
            device_public_key: public_key_from_seed(&f.device_seed).unwrap(),
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &foreign_person,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    f.signer.certificates = vec![cert];

    let result = prepare_workspace_history(f.source, f.signer);
    assert!(
        result.is_err(),
        "accepted a signer chain rooted outside current owner identity"
    );
}

#[test]
fn given_valid_foreign_identity_and_device_certificate_when_preparing_then_reject_nonowner() {
    let mut f = fixture();
    let foreign_seed = [125; 32];
    let foreign_public = public_key_from_seed(&foreign_seed).unwrap();
    let foreign_person = public_key_id(&foreign_public).unwrap();
    let device_seed = [126; 32];
    let device_public = public_key_from_seed(&device_seed).unwrap();
    let device_id = public_key_id(&device_public).unwrap();
    let cert = sign_device_certificate(
        &foreign_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: foreign_person.clone(),
            device_id: device_id.clone(),
            device_public_key: device_public,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &foreign_person,
        DEFAULT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    f.signer = HistoryPreparationSigner {
        person_id: foreign_person,
        device_id,
        certificates: vec![cert],
    };

    let result = prepare_workspace_history(f.source, f.signer);
    assert!(
        result.is_err(),
        "accepted a valid signer who is not current workspace owner"
    );
}

#[test]
fn given_record_count_over_preparation_bound_when_preparing_then_reject_before_admission() {
    let mut f = fixture();
    let record = f.source.records[0].clone();
    f.source.records = vec![record; 20_001];

    let result = prepare_workspace_history(f.source, f.signer);
    assert!(matches!(result, Err(error) if error.contains("evidence exceeds size limit")));
}
