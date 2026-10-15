//! Reproduce the cross-runtime Native capture vector. Prints public test data only.
//! cargo run -p meta-mesh-core --example history_capture_fixture > packages/mesh-replication/fixtures/history-capture-v1.json
use automerge::{ActorId, AutoCommit, ROOT, transaction::Transactable};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use meta_mesh_core::{
    DEFAULT_SIGNATURE_DOMAIN, DeviceCertificatePayload, IncomingWorkspaceChangeAuthorization,
    WorkspaceAuthority, WorkspaceChangeAuthorization, WorkspaceChangeAuthorizationPayload,
    WorkspaceWriteAuthorizationSnapshot,
    causal_admission::CausalAdmissionInput,
    history_capture::{
        HistoryArchiveObjectBinding, HistoryArchiveWriter, HistoryOriginalEvidence,
        capture_workspace_history, history_control_value,
    },
    history_preparation::{HistoryPreparationSigner, prepare_workspace_history},
    public_key_from_seed, public_key_id, sign_device_certificate, sign_json_envelope,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Default)]
struct Store(BTreeMap<String, Value>);
impl HistoryArchiveWriter for Store {
    fn write(
        &mut self,
        id: &str,
        bytes: &[u8],
        binding: &HistoryArchiveObjectBinding,
    ) -> Result<(), String> {
        let key = meta_mesh_core::canonicalize_json(&json!({"objectId": id, "binding": binding}))?;
        self.0.insert(
            key,
            json!({"objectId": id, "bytes": URL_SAFE_NO_PAD.encode(bytes), "binding": binding}),
        );
        Ok(())
    }
}

fn main() -> Result<(), String> {
    let owner_seed = [151; 32];
    let device_seed = [152; 32];
    let public_key = public_key_from_seed(&owner_seed)?;
    let person_id = public_key_id(&public_key)?;
    let device_public_key = public_key_from_seed(&device_seed)?;
    let device_id = public_key_id(&device_public_key)?;
    let certificate = sign_device_certificate(
        &owner_seed,
        DeviceCertificatePayload {
            kind: "device-certificate".into(),
            version: 1,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
            device_public_key,
            issuer_certificate_hash: None,
            can_enroll_devices: true,
        },
        &person_id,
        DEFAULT_SIGNATURE_DOMAIN,
    )?;
    let owner = WorkspaceAuthority {
        person_id: person_id.clone(),
        public_key: public_key.clone(),
        certificates: vec![certificate.clone()],
    };
    let proof = |hashes: Vec<String>| -> Result<IncomingWorkspaceChangeAuthorization, String> {
        let payload = WorkspaceChangeAuthorizationPayload {
            kind: "workspace-changes".into(),
            version: 1,
            workspace_id: "native-capture-workspace".into(),
            hashes,
            person_id: person_id.clone(),
            device_id: device_id.clone(),
        };
        let signed = sign_json_envelope(
            &device_seed,
            serde_json::to_value(&payload).unwrap(),
            &device_id,
            DEFAULT_SIGNATURE_DOMAIN,
        )?;
        Ok(IncomingWorkspaceChangeAuthorization {
            signed: WorkspaceChangeAuthorization {
                payload,
                signer_key_id: signed.signer_key_id,
                signature: signed.signature,
            },
            public_key: public_key.clone(),
            certificates: vec![certificate.clone()],
            grant: None,
        })
    };
    let mut raw = AutoCommit::new().with_actor(ActorId::from(vec![153; 16]));
    raw.put(ROOT, "title", "Native admitted original")
        .map_err(|error| error.to_string())?;
    raw.commit();
    let admitted_hash = raw.get_heads()[0].to_string();
    let genesis_proof = proof(vec![admitted_hash.clone()])?;
    raw.put(ROOT, "title", "Unsigned overwrite remains quarantined")
        .unwrap();
    raw.commit();
    let quarantined_hash = raw.get_heads()[0].to_string();
    let document = raw.save();
    raw.put(ROOT, "missing", "This dependency is deliberately absent")
        .unwrap();
    raw.commit();
    raw.put(
        ROOT,
        "pending",
        "Keep compressed original unchanged. ".repeat(500),
    )
    .unwrap();
    raw.commit();
    let mut pending = raw.get_changes(&[]).last().unwrap().clone();
    let pending_hash = pending.hash().to_string();
    let pending_bytes = pending.bytes().into_owned();
    let source = CausalAdmissionInput {
        snapshot: WorkspaceWriteAuthorizationSnapshot {
            workspace_id: "native-capture-workspace".into(),
            genesis_owner: owner.clone(),
            genesis_epoch: 1,
            expected_current_owner: owner,
            document: document.clone(),
            ownership_transfers: vec![],
            succession_claims: vec![],
            revocations: vec![],
            device_revocations: vec![],
            departures: vec![],
        },
        records: vec![genesis_proof, proof(vec![pending_hash.clone()])?],
        pending_change_bytes: vec![pending_bytes.clone()],
        now_ms: 1_900_000_000_000,
    };
    let control = serde_json::to_vec_pretty(&history_control_value(&source.snapshot)?).unwrap();
    let mut originals = Vec::new();
    for record in &source.records {
        let mut value = serde_json::to_value(record).unwrap();
        value.as_object_mut().unwrap().remove("grant");
        let mut bytes = serde_json::to_vec_pretty(&value).unwrap();
        bytes.extend_from_slice(b" \n");
        originals.push(bytes);
    }
    let prepared = prepare_workspace_history(
        source,
        HistoryPreparationSigner {
            person_id: person_id.clone(),
            device_id,
            certificates: vec![certificate],
        },
    )?;
    let capture = capture_workspace_history(
        prepared,
        1,
        HistoryOriginalEvidence {
            control_json: control.clone(),
            authorization_json: originals.clone(),
        },
    )?;
    let mut store = Store::default();
    let catalogue = capture.write_catalogue(&mut store)?;
    let fixture = json!({ "catalogue": catalogue, "objects": store.0.into_values().collect::<Vec<_>>(),
        "originals": { "control": URL_SAFE_NO_PAD.encode(control), "authorizations": originals.iter().map(|value| URL_SAFE_NO_PAD.encode(value)).collect::<Vec<_>>(),
            "document": URL_SAFE_NO_PAD.encode(document), "pending": [URL_SAFE_NO_PAD.encode(pending_bytes)] },
        "expected": { "personId": person_id, "publicKey": public_key, "admittedHash": admitted_hash, "quarantinedHash": quarantined_hash, "pendingHash": pending_hash } });
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
    Ok(())
}
