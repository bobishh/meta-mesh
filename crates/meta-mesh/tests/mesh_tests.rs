use meta_mesh::{
    blobs::BlobEngine,
    gossip::GossipEngine,
};

#[test]
fn test_gossip_topic_and_broadcast() {
    let mut engine = GossipEngine::new("local-node-1");
    let topic_id = engine.join_topic("workspace-123", vec!["peer-a".to_string()]).expect("join topic failed");
    assert_eq!(topic_id.len(), 64); // 32-byte hex hash

    let msg = b"change-hash-abc";
    let packet = engine.broadcast("workspace-123", msg).expect("broadcast failed");
    assert!(!packet.is_empty());

    // Deliver to peer engine
    let mut peer_engine = GossipEngine::new("peer-a");
    peer_engine.join_topic("workspace-123", vec!["local-node-1".to_string()]).expect("peer join failed");
    let delivered = peer_engine.handle_message("local-node-1", &packet).expect("handle failed");
    assert_eq!(delivered.as_deref(), Some(&msg[..]));

    // Duplicate message delivery suppression
    let dup = peer_engine.handle_message("local-node-1", &packet).expect("handle dup failed");
    assert!(dup.is_none(), "Duplicate message must be suppressed");
}

#[test]
fn test_blob_engine_storage_and_verification() {
    let engine = BlobEngine::new();
    let data = b"Hello from iroh-blobs test data for p2p sync";
    let desc = engine.create_blob(data, "test.txt", "text/plain", Some("node-endpoint-123")).expect("create blob failed");

    assert_eq!(desc.name, "test.txt");
    assert_eq!(desc.media_type, "text/plain");
    assert_eq!(desc.size, data.len());
    assert!(!desc.hash.is_empty());
    assert!(!desc.ticket.is_empty());

    // Verify presence and read back
    assert!(engine.has_blob(&desc.hash));
    let retrieved = engine.get_blob(&desc.hash).expect("get blob failed").expect("blob not found");
    assert_eq!(retrieved, data);

    // Verify valid bytes vs corrupted bytes
    assert!(engine.verify_blob(&desc.hash, data).expect("verification failed"));
    assert!(!engine.verify_blob(&desc.hash, b"corrupted data").expect("verification failed"));
}

#[test]
fn test_blob_ticket_parsing() {
    let engine = BlobEngine::new();
    let data = b"Sample artifact content";
    let desc = engine.create_blob(data, "sample.pdf", "application/pdf", Some("node-endpoint-abc")).expect("create blob failed");
    let parsed = BlobEngine::parse_ticket(&desc.ticket).expect("parse ticket failed");
    assert_eq!(parsed.hash, desc.hash);
    assert_eq!(parsed.node, "node-endpoint-abc");
}
