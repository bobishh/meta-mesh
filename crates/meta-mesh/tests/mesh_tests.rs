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
fn test_iroh_gossip_state_machine_direct() {
    use bytes::Bytes;
    use iroh_gossip::proto::{
        state::{InEvent, OutEvent, State},
        topic::{Command, Event},
        Config, PeerData, TopicId, Message,
    };
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct WireGossip {
        id: [u8; 32],
        content: Bytes,
        scope: WireDeliveryScope,
    }

    #[derive(Serialize, Deserialize)]
    enum WireDeliveryScope {
        Swarm(u16),
        Neighbors,
    }

    #[derive(Serialize, Deserialize)]
    enum WirePlumtreeMessage {
        Gossip(WireGossip),
        Prune,
    }

    #[derive(Serialize, Deserialize)]
    enum WireTopicMessage {
        Swarm(()),
        Gossip(WirePlumtreeMessage),
    }

    #[derive(Serialize, Deserialize)]
    struct WireMessage {
        topic: TopicId,
        message: WireTopicMessage,
    }

    let peer_a: [u8; 32] = [1u8; 32];
    let peer_b: [u8; 32] = [2u8; 32];
    let topic_id = TopicId::from_bytes([42u8; 32]);

    let mut state_b = State::new(peer_b, PeerData::default(), Config::default(), StdRng::seed_from_u64(2));
    let now = n0_future::time::Instant::now();

    // Peer B joins topic
    let _ = state_b.handle(InEvent::Command(topic_id, Command::Join(vec![])), now, None).collect::<Vec<_>>();

    // Create a broadcast wire message from Peer A
    let payload = b"hello from real iroh gossip";
    let msg_id = *blake3::hash(payload).as_bytes();
    let wire_msg = WireMessage {
        topic: topic_id,
        message: WireTopicMessage::Gossip(WirePlumtreeMessage::Gossip(WireGossip {
            id: msg_id,
            content: Bytes::copy_from_slice(payload),
            scope: WireDeliveryScope::Swarm(0),
        })),
    };

    let encoded = postcard::to_stdvec(&wire_msg).expect("serialize wire msg");

    // Deserialize as real iroh_gossip::proto::Message
    let iroh_msg: Message<[u8; 32]> = postcard::from_bytes(&encoded).expect("deserialize as real iroh_gossip message");

    // Peer B handles the received message in State!
    let out_events: Vec<OutEvent<[u8; 32]>> = state_b.handle(InEvent::RecvMessage(peer_a, iroh_msg.clone()), now, None).collect();

    let mut received_content = None;
    for event in out_events {
        if let OutEvent::EmitEvent(t, Event::Received(gossip_ev)) = event {
            assert_eq!(t, topic_id);
            received_content = Some(gossip_ev.content);
        }
    }

    assert_eq!(received_content.as_deref(), Some(&payload[..]));

    // Sending duplicate to Peer B state machine suppresses it!
    let out_dup: Vec<OutEvent<[u8; 32]>> = state_b.handle(InEvent::RecvMessage(peer_a, iroh_msg), now, None).collect();
    let received_dup = out_dup.iter().any(|e| matches!(e, OutEvent::EmitEvent(_, Event::Received(_))));
    assert!(!received_dup, "Real iroh-gossip state machine must suppress duplicate message!");
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
