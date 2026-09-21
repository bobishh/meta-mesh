use meta_mesh::{blobs::BlobEngine, gossip::GossipEngine};
use std::collections::{HashMap, VecDeque};

fn drive_gossip(
    engines: &HashMap<String, GossipEngine>,
    initial: Vec<(String, meta_mesh::gossip::GossipStep)>,
) -> Vec<(String, Vec<u8>)> {
    let mut queue = VecDeque::from(initial);
    let mut delivered = Vec::new();
    let mut steps = 0;
    while let Some((sender, step)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 1_000, "gossip driver did not settle");
        delivered.extend(
            step.deliveries
                .into_iter()
                .map(|delivery| (delivery.topic, delivery.content)),
        );
        for send in step.sends {
            let receiver = engines
                .get(&send.peer)
                .unwrap_or_else(|| panic!("missing gossip peer {}", send.peer));
            let next = receiver
                .handle_message(&sender, &send.packet)
                .expect("peer handles gossip packet");
            queue.push_back((send.peer, next));
        }
    }
    delivered
}

#[test]
fn browser_gossip_driver_forwards_multi_hop_and_suppresses_duplicates() {
    // Given three browser protocol engines joined as A <-> B <-> C.
    let mut a = GossipEngine::new("peer-a");
    let mut b = GossipEngine::new("peer-b");
    let mut c = GossipEngine::new("peer-c");
    let joins = vec![
        (
            "peer-a".into(),
            a.join_topic("workspace-123", vec!["peer-b".into()])
                .expect("A joins"),
        ),
        (
            "peer-b".into(),
            b.join_topic("workspace-123", vec!["peer-a".into(), "peer-c".into()])
                .expect("B joins"),
        ),
        (
            "peer-c".into(),
            c.join_topic("workspace-123", vec!["peer-b".into()])
                .expect("C joins"),
        ),
    ];
    assert_eq!(joins[0].1.topic_id.as_ref().unwrap().len(), 64);
    let engines = HashMap::from([
        ("peer-a".into(), a.clone()),
        ("peer-b".into(), b.clone()),
        ("peer-c".into(), c.clone()),
    ]);
    drive_gossip(&engines, joins);

    // When A broadcasts and every state-machine send/forward action is driven.
    let payload = b"change-hash-abc";
    let step = a
        .broadcast("workspace-123", payload)
        .expect("broadcast failed");
    assert!(!step.sends.is_empty());
    let first_packet = step.sends[0].packet.clone();
    assert_eq!(
        hex::encode(&first_packet),
        "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f0100ca3a7f2ff410a9bf3800173f61d7fa30956d12afefbcffb537f0fb563c36e88c0f6368616e67652d686173682d6162630000"
    );
    let delivered = drive_gossip(&engines, vec![("peer-a".into(), step)]);

    // Then both downstream peers receive exact bytes, while replay is suppressed.
    assert_eq!(
        delivered
            .iter()
            .filter(|(_, content)| content.as_slice() == payload)
            .count(),
        2
    );
    let replay = b
        .handle_message("peer-a", &first_packet)
        .expect("handle duplicate");
    assert!(replay.deliveries.is_empty());
}

#[test]
fn browser_gossip_driver_exposes_and_expires_protocol_timers() {
    // Given joining emits opaque protocol timers for the browser runtime.
    let mut engine = GossipEngine::new("peer-a");
    let joined = engine
        .join_topic("workspace-123", vec!["peer-b".into()])
        .expect("join topic");
    let timer = joined
        .timers
        .first()
        .expect("join schedules a timer")
        .clone();

    // When the runtime returns that timer to the state machine.
    let _ = engine
        .expire_timer(timer.timer_id)
        .expect("timer expiration succeeds");

    // Then replaying the same runtime timer is an idempotent no-op.
    assert_eq!(
        engine.expire_timer(timer.timer_id).unwrap(),
        meta_mesh::gossip::GossipStep::default()
    );
}

#[test]
fn browser_098_reads_native_0101_join_and_gossip_fixtures() {
    // Given the browser joins a topic and receives the exact native 0.101 join packet.
    let mut browser = GossipEngine::new("peer-a");
    browser.join_topic("workspace-123", vec![]).unwrap();
    let native_join = hex::decode(
        "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f00000106706565722d62",
    )
    .unwrap();
    let joined = browser.handle_message("peer-b", &native_join).unwrap();
    assert_eq!(
        hex::encode(&joined.sends[0].packet),
        "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f0004000106706565722d61"
    );

    // When the exact native 0.101 gossip packet enters browser 0.98.
    let native_gossip = hex::decode(
        "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f010059e61a6028fb3158df6670e071b9db844f506196a75074519a85f19fe60fe254116e61746976652d746f2d62726f777365720000",
    )
    .unwrap();
    let received = browser.handle_message("peer-b", &native_gossip).unwrap();

    // Then browser delivers exact native content.
    assert_eq!(received.deliveries.len(), 1);
    assert_eq!(received.deliveries[0].content, b"native-to-browser");
}

#[test]
fn test_iroh_gossip_state_machine_direct() {
    use bytes::Bytes;
    use iroh_gossip::proto::{
        Config, Message, PeerData, TopicId,
        state::{InEvent, OutEvent, State},
        topic::{Command, Event},
    };
    use rand::SeedableRng;
    use rand::rngs::StdRng;
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

    let mut state_b = State::new(
        peer_b,
        PeerData::default(),
        Config::default(),
        StdRng::seed_from_u64(2),
    );
    let now = n0_future::time::Instant::now();

    // Peer B joins topic
    let _ = state_b
        .handle(InEvent::Command(topic_id, Command::Join(vec![])), now, None)
        .collect::<Vec<_>>();

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
    let iroh_msg: Message<[u8; 32]> =
        postcard::from_bytes(&encoded).expect("deserialize as real iroh_gossip message");

    // Peer B handles the received message in State!
    let out_events: Vec<OutEvent<[u8; 32]>> = state_b
        .handle(InEvent::RecvMessage(peer_a, iroh_msg.clone()), now, None)
        .collect();

    let mut received_content = None;
    for event in out_events {
        if let OutEvent::EmitEvent(t, Event::Received(gossip_ev)) = event {
            assert_eq!(t, topic_id);
            received_content = Some(gossip_ev.content);
        }
    }

    assert_eq!(received_content.as_deref(), Some(&payload[..]));

    // Sending duplicate to Peer B state machine suppresses it!
    let out_dup: Vec<OutEvent<[u8; 32]>> = state_b
        .handle(InEvent::RecvMessage(peer_a, iroh_msg), now, None)
        .collect();
    let received_dup = out_dup
        .iter()
        .any(|e| matches!(e, OutEvent::EmitEvent(_, Event::Received(_))));
    assert!(
        !received_dup,
        "Real iroh-gossip state machine must suppress duplicate message!"
    );
}

#[test]
fn test_blob_engine_storage_and_verification() {
    let engine = BlobEngine::new();
    let data = b"Hello from iroh-blobs test data for p2p sync";
    let desc = engine
        .create_blob(data, "test.txt", "text/plain", Some("node-endpoint-123"))
        .expect("create blob failed");

    assert_eq!(desc.name, "test.txt");
    assert_eq!(desc.media_type, "text/plain");
    assert_eq!(desc.size, data.len());
    assert!(!desc.hash.is_empty());
    assert!(!desc.ticket.is_empty());

    // Verify presence and read back
    assert!(engine.has_blob(&desc.hash));
    let retrieved = engine
        .get_blob(&desc.hash)
        .expect("get blob failed")
        .expect("blob not found");
    assert_eq!(retrieved, data);

    // Verify valid bytes vs corrupted bytes
    assert!(
        engine
            .verify_blob(&desc.hash, data)
            .expect("verification failed")
    );
    assert!(
        !engine
            .verify_blob(&desc.hash, b"corrupted data")
            .expect("verification failed")
    );
}

#[test]
fn test_blob_ticket_parsing() {
    let engine = BlobEngine::new();
    let data = b"Sample artifact content";
    let desc = engine
        .create_blob(
            data,
            "sample.pdf",
            "application/pdf",
            Some("node-endpoint-abc"),
        )
        .expect("create blob failed");
    let parsed = BlobEngine::parse_ticket(&desc.ticket).expect("parse ticket failed");
    assert_eq!(parsed.hash, desc.hash);
    assert_eq!(parsed.node, "node-endpoint-abc");
}
