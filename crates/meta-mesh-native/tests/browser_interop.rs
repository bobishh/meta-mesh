use bytes::Bytes;
use iroh_gossip::proto::{
    Config, Message, PeerData, Scope, TopicId,
    state::{InEvent, OutEvent, State},
    topic::{Command, Event},
};
use rand::{SeedableRng, rngs::StdRng};

const BROWSER_098_PACKET: &str = "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f0100ca3a7f2ff410a9bf3800173f61d7fa30956d12afefbcffb537f0fb563c36e88c0f6368616e67652d686173682d6162630000";
const NATIVE_0101_JOIN_PACKET: &str =
    "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f00000106706565722d62";
const BROWSER_098_JOIN_RESPONSE: &str =
    "415f7072af6c542932314515335cb4a4f69e293a6c2db60abe80ded431aaf42f0004000106706565722d61";

fn peer_id(value: &str) -> [u8; 32] {
    *blake3::hash(value.as_bytes()).as_bytes()
}

#[test]
fn native_0101_reads_browser_098_and_emits_browser_compatible_wire_packets() {
    // Given current native gossip joins the same topic as the browser 0.98 fixture.
    let browser_id = peer_id("peer-a");
    let native_id = peer_id("peer-b");
    let topic = TopicId::from_bytes(*blake3::hash(b"workspace-123").as_bytes());
    let mut native = State::new(
        native_id,
        PeerData::new(b"peer-b".to_vec()),
        Config::default(),
        StdRng::seed_from_u64(9),
    );
    let native_join = native
        .handle(
            InEvent::Command(topic, Command::Join(vec![browser_id])),
            n0_future::time::Instant::now(),
            None,
        )
        .collect::<Vec<_>>();
    let native_join_packet = native_join.into_iter().find_map(|event| match event {
        OutEvent::SendMessage(_, message) => {
            Some(postcard::to_stdvec(&message).expect("serialize native join"))
        }
        _ => None,
    });
    assert_eq!(
        hex::encode(native_join_packet.expect("native join packet")),
        NATIVE_0101_JOIN_PACKET
    );
    let join_response: Message<[u8; 32]> =
        postcard::from_bytes(&hex::decode(BROWSER_098_JOIN_RESPONSE).unwrap())
            .expect("native decodes browser join response");
    let _ = native
        .handle(
            InEvent::RecvMessage(browser_id, join_response),
            n0_future::time::Instant::now(),
            None,
        )
        .collect::<Vec<_>>();

    // When the exact browser 0.98 state-machine packet enters native 0.101.
    let packet = hex::decode(BROWSER_098_PACKET).expect("fixture hex");
    let message: Message<[u8; 32]> =
        postcard::from_bytes(&packet).expect("native decodes browser packet");
    let events = native
        .handle(
            InEvent::RecvMessage(browser_id, message),
            n0_future::time::Instant::now(),
            None,
        )
        .collect::<Vec<_>>();

    // Then native delivers exact browser content.
    let received = events.into_iter().find_map(|event| match event {
        OutEvent::EmitEvent(_, Event::Received(message)) => Some(message.content.to_vec()),
        _ => None,
    });
    assert_eq!(received.as_deref(), Some(b"change-hash-abc".as_slice()));

    // And native's current wire output is captured for the reciprocal browser test.
    let events = native
        .handle(
            InEvent::Command(
                topic,
                Command::Broadcast(Bytes::from_static(b"native-to-browser"), Scope::Swarm),
            ),
            n0_future::time::Instant::now(),
            None,
        )
        .collect::<Vec<_>>();
    let packet = events.into_iter().find_map(|event| match event {
        OutEvent::SendMessage(peer, message) if peer == browser_id => {
            Some(postcard::to_stdvec(&message).expect("serialize native packet"))
        }
        _ => None,
    });
    let packet = packet.expect("native broadcast packet");
    println!("native_gossip_fixture={}", hex::encode(&packet));
    let _: Message<[u8; 32]> = postcard::from_bytes(&packet).expect("native packet roundtrip");
}
