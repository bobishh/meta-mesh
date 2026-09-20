use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iroh::RelayMode;
use meta_mesh_native::{NativeNode, NativeNodeOptions};

#[tokio::test]
async fn authorized_peers_exchange_real_gossip() {
    // Given two mutually authorized nodes.
    let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
    let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()])
        .await
        .expect("start node 2");
    node_1.authorize_peer(node_2.endpoint_id());

    // When both join one topic and node 1 broadcasts.
    let (sender_1, _receiver_1) = node_1
        .join_gossip("workspace-999", vec![])
        .await
        .expect("node 1 joins topic");
    let (_sender_2, mut receiver_2) = node_2
        .join_gossip("workspace-999", vec![node_1.addr()])
        .await
        .expect("node 2 joins topic");
    let payload = b"automerge-sync-state-change-vector";
    sender_1
        .broadcast(payload.to_vec())
        .await
        .expect("node 1 broadcasts");

    // Then node 2 receives exact bytes from node 1.
    let received = tokio::time::timeout(Duration::from_secs(5), receiver_2.recv())
        .await
        .expect("gossip delivery timeout")
        .expect("gossip receive failed")
        .expect("gossip stream ended");
    assert_eq!(received.content.as_ref(), payload);
    assert_eq!(received.delivered_from, node_1.endpoint_id());

    node_1.close().await.expect("close node 1");
    node_2.close().await.expect("close node 2");
}

#[tokio::test]
async fn authorized_peer_fetches_bao_verified_blob() {
    // Given two mutually authorized nodes and one stored blob.
    let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
    let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()])
        .await
        .expect("start node 2");
    node_1.authorize_peer(node_2.endpoint_id());
    let payload = b"bao-verified-binary-blob-over-current-iroh";
    let ticket = node_1.add_blob(payload).await.expect("store blob");

    // When node 2 fetches through the authenticated ticket.
    let fetched = node_2.fetch_blob(&ticket).await.expect("fetch blob");

    // Then content matches exactly.
    assert_eq!(fetched, payload);
    node_1.close().await.expect("close node 1");
    node_2.close().await.expect("close node 2");
}

#[tokio::test]
async fn unauthorized_peer_is_rejected_without_timeout() {
    // Given one provider that has not authorized the outsider.
    let provider = NativeNode::start(None, vec![])
        .await
        .expect("start provider");
    let outsider = NativeNode::start(None, vec![])
        .await
        .expect("start outsider");
    let ticket = provider
        .add_blob(b"private-workspace-snapshot")
        .await
        .expect("store private blob");

    // When the outsider fetches the provider blob.
    let outcome = tokio::time::timeout(Duration::from_secs(5), outsider.fetch_blob(&ticket))
        .await
        .expect("authorization rejection must not time out");

    // Then the network rejects access rather than returning data.
    let error = outcome.expect_err("outsider must not fetch provider blob");
    let diagnostic = format!("{error:#?}");
    assert!(
        diagnostic.contains("403") && diagnostic.contains("unauthorized"),
        "unexpected rejection: {diagnostic}"
    );
    provider.close().await.expect("close provider");
    outsider.close().await.expect("close outsider");
}

#[tokio::test]
async fn disk_store_survives_restart() {
    // Given a node using an isolated disk store.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let store_path =
        std::env::temp_dir().join(format!("meta-mesh-native-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&store_path).expect("create disk store");
    let options = NativeNodeOptions {
        secret: Some([42; 32]),
        storage_path: Some(store_path.clone()),
        bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        relay_mode: RelayMode::Disabled,
        ..NativeNodeOptions::default()
    };
    let node = NativeNode::start_with_options(options.clone())
        .await
        .expect("start disk node");
    let payload = b"persistent-automerge-snapshot";
    let ticket = node.add_blob(payload).await.expect("store persistent blob");

    // When the node closes and restarts on the same directory.
    node.close().await.expect("close disk node");
    let restarted = NativeNode::start_with_options(options)
        .await
        .expect("restart disk node");

    // Then the blob remains available by authenticated hash.
    let restored = restarted
        .get_blob(ticket.hash())
        .await
        .expect("read persistent blob");
    assert_eq!(restored, Some(payload.to_vec()));
    restarted.close().await.expect("close restarted node");
    std::fs::remove_dir_all(store_path).expect("remove disk store");
}
