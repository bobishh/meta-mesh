#[cfg(not(target_family = "wasm"))]
mod native_integration_tests {
    use meta_mesh::{BrowserNode, NativeNode, NativeNodeOptions};
    use std::time::Duration;

    #[tokio::test]
    async fn test_native_node_real_gossip_delivery() {
        // Given two authorized native nodes: node_1 and node_2
        let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
        let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()]).await.expect("start node 2");

        // Cross-authorize
        node_1.authorize_peer(node_2.endpoint_id());

        let topic_name = "automerge-collab-workspace-999";

        // When both nodes join the gossip topic with node_1 as bootstrap for node_2
        let (sender_1, _receiver_1) = node_1.join_gossip(topic_name, vec![]).await.expect("node 1 join gossip");
        let (_sender_2, mut receiver_2) = node_2.join_gossip(topic_name, vec![node_1.addr()]).await.expect("node 2 join gossip");

        // When node_1 broadcasts a message
        let payload = b"automerge-sync-state-change-vector";
        sender_1.broadcast(payload.to_vec()).await.expect("broadcast from node 1");

        // Then node_2 receives the exact message delivered from node_1
        let received = tokio::time::timeout(Duration::from_secs(3), receiver_2.recv())
            .await
            .expect("timeout waiting for gossip message")
            .expect("error receiving message")
            .expect("receiver stream ended unexpectedly");

        assert_eq!(received.content.as_ref(), payload);
        assert_eq!(received.delivered_from, node_1.endpoint_id());

        // Clean up
        let _ = node_1.close().await;
        let _ = node_2.close().await;
    }

    #[tokio::test]
    async fn test_native_node_real_bao_blob_transfer() {
        // Given two authorized native nodes
        let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
        let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()]).await.expect("start node 2");
        node_1.authorize_peer(node_2.endpoint_id());

        // When node_1 stores a binary blob and generates an authenticated ticket
        let binary_payload = b"test-bao-verified-binary-blob-transfer-over-real-p2p-network";
        let ticket = node_1.add_blob(binary_payload).await.expect("add blob to node 1");

        // Then node_2 can fetch and Bao-verify the blob using the ticket
        let fetched_data = node_2.fetch_blob(&ticket).await.expect("fetch blob from node 1");
        assert_eq!(fetched_data, binary_payload);

        let _ = node_1.close().await;
        let _ = node_2.close().await;
    }

    #[tokio::test]
    async fn test_native_node_deny_by_default_and_revocation() {
        // Given node_1 with only node_2 initially authorized
        let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
        let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()]).await.expect("start node 2");
        let node_3 = NativeNode::start(None, vec![]).await.expect("start node 3");

        node_1.authorize_peer(node_2.endpoint_id());

        // Node 2 is authorized; Node 3 is an unauthorized outsider
        assert!(node_1.is_peer_authorized(&node_2.endpoint_id()));
        assert!(!node_1.is_peer_authorized(&node_3.endpoint_id()));

        // When node_1 revokes node_2 (leaving the allowed set completely empty)
        node_1.revoke_peer(&node_2.endpoint_id());

        // Then under deny-by-default, an empty allowlist must DENY everyone, NOT open to all
        assert!(
            !node_1.is_peer_authorized(&node_2.endpoint_id()),
            "Revoked peer must not be authorized"
        );
        assert!(
            !node_1.is_peer_authorized(&node_3.endpoint_id()),
            "Outsider must not be authorized when allowlist is empty (deny-by-default)"
        );

        let _ = node_1.close().await;
        let _ = node_2.close().await;
        let _ = node_3.close().await;
    }

    #[tokio::test]
    async fn test_native_node_outsider_access_control_rejection() {
        // Given node_1 with only node_2 authorized
        let node_1 = NativeNode::start(None, vec![]).await.expect("start node 1");
        let node_2 = NativeNode::start(None, vec![node_1.endpoint_id()]).await.expect("start node 2");
        node_1.authorize_peer(node_2.endpoint_id());

        let payload = b"confidential-data";
        let ticket = node_1.add_blob(payload).await.expect("add blob");

        // When node_3 (unauthorized outsider) attempts to fetch the blob from node_1
        let node_3 = NativeNode::start(None, vec![]).await.expect("start node 3");
        let fetch_attempt = tokio::time::timeout(
            Duration::from_secs(3),
            node_3.fetch_blob(&ticket),
        ).await;

        // Then node_3 is actively rejected with an authorization error — NOT timed out
        let result = fetch_attempt.expect("fetch must not hang or time out; access control must fail promptly");
        match result {
            Err(err) => {
                let err_debug = format!("{:#?}", err);
                assert!(
                    err_debug.contains("403") && err_debug.contains("unauthorized"),
                    "Expected 403 unauthorized rejection from peer, got: {}",
                    err_debug
                );
            }
            Ok(_) => {
                panic!("Unauthorized node_3 MUST NOT be allowed to fetch blobs from node_1");
            }
        }

        let _ = node_1.close().await;
        let _ = node_2.close().await;
        let _ = node_3.close().await;
    }

    #[tokio::test]
    async fn test_native_node_durable_disk_storage() {
        let test_dir = std::env::temp_dir().join(format!("meta-mesh-test-persist-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&test_dir).expect("create test dir");

        let secret = [42u8; 32];
        let options = NativeNodeOptions {
            secret: Some(secret),
            allowed_peers: vec![],
            allow_any: false,
            storage_path: Some(test_dir.clone()),
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            relay_mode: iroh::endpoint::RelayMode::Disabled,
        };

        // Given a node with disk-backed storage
        let node = NativeNode::start_with_options(options.clone()).await.expect("start node with disk store");
        let payload = b"persistent-automerge-blob-content-across-restart";
        let ticket = node.add_blob(payload).await.expect("add blob to disk store");

        // When the node is cleanly closed and restarted with the same storage path
        node.close().await.expect("close node");

        let restarted_node = NativeNode::start_with_options(options).await.expect("restart node with disk store");

        // Then the blob is still present in the store and matches original bytes
        let retrieved = restarted_node.get_blob(ticket.hash()).await.expect("retrieve blob from restarted store");
        assert_eq!(retrieved, Some(payload.to_vec()));

        let _ = restarted_node.close().await;
        let _ = std::fs::remove_dir_all(&test_dir);
    }

    #[tokio::test]
    async fn test_browser_node_on_native_is_not_mock() {
        // Given a BrowserNode started on native target
        let browser_node = BrowserNode::start(None).await.expect("start browser node");

        // Then its endpoint_id is a real 64-char hex public key, NOT "native-mock-endpoint"
        let endpoint_id = browser_node.endpoint_id();
        assert_ne!(endpoint_id, "native-mock-endpoint");
        assert_eq!(endpoint_id.len(), 64);

        // Node remains alive and operational across time
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(browser_node.endpoint_id(), endpoint_id);

        let _ = browser_node.close(None).await;
    }
}
