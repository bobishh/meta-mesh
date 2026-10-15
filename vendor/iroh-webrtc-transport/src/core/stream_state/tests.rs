use super::*;
use anyhow::Context;
use iroh::{
    Endpoint, RelayMode,
    endpoint::{Connection, presets},
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

const ALPN: &[u8] = b"mesh-stream-reset-test";

#[tokio::test]
async fn given_an_over_limit_response_without_fin_when_reading_then_stop_only_its_stream()
-> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        let (client, server, connected, accepted) = pair().await?;
        let (mut send, recv) = connected.open_bi().await?;
        send.write_all(b"request").await?;
        let (mut response, mut request) = accepted.accept_bi().await?;
        request.read_exact(&mut [0; 7]).await?;
        let state = StreamState::new(send, recv);
        response.write_all(&[9; 1025]).await?;
        // Deliberately retain the send half without FIN: rejection cannot wait for EOF.
        let result = timeout(Duration::from_secs(1), state.read_to_end(1024))
            .await
            .context("oversized response waited for EOF")?;
        assert!(result.is_err(), "oversized response returned partial bytes");
        assert_eq!(
            timeout(Duration::from_secs(1), response.stopped()).await??,
            Some(0u32.into())
        );
        assert!(
            timeout(Duration::from_secs(1), request.read(&mut [0; 1]))
                .await?
                .is_err()
        );
        assert!(connected.close_reason().is_none());
        let (mut send, recv) = connected.open_bi().await?;
        send.write_all(b"next").await?;
        send.finish()?;
        let (mut response, mut request) = accepted.accept_bi().await?;
        assert_eq!(request.read_to_end(4).await?, b"next");
        response.write_all(b"ok").await?;
        response.finish()?;
        assert_eq!(
            StreamState::new(send, recv)
                .read_to_end(2)
                .await
                .map_err(anyhow::Error::msg)?,
            b"ok"
        );
        connected.close(0u32.into(), b"test complete");
        client.close().await;
        server.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn given_a_response_at_the_exact_read_limit_when_finished_then_return_all_bytes()
-> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        let (client, server, connected, accepted) = pair().await?;
        for bytes in [vec![], vec![7; 1024], vec![6; 80 * 1024]] {
            let (mut send, recv) = connected.open_bi().await?;
            send.write_all(b"x").await?;
            let (mut response, mut request) = accepted.accept_bi().await?;
            request.read_exact(&mut [0; 1]).await?;
            response.write_all(&bytes).await?;
            response.finish()?;
            let state = StreamState::new(send, recv);
            assert_eq!(
                state
                    .read_to_end(bytes.len())
                    .await
                    .map_err(anyhow::Error::msg)?,
                bytes
            );
            assert!(!state.closed_recv.load(std::sync::atomic::Ordering::SeqCst));
            state.reset().await;
        }
        connected.close(0u32.into(), b"test complete");
        client.close().await;
        server.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn given_a_partial_response_when_reset_during_bounded_read_then_return_no_partial_bytes()
-> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        let (client, server, connected, accepted) = pair().await?;
        let (mut send, recv) = connected.open_bi().await?;
        send.write_all(b"x").await?;
        let (mut response, mut request) = accepted.accept_bi().await?;
        request.read_exact(&mut [0; 1]).await?;
        response.write_all(b"partial").await?;
        let state = Arc::new(StreamState::new(send, recv));
        let reader = {
            let state = state.clone();
            tokio::spawn(async move { state.read_to_end(1024).await })
        };
        tokio::task::yield_now().await;
        assert!(!reader.is_finished());
        timeout(Duration::from_secs(1), state.reset()).await?;
        assert!(timeout(Duration::from_secs(1), reader).await??.is_err());
        assert_eq!(
            timeout(Duration::from_secs(1), response.stopped()).await??,
            Some(0u32.into())
        );
        assert!(connected.close_reason().is_none());
        connected.close(0u32.into(), b"test complete");
        client.close().await;
        server.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

async fn endpoint() -> anyhow::Result<Endpoint> {
    Ok(Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?)
}

async fn pair() -> anyhow::Result<(Endpoint, Endpoint, Connection, Connection)> {
    let client = endpoint().await?;
    let server = endpoint().await?;
    let (connected, accepted) = tokio::join!(client.connect(server.addr(), ALPN), async {
        server.accept().await.expect("incoming connection").await
    });
    Ok((client, server, connected?, accepted?))
}

#[tokio::test]
async fn given_pending_read_when_stream_resets_then_peer_is_stopped_and_connection_stays_usable()
-> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        let (client, server, connected, accepted) = pair().await?;
        let (mut send, recv) = connected.open_bi().await?;
        send.write_all(b"request").await?;
        let (remote_send, mut remote_recv) = accepted.accept_bi().await?;
        let mut request = [0; 7];
        remote_recv.read_exact(&mut request).await?;
        assert_eq!(&request, b"request");

        let state = Arc::new(StreamState::new(send, recv));
        let (begun, started) = tokio::sync::oneshot::channel();
        let reader = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut recv = state.recv.lock().await;
                begun.send(()).expect("read barrier");
                let mut buffer = [0; 16];
                tokio::select! {
                    _ = state.recv_cancel.notified() => Err("cancelled".to_owned()),
                    read = recv.read(&mut buffer) => read.map_err(|error| error.to_string()),
                }
            })
        };
        started.await?;
        tokio::task::yield_now().await;
        timeout(Duration::from_secs(1), state.reset()).await?;
        assert_eq!(
            timeout(Duration::from_secs(1), reader).await??,
            Err("cancelled".to_owned())
        );
        assert!(state.closed_send.load(std::sync::atomic::Ordering::SeqCst));
        assert!(state.closed_recv.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            timeout(Duration::from_secs(1), remote_send.stopped())
                .await
                .context("peer did not receive STOP_SENDING")??,
            Some(0u32.into())
        );
        assert!(
            timeout(Duration::from_secs(1), remote_recv.read(&mut [0; 1]))
                .await?
                .is_err()
        );
        state.reset().await;

        assert!(connected.close_reason().is_none());
        assert!(accepted.close_reason().is_none());
        let (mut next_send, mut next_recv) = connected.open_bi().await?;
        next_send.write_all(b"next").await?;
        next_send.finish()?;
        let (mut reply, mut incoming) = accepted.accept_bi().await?;
        assert_eq!(incoming.read_to_end(64).await?, b"next");
        reply.write_all(b"ok").await?;
        reply.finish()?;
        assert_eq!(next_recv.read_to_end(64).await?, b"ok");
        connected.close(0u32.into(), b"test complete");
        client.close().await;
        server.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn given_a_blocked_writer_when_two_resets_race_then_wake_before_locking_and_stop_both_directions()
-> anyhow::Result<()> {
    timeout(Duration::from_secs(10), async {
        let (client, server, connected, accepted) = pair().await?;
        let (mut send, recv) = connected.open_bi().await?;
        send.write_all(b"x").await?;
        let (remote_send, mut remote_recv) = accepted.accept_bi().await?;
        remote_recv.read_exact(&mut [0; 1]).await?;
        let state = Arc::new(StreamState::new(send, recv));
        let (begun, started) = tokio::sync::oneshot::channel();
        let writer = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut send = state.send.lock().await;
                let buffer = [7; 64 * 1024];
                begun.send(()).expect("write barrier");
                tokio::select! {
                    _ = state.send_cancel.notified() => Err("cancelled".to_owned()),
                    result = async {
                        for _ in 0..10_000 {
                            send.write_all(&buffer).await.map_err(|error| error.to_string())?;
                        }
                        Ok::<_, String>(())
                    } => result,
                }
            })
        };
        started.await?;
        tokio::task::yield_now().await;
        assert!(!writer.is_finished());
        timeout(Duration::from_secs(1), async {
            tokio::join!(state.reset(), state.reset());
        })
        .await?;
        assert_eq!(
            timeout(Duration::from_secs(1), writer).await??,
            Err("cancelled".to_owned())
        );
        assert_eq!(
            timeout(Duration::from_secs(1), remote_send.stopped()).await??,
            Some(0u32.into())
        );
        assert!(
            timeout(
                Duration::from_secs(1),
                remote_recv.read_to_end(16 * 1024 * 1024)
            )
            .await?
            .is_err()
        );
        assert!(connected.close_reason().is_none());
        connected.close(0u32.into(), b"test complete");
        client.close().await;
        server.close().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
