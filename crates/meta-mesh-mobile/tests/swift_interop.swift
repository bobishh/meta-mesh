import Foundation

func expect(_ condition: Bool, _ message: String) {
    if !condition {
        fputs("Swift interop failure: \(message)\n", stderr)
        exit(1)
    }
}

@main
struct SwiftInterop {
static func main() {
do {
    let native = try MobileMeshNode.start(
        secret: Data(repeating: 31, count: 32),
        allowedPeerIds: [],
        allowUnknownPeers: false,
        storagePath: nil
    )
    let swift = try MobileMeshNode.start(
        secret: Data(repeating: 32, count: 32),
        allowedPeerIds: [try native.endpointId()],
        allowUnknownPeers: false,
        storagePath: nil
    )
    defer {
        try? swift.shutdown()
        try? native.shutdown()
    }

    let runtime = MobileMeshRuntime()
    try runtime.start()
    let handshake = try MobileMeshHandshakeFlow(direction: "incoming")
    expect(try handshake.step() == "readRequest", "Swift handshake did not start inbound")
    expect(try handshake.advance(completed: "readRequest", decision: nil) == "mergeAuthority", "Swift handshake lost authority stage")
    expect(try handshake.advance(completed: "mergeAuthority", decision: nil) == "verifyPeer", "Swift handshake lost peer verification")
    expect(try handshake.advance(completed: "verifyPeer", decision: nil) == "checkRevocation", "Swift handshake lost revocation check")
    expect(try handshake.advance(completed: "checkRevocation", decision: true) == "sendRevocation", "Swift handshake admitted revoked peer")
    do {
        _ = try meshAdmitPeerJson(handshakeJson: "{}", snapshotJson: "{}", remoteEndpoint: "peer", nowMs: 0)
        expect(false, "Swift admitted a peer without signed workspace authority")
    } catch {}
    let sessions = MobileMeshAuthenticatedSessions()
    do {
        _ = try sessions.admitJson(handshakeJson: "{}", snapshotJson: "{}", remoteEndpoint: "peer", nowMs: 0)
        expect(false, "Swift session registry admitted unsigned authority")
    } catch {}
    expect(try sessions.peerJson(workspaceId: "workspace", remoteEndpoint: "peer") == nil, "Swift retained denied peer")
    let running = try runtime.isRunning()
    expect(running, "Swift runtime did not start")
    let attempt = try runtime.beginRouteAttemptJson(routeKey: "peer-1", nowMs: 100)
    expect(attempt.contains("\"routeKey\":\"peer-1\""), "Swift route attempt lost peer key")
    let active = try runtime.routeAttemptActive(routeKey: "peer-1")
    expect(active, "Swift route attempt was not retained")
    _ = try runtime.scheduleReconnectJson(routeKey: "peer-1", nowMs: 100, baseDelayMs: 50, maximumDelayMs: 500)
    let earlyReconnects = try runtime.dueReconnects(nowMs: 149)
    expect(earlyReconnects.isEmpty, "Swift reconnect fired early")
    let dueReconnects = try runtime.dueReconnects(nowMs: 150)
    expect(dueReconnects == ["peer-1"], "Swift reconnect did not fire")
    let firstDial = try runtime.planDialJson(peerKey: "peer-1", relayAvailable: true, nowMs: 100)
    expect(firstDial.contains("\"mode\":\"direct\""), "Swift first dial did not prefer direct")
    try runtime.recordNetworkFailure(peerKey: "peer-1", nowMs: 100)
    let retryDial = try runtime.planDialJson(peerKey: "peer-1", relayAvailable: true, nowMs: 101)
    expect(retryDial.contains("\"mode\":\"relay\""), "Swift retry did not choose relay")
    try runtime.recordDialSuccess(peerKey: "peer-1", mode: "direct", nowMs: 102)
    let recoveredDial = try runtime.planDialJson(peerKey: "peer-1", relayAvailable: true, nowMs: 103)
    expect(recoveredDial.contains("\"mode\":\"direct\""), "Swift direct success did not reset dial policy")
    _ = try runtime.stop()

    let deniedTicket = try native.addBlob(data: Data("denied".utf8))
    do {
        _ = try swift.fetchBlob(ticket: deniedTicket)
        expect(false, "deny-by-default accepted an unauthorized Swift client")
    } catch {}

    try native.authorizePeer(peerId: swift.endpointId())
    let blob = Data("swift-native-blob".utf8)
    let ticket = try native.addBlob(data: blob)
    let fetchedBlob = try swift.fetchBlob(ticket: ticket)
    expect(fetchedBlob == blob, "Swift client failed native blob transfer")

    let nativeTopic = try native.joinGossip(topic: "swift-native", bootstrapPeerAddrsJson: [])
    let swiftTopic = try swift.joinGossip(
        topic: "swift-native",
        bootstrapPeerAddrsJson: [try native.endpointAddrJson()]
    )
    let payload = Data("swift-native-gossip".utf8)
    try nativeTopic.broadcast(content: payload)
    let received = try swiftTopic.receive(timeoutMs: 5_000)
    expect(received?.content == payload, "Swift client missed native gossip")

    try native.revokePeer(peerId: swift.endpointId())
    let revokedTicket = try native.addBlob(data: Data("revoked".utf8))
    do {
        _ = try swift.fetchBlob(ticket: revokedTicket)
        expect(false, "revoked Swift client retained native access")
    } catch {}

    print("Swift/native interop passed")
} catch {
    fputs("Swift interop failure: \(error)\n", stderr)
    exit(1)
}
}
}
