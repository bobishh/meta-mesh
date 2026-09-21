import Foundation

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
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
