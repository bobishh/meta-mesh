package interop

import uniffi.meta_mesh_mobile.MobileMeshNode
import uniffi.meta_mesh_mobile.MobileMeshRuntime
import uniffi.meta_mesh_mobile.MobileMeshHandshakeFlow
import uniffi.meta_mesh_mobile.MobileMeshAuthenticatedSessions
import uniffi.meta_mesh_mobile.MobileAutomergeSyncEngine
import uniffi.meta_mesh_mobile.meshAdmitPeerJson
import uniffi.meta_mesh_mobile.meshNextVerifiedOwnershipTransitionJson

private fun expect(condition: Boolean, message: String) {
    check(condition) { "Kotlin interop failure: $message" }
}

fun main() {
    val native = MobileMeshNode.start(ByteArray(32) { 41 }, emptyList(), false, null)
    val kotlin = MobileMeshNode.start(ByteArray(32) { 42 }, listOf(native.endpointId()), false, null)
    try {
        val runtime = MobileMeshRuntime()
        runtime.start()
        val handshake = MobileMeshHandshakeFlow("outgoing")
        expect(handshake.step() == "sendRequest", "Kotlin handshake did not start outbound")
        expect(handshake.advance("sendRequest", null) == "readResponse", "Kotlin handshake lost response stage")
        expect(handshake.advance("readResponse", null) == "mergeAuthority", "Kotlin handshake lost authority stage")
        expect(handshake.advance("mergeAuthority", null) == "verifyPeer", "Kotlin handshake lost peer verification")
        expect(handshake.advance("verifyPeer", null) == "checkExpectedPeer", "Kotlin handshake lost peer identity check")
        expect(handshake.advance("checkExpectedPeer", false) == "peerMismatch", "Kotlin handshake accepted wrong peer")
        expect(runCatching { meshAdmitPeerJson("{}", "{}", "peer", 0L) }.isFailure,
            "Kotlin admitted a peer without signed workspace authority")
        val sessions = MobileMeshAuthenticatedSessions()
        expect(runCatching { sessions.admitJson("{}", "{}", "peer", 0L) }.isFailure,
            "Kotlin session registry admitted unsigned authority")
        expect(sessions.peerJson("workspace", "peer") == null, "Kotlin retained denied peer")
        val owner = """{"personId":"owner","publicKey":"key","certificates":[]}"""
        expect(meshNextVerifiedOwnershipTransitionJson("[]", "workspace", owner, 1UL, emptyList(), 0L)
            .contains("\"candidates\":[]"), "Kotlin ownership planner binding is unavailable")
        val documentSync = MobileAutomergeSyncEngine("kotlin-device", null)
        documentSync.abortPreparedReceive("doc", "peer")
        expect(runCatching { documentSync.commitPreparedReceive("doc", "peer") }.isFailure,
            "Kotlin committed a document without prepared admission")
        expect(runtime.isRunning(), "Kotlin runtime did not start")
        expect(runtime.beginRouteAttemptJson("peer-1", 100UL).contains("\"routeKey\":\"peer-1\""), "Kotlin route attempt lost peer key")
        expect(runtime.routeAttemptActive("peer-1"), "Kotlin route attempt was not retained")
        runtime.scheduleReconnectJson("peer-1", 100UL, 50UL, 500UL)
        expect(runtime.dueReconnects(149UL).isEmpty(), "Kotlin reconnect fired early")
        expect(runtime.dueReconnects(150UL) == listOf("peer-1"), "Kotlin reconnect did not fire")
        expect(runtime.planDialJson("peer-1", true, 100UL).contains("\"mode\":\"direct\""), "Kotlin first dial did not prefer direct")
        runtime.recordNetworkFailure("peer-1", 100UL)
        expect(runtime.planDialJson("peer-1", true, 101UL).contains("\"mode\":\"relay\""), "Kotlin retry did not choose relay")
        runtime.recordDialSuccess("peer-1", "direct", 102UL)
        expect(runtime.planDialJson("peer-1", true, 103UL).contains("\"mode\":\"direct\""), "Kotlin direct success did not reset dial policy")
        runtime.stop()

        val deniedTicket = native.addBlob("denied".encodeToByteArray())
        expect(runCatching { kotlin.fetchBlob(deniedTicket) }.isFailure, "deny-by-default accepted an unauthorized Kotlin client")

        native.authorizePeer(kotlin.endpointId())
        val blob = "kotlin-native-blob".encodeToByteArray()
        val ticket = native.addBlob(blob)
        expect(kotlin.fetchBlob(ticket).contentEquals(blob), "Kotlin client failed native blob transfer")

        val nativeTopic = native.joinGossip("kotlin-native", emptyList())
        val kotlinTopic = kotlin.joinGossip("kotlin-native", listOf(native.endpointAddrJson()))
        val payload = "kotlin-native-gossip".encodeToByteArray()
        nativeTopic.broadcast(payload)
        expect(kotlinTopic.receive(5_000UL)?.content?.contentEquals(payload) == true, "Kotlin client missed native gossip")

        native.revokePeer(kotlin.endpointId())
        val revokedTicket = native.addBlob("revoked".encodeToByteArray())
        expect(runCatching { kotlin.fetchBlob(revokedTicket) }.isFailure, "revoked Kotlin client retained native access")
        println("Kotlin/native interop passed")
    } finally {
        kotlin.shutdown()
        native.shutdown()
    }
}
