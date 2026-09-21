package interop

import uniffi.meta_mesh_mobile.MobileMeshNode

private fun expect(condition: Boolean, message: String) {
    check(condition) { "Kotlin interop failure: $message" }
}

fun main() {
    val native = MobileMeshNode.start(ByteArray(32) { 41 }, emptyList(), false, null)
    val kotlin = MobileMeshNode.start(ByteArray(32) { 42 }, listOf(native.endpointId()), false, null)
    try {
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
