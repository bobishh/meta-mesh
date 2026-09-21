plugins {
    kotlin("jvm") version "2.2.20"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    main {
        kotlin.srcDirs("../generated/kotlin", ".")
        kotlin.include("uniffi/meta_mesh_mobile/meta_mesh_mobile.kt", "kotlin_interop.kt")
    }
}

application {
    mainClass = "interop.Kotlin_interopKt"
    applicationDefaultJvmArgs = listOf(
        "-Djna.library.path=${System.getenv("META_MESH_LIBRARY_PATH") ?: error("META_MESH_LIBRARY_PATH is required")}",
    )
}
