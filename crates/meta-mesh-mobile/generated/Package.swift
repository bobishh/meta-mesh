// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MetaMeshMobile",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "MetaMeshMobile", targets: ["MetaMeshMobile"]),
    ],
    targets: [
        .binaryTarget(
            name: "meta_mesh_mobileFFI",
            path: "apple/meta_mesh_mobileFFI.xcframework"
        ),
        .target(
            name: "MetaMeshMobile",
            dependencies: ["meta_mesh_mobileFFI"],
            path: "swift",
            exclude: [
                "meta_mesh_mobileFFI.h",
                "meta_mesh_mobileFFI.modulemap",
            ],
            sources: ["meta_mesh_mobile.swift"]
        ),
    ]
)
