// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "BIP32",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "BIP32",
            targets: ["BIP32"]),
    ],
    dependencies: [
        .package(url: "https://github.com/pengpengliu/Base58.git", from: "1.0.0"),
        .package(url: "https://github.com/pengpengliu/Crypto101.git", .upToNextMinor(from: "0.3.0")),
        .package(name: "secp256k1", url: "https://github.com/Boilertalk/secp256k1.swift.git", from: "0.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "BIP32",
            dependencies: ["Base58", "Crypto101"]),
        .testTarget(
            name: "BIP32Tests",
            dependencies: ["BIP32"]),
    ]
)
