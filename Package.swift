// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "cengine",
    platforms: [.macOS(.v26)],
    products: [
        .executable(name: "cengine", targets: ["cengine"]),
        .library(name: "CEngineCore", targets: ["CEngineCore"]),
        .library(name: "CEngineAPI", targets: ["CEngineAPI"]),
        .library(name: "CEngineRuntime", targets: ["CEngineRuntime"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/containerization.git", exact: "0.37.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.80.0"),
        .package(url: "https://github.com/apple/swift-system.git", from: "1.6.4"),
    ],
    targets: [
        .target(name: "CEngineCore"),
        .target(
            name: "CEngineRuntime",
            dependencies: [
                "CEngineCore",
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationArchive", package: "containerization"),
                .product(name: "ContainerizationEXT4", package: "containerization"),
                .product(name: "ContainerizationExtras", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
                .product(name: "ContainerizationOS", package: "containerization"),
                .product(name: "SystemPackage", package: "swift-system"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .target(
            name: "CEngineAPI",
            dependencies: [
                "CEngineCore",
                "CEngineRuntime",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .executableTarget(
            name: "cengine",
            dependencies: ["CEngineAPI", "CEngineCore", "CEngineRuntime"],
            swiftSettings: [.unsafeFlags(["-parse-as-library"])]
        ),
        .testTarget(name: "CEngineCoreTests", dependencies: ["CEngineCore", "CEngineRuntime"]),
        .testTarget(
            name: "CEngineAPITests",
            dependencies: [
                "CEngineAPI",
                "CEngineCore",
                "CEngineRuntime",
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
    ]
)
