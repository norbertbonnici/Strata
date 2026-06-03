// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Strata",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "StrataCore", targets: ["StrataCore"]),
        .library(name: "StrataTSK", targets: ["StrataTSK"]),
        .library(name: "StrataTimeline", targets: ["StrataTimeline"]),
        .executable(name: "Strata", targets: ["StrataApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "6.24.1"),
    ],
    targets: [
        .target(name: "StrataCore"),
        .target(
            name: "StrataTSK",
            dependencies: [
                "StrataCore",
                .product(name: "GRDB", package: "GRDB.swift"),
            ]
        ),
        .target(name: "StrataTimeline", dependencies: ["StrataCore"]),
        .executableTarget(
            name: "StrataApp",
            dependencies: ["StrataCore", "StrataTSK", "StrataTimeline"]
        ),
    ]
)
