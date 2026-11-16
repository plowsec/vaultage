// swift-tools-version: 5.10
import PackageDescription

// Static library produced by `cargo build --release --locked -p vaultage-ffi`.
let rustLib = Context.packageDirectory + "/../target/release"

let package = Package(
    name: "Vaultage",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "Vaultage", targets: ["Coffer"]),
        .executable(name: "vaultage-selftest", targets: ["CofferSelfTest"]),
    ],
    targets: [
        .target(name: "CCoffer", path: "Sources/CCoffer"),
        .target(
            name: "CofferKit",
            dependencies: ["CCoffer"],
            path: "Sources/CofferKit",
            linkerSettings: [
                .unsafeFlags(["-L", rustLib]),
                .linkedLibrary("vaultage_ffi"),
                .linkedFramework("Security"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .executableTarget(name: "Coffer", dependencies: ["CofferKit"], path: "Sources/Coffer"),
        .executableTarget(name: "CofferSelfTest", dependencies: ["CofferKit"], path: "Sources/CofferSelfTest"),
    ],
    swiftLanguageVersions: [.v5]
)
