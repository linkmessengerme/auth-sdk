import Foundation

struct DemoConfiguration: Sendable {
    static let bundleID = "me.linkmessenger.auth.demo.ios"
    static let callback = bundleID + "://oauth/callback"
    static let maximumBytes = 64 * 1024

    let json: String
    let clientID: String
    let issuer: String
    let apiBaseURL: String
    let scopes: [String]

    static func parse(_ data: Data) throws -> DemoConfiguration {
        guard data.count <= maximumBytes else { throw DemoConfigError.tooLarge }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let json = String(data: data, encoding: .utf8) else { throw DemoConfigError.invalid }
        guard !object.keys.contains("private_key"), !object.keys.contains("client_secret") else {
            throw DemoConfigError.publicOnly
        }
        guard object["type"] as? String == "link_oauth_client_config",
              object["platform"] as? String == "ios" else { throw DemoConfigError.iosOnly }
        guard object["bundle_id"] as? String == bundleID else { throw DemoConfigError.bundleMismatch }
        guard let redirects = object["redirect_uris"] as? [String], redirects.contains(callback) else {
            throw DemoConfigError.callbackMissing
        }
        guard let clientID = object["client_id"] as? String, !clientID.isEmpty,
              let issuer = object["issuer"] as? String, !issuer.isEmpty,
              let scopes = object["scopes"] as? [String], !scopes.isEmpty else {
            throw DemoConfigError.invalid
        }
        // The SDK validates the complete protocol configuration before it is used.
        return DemoConfiguration(json: json, clientID: clientID, issuer: issuer,
            apiBaseURL: object["api_base_url"] as? String ?? issuer, scopes: scopes)
    }
}

enum DemoConfigError: Error {
    case invalid, tooLarge, publicOnly, iosOnly, bundleMismatch, callbackMissing, unreadable

    var message: String {
        switch self {
        case .invalid: return "The config could not be read. A public JSON from Console is required."
        case .tooLarge: return "The config is too large. The maximum is 64 KB."
        case .publicOnly: return "A public app config is required, without private_key or client_secret."
        case .iosOnly: return "An iOS client config of type link_oauth_client_config is required."
        case .bundleMismatch: return "The config Bundle ID must be \(DemoConfiguration.bundleID)."
        case .callbackMissing: return "The config does not contain this demo's callback."
        case .unreadable: return "The configuration file could not be opened."
        }
    }
}

/// Only public configuration is stored here. Tokens belong exclusively to the SDK.
actor DemoConfigStore {
    private let directory: URL
    private let bundled: URL?

    init(directory: URL? = nil, bundled: URL? = Bundle.main.url(forResource: "link-login", withExtension: "json")) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory,
            in: .userDomainMask)[0].appendingPathComponent("LinkAuthDemo", isDirectory: true)
        self.bundled = bundled
    }

    func load() throws -> DemoConfiguration? {
        let saved = directory.appendingPathComponent("config.json")
        let source = FileManager.default.fileExists(atPath: saved.path) ? saved : bundled
        guard let source else { return nil }
        return try DemoConfiguration.parse(Self.readBounded(source))
    }

    func read(_ url: URL) throws -> DemoConfiguration {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        return try DemoConfiguration.parse(Self.readBounded(url))
    }

    func save(_ config: DemoConfiguration) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        var destination = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try destination.setResourceValues(values)
        try Data(config.json.utf8).write(to: directory.appendingPathComponent("config.json"),
            options: [.atomic, .completeFileProtection])
    }

    private static func readBounded(_ url: URL) throws -> Data {
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            var result = Data()
            while result.count <= DemoConfiguration.maximumBytes {
                let chunk = try handle.read(upToCount: min(4096, DemoConfiguration.maximumBytes + 1 - result.count)) ?? Data()
                if chunk.isEmpty { return result }
                result.append(chunk)
            }
            throw DemoConfigError.tooLarge
        } catch let error as DemoConfigError { throw error }
        catch { throw DemoConfigError.unreadable }
    }
}
