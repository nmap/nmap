import Foundation

struct ScanProfile: Identifiable, Hashable, Codable {
    let id: UUID
    let name: String
    let arguments: String
    let description: String
    var isBuiltIn = true

    init(
        id: UUID = UUID(),
        name: String,
        arguments: String,
        description: String,
        isBuiltIn: Bool = true
    ) {
        self.id = id
        self.name = name
        self.arguments = arguments
        self.description = description
        self.isBuiltIn = isBuiltIn
    }
}

struct ScannedHost: Identifiable, Hashable {
    let id = UUID()
    var address: String
    var hostname: String
    var status: String
    var ports: [ScannedPort]

    var displayName: String {
        hostname.isEmpty ? address : hostname
    }

    var openPortCount: Int {
        ports.filter { $0.state == "open" }.count
    }
}

struct ScannedPort: Identifiable, Hashable {
    let id = UUID()
    var hostAddress: String
    var protocolName: String
    var portNumber: String
    var state: String
    var serviceName: String
    var product: String
    var version: String
    var extraInfo: String

    var serviceSummary: String {
        [product, version, extraInfo]
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
}


struct SavedScan: Identifiable, Hashable, Codable {
    let id: UUID
    var title: String
    var command: String
    var xmlPath: String
    var scannedAt: Date
    var hostCount: Int
    var portCount: Int
    var notes: String
    var tags: String

    init(
        id: UUID = UUID(),
        title: String,
        command: String,
        xmlPath: String,
        scannedAt: Date,
        hostCount: Int,
        portCount: Int,
        notes: String = "",
        tags: String = ""
    ) {
        self.id = id
        self.title = title
        self.command = command
        self.xmlPath = xmlPath
        self.scannedAt = scannedAt
        self.hostCount = hostCount
        self.portCount = portCount
        self.notes = notes
        self.tags = tags
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case command
        case xmlPath
        case scannedAt
        case hostCount
        case portCount
        case notes
        case tags
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        command = try container.decode(String.self, forKey: .command)
        xmlPath = try container.decode(String.self, forKey: .xmlPath)
        scannedAt = try container.decode(Date.self, forKey: .scannedAt)
        hostCount = try container.decode(Int.self, forKey: .hostCount)
        portCount = try container.decode(Int.self, forKey: .portCount)
        notes = try container.decodeIfPresent(String.self, forKey: .notes) ?? ""
        tags = try container.decodeIfPresent(String.self, forKey: .tags) ?? ""
    }
}
