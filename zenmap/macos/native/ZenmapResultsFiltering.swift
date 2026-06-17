import Foundation

extension ContentView {
    var allPorts: [ScannedPort] {
        hosts.flatMap { $0.ports }
    }

    var filteredHosts: [ScannedHost] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return hosts
        }

        return hosts.filter { hostMatchesFilter($0, query: query) }
    }

    var filteredPorts: [ScannedPort] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return allPorts
        }

        return allPorts.filter { portMatchesFilter($0, query: query) }
    }

    var allServicePorts: [ScannedPort] {
        allPorts.filter { !$0.serviceName.isEmpty || !$0.serviceSummary.isEmpty }
    }

    var filteredServicePorts: [ScannedPort] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return allServicePorts
        }

        return allServicePorts.filter { portMatchesFilter($0, query: query) }
    }

    var normalizedResultsFilterText: String {
        resultsFilterText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    var isFilteringResults: Bool {
        !normalizedResultsFilterText.isEmpty
    }

    func hostMatchesFilter(_ host: ScannedHost, query: String) -> Bool {
        let hostText = [
            host.address,
            host.hostname,
            host.status,
            "\(host.openPortCount)"
        ]
        .joined(separator: " ")
        .lowercased()

        if hostText.contains(query) {
            return true
        }

        return host.ports.contains { portMatchesFilter($0, query: query) }
    }

    func portMatchesFilter(_ port: ScannedPort, query: String) -> Bool {
        [
            port.hostAddress,
            port.protocolName,
            port.portNumber,
            port.state,
            port.serviceName,
            port.product,
            port.version,
            port.extraInfo,
            port.serviceSummary
        ]
        .joined(separator: " ")
        .lowercased()
        .contains(query)
    }

    var filteredSavedScans: [SavedScan] {
        let query = normalizedSavedScansFilterText

        guard !query.isEmpty else {
            return scanHistory.savedScans
        }

        return scanHistory.savedScans.filter { savedScanMatchesFilter($0, query: query) }
    }

    var normalizedSavedScansFilterText: String {
        savedScansFilterText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    var isFilteringSavedScans: Bool {
        !normalizedSavedScansFilterText.isEmpty
    }

    func savedScanMatchesFilter(_ scan: SavedScan, query: String) -> Bool {
        let dateText = scan.scannedAt.formatted(date: .abbreviated, time: .shortened)

        return [
            scan.title,
            scan.command,
            scan.xmlPath,
            scan.notes,
            scan.tags,
            dateText,
            "\(scan.hostCount)",
            "\(scan.portCount)"
        ]
        .joined(separator: " ")
        .lowercased()
        .contains(query)
    }
}
