import AppKit
import Foundation
import UniformTypeIdentifiers

struct ScanComparison {
    let newHosts: [String]
    let missingHosts: [String]
    let newOpenPorts: [String]
    let closedPorts: [String]
    let changedServices: [String]
}

extension ContentView {
    var currentScanComparison: ScanComparison? {
        guard let baselineCompareScanID,
              let comparisonCompareScanID,
              baselineCompareScanID != comparisonCompareScanID,
              let baselineScan = scanHistory.savedScans.first(where: { $0.id == baselineCompareScanID }),
              let comparisonScan = scanHistory.savedScans.first(where: { $0.id == comparisonCompareScanID }) else {
            return nil
        }

        let baselineHosts = parseNmapXML(at: URL(fileURLWithPath: baselineScan.xmlPath))
        let comparisonHosts = parseNmapXML(at: URL(fileURLWithPath: comparisonScan.xmlPath))
        return compareScans(baseline: baselineHosts, comparison: comparisonHosts)
    }

    func scanComparisonScanLabel(_ scan: SavedScan) -> String {
        let date = scan.scannedAt.formatted(date: .abbreviated, time: .shortened)
        return "\(date) - \(scan.title)"
    }

    func compareScans(baseline: [ScannedHost], comparison: [ScannedHost]) -> ScanComparison {
        let baselineHostMap = Dictionary(uniqueKeysWithValues: baseline.map { ($0.address, $0) })
        let comparisonHostMap = Dictionary(uniqueKeysWithValues: comparison.map { ($0.address, $0) })

        let baselineHostAddresses = Set(baselineHostMap.keys)
        let comparisonHostAddresses = Set(comparisonHostMap.keys)

        let newHosts = comparisonHostAddresses.subtracting(baselineHostAddresses).sorted()
        let missingHosts = baselineHostAddresses.subtracting(comparisonHostAddresses).sorted()

        var newOpenPorts: [String] = []
        var closedPorts: [String] = []
        var changedServices: [String] = []

        for hostAddress in baselineHostAddresses.intersection(comparisonHostAddresses).sorted() {
            guard let baselineHost = baselineHostMap[hostAddress],
                  let comparisonHost = comparisonHostMap[hostAddress] else {
                continue
            }

            let baselinePorts = openPortMap(for: baselineHost)
            let comparisonPorts = openPortMap(for: comparisonHost)
            let baselineKeys = Set(baselinePorts.keys)
            let comparisonKeys = Set(comparisonPorts.keys)

            for key in comparisonKeys.subtracting(baselineKeys).sorted() {
                if let port = comparisonPorts[key] {
                    newOpenPorts.append("\(hostAddress) \(port.protocolName)/\(port.portNumber) \(scanPortServiceDescription(port))")
                }
            }

            for key in baselineKeys.subtracting(comparisonKeys).sorted() {
                if let port = baselinePorts[key] {
                    closedPorts.append("\(hostAddress) \(port.protocolName)/\(port.portNumber) \(scanPortServiceDescription(port))")
                }
            }

            for key in baselineKeys.intersection(comparisonKeys).sorted() {
                guard let baselinePort = baselinePorts[key],
                      let comparisonPort = comparisonPorts[key] else {
                    continue
                }

                let baselineService = scanPortServiceDescription(baselinePort)
                let comparisonService = scanPortServiceDescription(comparisonPort)

                if baselineService != comparisonService {
                    changedServices.append("\(hostAddress) \(comparisonPort.protocolName)/\(comparisonPort.portNumber): \(baselineService) -> \(comparisonService)")
                }
            }
        }

        return ScanComparison(
            newHosts: newHosts,
            missingHosts: missingHosts,
            newOpenPorts: newOpenPorts,
            closedPorts: closedPorts,
            changedServices: changedServices
        )
    }

    func openPortMap(for host: ScannedHost) -> [String: ScannedPort] {
        Dictionary(uniqueKeysWithValues: host.ports
            .filter { $0.state == "open" }
            .map { ("\($0.protocolName)/\($0.portNumber)", $0) })
    }

    func scanPortServiceDescription(_ port: ScannedPort) -> String {
        let description = [port.serviceName, port.product, port.version, port.extraInfo]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")

        return description.isEmpty ? "(no service details)" : description
    }

    func copyScanComparisonReport() {
        guard let report = scanComparisonReportText() else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
        output += "\nCopied scan comparison report to clipboard."
    }

    func exportScanComparisonReport() {
        guard let report = scanComparisonReportText() else {
            return
        }

        let panel = NSSavePanel()
        panel.title = "Export Scan Comparison Report"
        panel.nameFieldStringValue = "nmap-scan-comparison.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true

        if panel.runModal() == .OK, let destinationURL = panel.url {
            do {
                try report.write(to: destinationURL, atomically: true, encoding: .utf8)
                output += "\nExported scan comparison report to: \(destinationURL.path)"
            } catch {
                output += "\nFailed to export scan comparison report: \(error.localizedDescription)"
            }
        }
    }

    func scanComparisonReportText() -> String? {
        guard let baselineCompareScanID,
              let comparisonCompareScanID,
              let baselineScan = scanHistory.savedScans.first(where: { $0.id == baselineCompareScanID }),
              let comparisonScan = scanHistory.savedScans.first(where: { $0.id == comparisonCompareScanID }),
              let comparison = currentScanComparison else {
            return nil
        }

        let baselineLabel = scanComparisonScanLabel(baselineScan)
        let comparisonLabel = scanComparisonScanLabel(comparisonScan)
        let generatedAt = Date().formatted(date: .abbreviated, time: .standard)
        let changeLines = scanComparisonNdiffStyleLines(comparison)

        return [
            "Nmap Scan Comparison Report",
            "Generated: \(generatedAt)",
            "",
            "Baseline Scan:",
            "  \(baselineLabel)",
            "  Date: \(baselineScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "  Command: \(baselineScan.command)",
            "  XML: \(baselineScan.xmlPath)",
            "  Hosts: \(baselineScan.hostCount)",
            "  Ports: \(baselineScan.portCount)",
            "  Tags: \(baselineScan.tags.isEmpty ? "(none)" : baselineScan.tags)",
            "  Notes: \(baselineScan.notes.isEmpty ? "(none)" : baselineScan.notes)",
            "",
            "Comparison Scan:",
            "  \(comparisonLabel)",
            "  Date: \(comparisonScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "  Command: \(comparisonScan.command)",
            "  XML: \(comparisonScan.xmlPath)",
            "  Hosts: \(comparisonScan.hostCount)",
            "  Ports: \(comparisonScan.portCount)",
            "  Tags: \(comparisonScan.tags.isEmpty ? "(none)" : comparisonScan.tags)",
            "  Notes: \(comparisonScan.notes.isEmpty ? "(none)" : comparisonScan.notes)",
            "",
            "Summary:",
            "  New Hosts: \(comparison.newHosts.count)",
            "  Missing Hosts: \(comparison.missingHosts.count)",
            "  New Open Ports: \(comparison.newOpenPorts.count)",
            "  Closed Ports: \(comparison.closedPorts.count)",
            "  Service Changes: \(comparison.changedServices.count)",
            "",
            "Ndiff-style Changes:",
            changeLines.joined(separator: "\n"),
            "",
            "Legend:",
            "  + added in comparison scan",
            "  - removed from comparison scan",
            "  ~ changed between scans",
            "",
            "Details:",
            "New Hosts:",
            scanComparisonReportSection(comparison.newHosts),
            "",
            "Missing Hosts:",
            scanComparisonReportSection(comparison.missingHosts),
            "",
            "New Open Ports:",
            scanComparisonReportSection(comparison.newOpenPorts),
            "",
            "Closed Ports:",
            scanComparisonReportSection(comparison.closedPorts),
            "",
            "Changed Services:",
            scanComparisonReportSection(comparison.changedServices)
        ].joined(separator: "\n")
    }

    func scanComparisonReportSection(_ rows: [String]) -> String {
        rows.isEmpty ? "No changes" : rows.map { "- \($0)" }.joined(separator: "\n")
    }

    func scanComparisonNdiffStyleLines(_ comparison: ScanComparison) -> [String] {
        var lines: [String] = []

        lines.append(contentsOf: comparison.newHosts.map { "+ Host added: \($0)" })
        lines.append(contentsOf: comparison.missingHosts.map { "- Host removed: \($0)" })
        lines.append(contentsOf: comparison.newOpenPorts.map { "+ Open port: \($0)" })
        lines.append(contentsOf: comparison.closedPorts.map { "- Open port removed or closed: \($0)" })
        lines.append(contentsOf: comparison.changedServices.map { "~ Service changed: \($0)" })

        return lines.isEmpty ? ["No differences detected."] : lines
    }
}
