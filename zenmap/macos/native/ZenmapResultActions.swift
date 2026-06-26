import AppKit
import Foundation

extension ContentView {
    func scanPortStateCount(_ state: String) -> Int {
        allPorts.filter { $0.state == state }.count
    }

    func hostPortStateCount(_ host: ScannedHost, state: String) -> Int {
        host.ports.filter { $0.state == state }.count
    }

    func sortedPorts(_ ports: [ScannedPort]) -> [ScannedPort] {
        ports.sorted {
            let leftNumber = Int($0.portNumber) ?? Int.max
            let rightNumber = Int($1.portNumber) ?? Int.max

            if leftNumber == rightNumber {
                return $0.protocolName < $1.protocolName
            }

            return leftNumber < rightNumber
        }
    }

    func copyScanDetailsSummary() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(scanDetailsSummaryText(), forType: .string)
        output += "\nCopied scan details summary to clipboard."
    }

    func copySelectedHostAddress() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHost.address, forType: .string)
        output += "\nCopied selected host address to clipboard: \(selectedHost.address)"
    }

    func copySelectedHostSummary() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHostSummaryText(selectedHost), forType: .string)
        output += "\nCopied selected host summary to clipboard."
    }

    func copySelectedHostOpenPorts() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHostOpenPortsText(selectedHost), forType: .string)
        output += "\nCopied selected host open ports to clipboard."
    }

    func copySelectedPortHostPort() {
        guard let selectedPort else {
            return
        }

        let hostPort = "\(selectedPort.hostAddress):\(selectedPort.portNumber)/\(selectedPort.protocolName)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(hostPort, forType: .string)
        output += "\nCopied selected port to clipboard: \(hostPort)"
    }

    func copySelectedPortSummary() {
        guard let selectedPort else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedPortSummaryText(selectedPort), forType: .string)
        output += "\nCopied selected port summary to clipboard."
    }

    func showSelectedPortHostDetails() {
        guard let selectedPort,
              let host = hosts.first(where: { $0.address == selectedPort.hostAddress }) else {
            return
        }

        selectedHostID = host.id
        selectedTab = "Details"
    }

    func selectedPortSummaryText(_ port: ScannedPort) -> String {
        [
            "Nmap Port Summary",
            "Host: \(port.hostAddress)",
            "Port: \(port.portNumber)/\(port.protocolName)",
            "State: \(port.state)",
            "Service: \(port.serviceName.isEmpty ? "None" : port.serviceName)",
            "Product: \(port.product.isEmpty ? "None" : port.product)",
            "Version: \(port.version.isEmpty ? "None" : port.version)",
            "Extra Info: \(port.extraInfo.isEmpty ? "None" : port.extraInfo)",
            "Summary: \(scanPortServiceDescription(port))"
        ].joined(separator: "\n")
    }

    func copySelectedServiceHostPort() {
        guard let selectedServicePort else {
            return
        }

        let hostPort = "\(selectedServicePort.hostAddress):\(selectedServicePort.portNumber)/\(selectedServicePort.protocolName)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(hostPort, forType: .string)
        output += "\nCopied selected service host and port to clipboard: \(hostPort)"
    }

    func copySelectedServiceSummary() {
        guard let selectedServicePort else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedServiceSummaryText(selectedServicePort), forType: .string)
        output += "\nCopied selected service summary to clipboard."
    }

    func copySelectedServiceProductVersion() {
        guard let selectedServicePort else {
            return
        }

        let productVersion = [
            selectedServicePort.product,
            selectedServicePort.version,
            selectedServicePort.extraInfo
        ]
        .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        .joined(separator: " ")

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(productVersion.isEmpty ? selectedServicePort.serviceName : productVersion, forType: .string)
        output += "\nCopied selected service product/version to clipboard."
    }

    func showSelectedServiceHostDetails() {
        guard let selectedServicePort,
              let host = hosts.first(where: { $0.address == selectedServicePort.hostAddress }) else {
            return
        }

        selectedHostID = host.id
        selectedTab = "Details"
    }

    func selectedServiceSummaryText(_ port: ScannedPort) -> String {
        [
            "Nmap Service Summary",
            "Host: \(port.hostAddress)",
            "Port: \(port.portNumber)/\(port.protocolName)",
            "State: \(port.state)",
            "Service: \(port.serviceName.isEmpty ? "None" : port.serviceName)",
            "Product: \(port.product.isEmpty ? "None" : port.product)",
            "Version: \(port.version.isEmpty ? "None" : port.version)",
            "Extra Info: \(port.extraInfo.isEmpty ? "None" : port.extraInfo)",
            "Summary: \(scanPortServiceDescription(port))"
        ].joined(separator: "\n")
    }

    func scanDetailsSummaryText() -> String {
        [
            "Nmap Scan Details",
            "Status: \(status)",
            "Command: \(lastCommand.isEmpty ? "None" : lastCommand)",
            "Exit status: \(exitStatus.map(String.init) ?? "None")",
            "Hosts: \(hosts.count)",
            "Ports: \(allPorts.count)",
            "Open ports: \(scanPortStateCount("open"))",
            "Filtered ports: \(scanPortStateCount("filtered"))",
            "Closed ports: \(scanPortStateCount("closed"))",
            "XML: \(lastXMLPath.isEmpty ? "None" : lastXMLPath)"
        ].joined(separator: "\n")
    }

    func selectedHostSummaryText(_ host: ScannedHost) -> String {
        var lines = [
            "Nmap Host Summary",
            "Host: \(host.displayName)",
            "Address: \(host.address)",
            "Hostname: \(host.hostname.isEmpty ? "None" : host.hostname)",
            "Status: \(host.status)",
            "Ports: \(host.ports.count)",
            "Open ports: \(hostPortStateCount(host, state: "open"))",
            "Filtered ports: \(hostPortStateCount(host, state: "filtered"))",
            "Closed ports: \(hostPortStateCount(host, state: "closed"))"
        ]

        let openPorts = sortedPorts(host.ports.filter { $0.state == "open" })
        if !openPorts.isEmpty {
            lines.append("")
            lines.append("Open Port Details:")
            lines.append(contentsOf: openPorts.map { port in
                "- \(port.portNumber)/\(port.protocolName) \(scanPortServiceDescription(port))"
            })
        }

        return lines.joined(separator: "\n")
    }

    func selectedHostOpenPortsText(_ host: ScannedHost) -> String {
        let openPorts = sortedPorts(host.ports.filter { $0.state == "open" })

        guard !openPorts.isEmpty else {
            return "No open ports for \(host.displayName)."
        }

        return openPorts
            .map { "\($0.portNumber)/\($0.protocolName) \(scanPortServiceDescription($0))" }
            .joined(separator: "\n")
    }
}
