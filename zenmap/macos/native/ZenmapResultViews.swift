import Foundation
import SwiftUI

extension ContentView {
    func scanMetricCard(title: String, value: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(value)
                .font(.title3.bold())
                .textSelection(.enabled)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    var resultsFilterBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)

            TextField("Filter results by host, port, state, service, or version", text: $resultsFilterText)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    // Consume Return so the window's default Run button does not start a new scan.
                }

            if isFilteringResults {
                Button("Clear") {
                    resultsFilterText = ""
                }
                .keyboardShortcut(.cancelAction)
            }
        }
    }

    func emptyResultsView(_ message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "tray")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(message)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    
    func placeholderView(title: String, systemImage: String, message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            
            Text(title)
                .font(.title.bold())
            
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    var hostsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Hosts")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredHosts.count) of \(hosts.count) hosts" : "\(hosts.count) host\(hosts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedHostAddress()
                } label: {
                    Label("Copy Address", systemImage: "number")
                }
                .disabled(selectedHost == nil)
                .help("Copy the selected host address")

                Button {
                    copySelectedHostSummary()
                } label: {
                    Label("Copy Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedHost == nil)
                .help("Copy a summary of the selected host")

                Button {
                    copySelectedHostOpenPorts()
                } label: {
                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                }
                .disabled(selectedHost == nil)
                .help("Copy open ports for the selected host")

                Button {
                    selectedTab = "Details"
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .disabled(selectedHost == nil)
                .help("Show details for the selected host")
            }
            
            resultsFilterBar

            if hosts.isEmpty {
                emptyResultsView("Run a scan to populate discovered hosts.")
            } else if filteredHosts.isEmpty {
                emptyResultsView("No hosts match the current filter.")
            } else {
                Table(filteredHosts, selection: $selectedHostID) {
                    TableColumn("Address") { host in
                        Text(host.address)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Hostname") { host in
                        Text(host.hostname.isEmpty ? "-" : host.hostname)
                    }
                    TableColumn("Status") { host in
                        Text(host.status)
                    }
                    TableColumn("Open Ports") { host in
                        Text("\(host.openPortCount)")
                    }
                }
                .contextMenu {
                    Button("Copy Address") {
                        copySelectedHostAddress()
                    }
                    .disabled(selectedHost == nil)

                    Button("Copy Host Summary") {
                        copySelectedHostSummary()
                    }
                    .disabled(selectedHost == nil)

                    Button("Copy Open Ports") {
                        copySelectedHostOpenPorts()
                    }
                    .disabled(selectedHost == nil)

                    Divider()

                    Button("Show Details") {
                        selectedTab = "Details"
                    }
                    .disabled(selectedHost == nil)
                }
            }
        }
        .padding()
    }
    
    var selectedPort: ScannedPort? {
        guard let selectedPortID else {
            return nil
        }

        return allPorts.first { $0.id == selectedPortID }
    }

    var selectedServicePort: ScannedPort? {
        guard let selectedServicePortID else {
            return nil
        }

        return allServicePorts.first { $0.id == selectedServicePortID }
    }

    var portsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Ports")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredPorts.count) of \(allPorts.count) port results" : "\(allPorts.count) port result\(allPorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedPortHostPort()
                } label: {
                    Label("Copy Host:Port", systemImage: "number")
                }
                .disabled(selectedPort == nil)
                .help("Copy the selected host and port")

                Button {
                    copySelectedPortSummary()
                } label: {
                    Label("Copy Port Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedPort == nil)
                .help("Copy a summary of the selected port")

                Button {
                    showSelectedPortHostDetails()
                } label: {
                    Label("Host Details", systemImage: "info.circle")
                }
                .disabled(selectedPort == nil)
                .help("Show details for the selected port's host")
            }
            
            resultsFilterBar

            if allPorts.isEmpty {
                emptyResultsView("Run a scan to populate port results.")
            } else if filteredPorts.isEmpty {
                emptyResultsView("No ports match the current filter.")
            } else {
                Table(filteredPorts, selection: $selectedPortID) {
                    TableColumn("Host") { port in
                        Text(port.hostAddress)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Port") { port in
                        Text("\(port.portNumber)/\(port.protocolName)")
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("State") { port in
                        Text(port.state)
                    }
                    TableColumn("Service") { port in
                        Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                    }
                    TableColumn("Version") { port in
                        Text(port.serviceSummary.isEmpty ? "-" : port.serviceSummary)
                    }
                }
                .contextMenu {
                    Button("Copy Host:Port") {
                        copySelectedPortHostPort()
                    }
                    .disabled(selectedPort == nil)

                    Button("Copy Port Summary") {
                        copySelectedPortSummary()
                    }
                    .disabled(selectedPort == nil)

                    Divider()

                    Button("Show Host Details") {
                        showSelectedPortHostDetails()
                    }
                    .disabled(selectedPort == nil)
                }
            }
        }
        .padding()
    }
    
    var servicesView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Services")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredServicePorts.count) of \(allServicePorts.count) service results" : "\(filteredServicePorts.count) service result\(filteredServicePorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedServiceHostPort()
                } label: {
                    Label("Copy Host:Port", systemImage: "number")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy the selected service host and port")

                Button {
                    copySelectedServiceSummary()
                } label: {
                    Label("Copy Service", systemImage: "doc.on.doc")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy a summary of the selected service")

                Button {
                    copySelectedServiceProductVersion()
                } label: {
                    Label("Copy Version", systemImage: "shippingbox")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy product and version for the selected service")

                Button {
                    showSelectedServiceHostDetails()
                } label: {
                    Label("Host Details", systemImage: "info.circle")
                }
                .disabled(selectedServicePort == nil)
                .help("Show details for the selected service's host")
            }
            
            resultsFilterBar

            if allServicePorts.isEmpty {
                emptyResultsView("Run a service detection scan to populate service results.")
            } else if filteredServicePorts.isEmpty {
                emptyResultsView("No services match the current filter.")
            } else {
                Table(filteredServicePorts, selection: $selectedServicePortID) {
                    TableColumn("Host") { port in
                        Text(port.hostAddress)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Service") { port in
                        Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                    }
                    TableColumn("Product") { port in
                        Text(port.product.isEmpty ? "-" : port.product)
                    }
                    TableColumn("Version") { port in
                        Text(port.version.isEmpty ? "-" : port.version)
                    }
                    TableColumn("Extra Info") { port in
                        Text(port.extraInfo.isEmpty ? "-" : port.extraInfo)
                    }
                }
                .contextMenu {
                    Button("Copy Host:Port") {
                        copySelectedServiceHostPort()
                    }
                    .disabled(selectedServicePort == nil)

                    Button("Copy Service Summary") {
                        copySelectedServiceSummary()
                    }
                    .disabled(selectedServicePort == nil)

                    Button("Copy Product/Version") {
                        copySelectedServiceProductVersion()
                    }
                    .disabled(selectedServicePort == nil)

                    Divider()

                    Button("Show Host Details") {
                        showSelectedServiceHostDetails()
                    }
                    .disabled(selectedServicePort == nil)
                }
            }
        }
        .padding()
    }
    
    var detailsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Scan Details", systemImage: "info.circle")
                    .font(.title2.bold())

                Spacer()

                Button {
                    copyScanDetailsSummary()
                } label: {
                    Label("Copy Scan Summary", systemImage: "doc.plaintext")
                }
                .disabled(hosts.isEmpty && lastCommand.isEmpty && lastXMLPath.isEmpty)

                if selectedHost != nil {
                    Button {
                        copySelectedHostSummary()
                    } label: {
                        Label("Copy Host Summary", systemImage: "doc.on.doc")
                    }

                    Button {
                        copySelectedHostOpenPorts()
                    } label: {
                        Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                    }
                }
            }

            HStack(spacing: 12) {
                scanMetricCard(title: "Hosts", value: "\(hosts.count)", systemImage: "desktopcomputer")
                scanMetricCard(title: "Ports", value: "\(allPorts.count)", systemImage: "network")
                scanMetricCard(title: "Open", value: "\(scanPortStateCount("open"))", systemImage: "checkmark.circle")
                scanMetricCard(title: "Filtered", value: "\(scanPortStateCount("filtered"))", systemImage: "line.3.horizontal.decrease.circle")
                scanMetricCard(title: "Closed", value: "\(scanPortStateCount("closed"))", systemImage: "xmark.circle")
            }

            GroupBox("Scan Context") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    GridRow {
                        Text("Status")
                            .foregroundStyle(.secondary)
                        Text(status)
                    }
                    GridRow {
                        Text("Last command")
                            .foregroundStyle(.secondary)
                        Text(lastCommand.isEmpty ? "None" : lastCommand)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Exit status")
                            .foregroundStyle(.secondary)
                        Text(exitStatus.map(String.init) ?? "None")
                    }
                    GridRow {
                        Text("XML output")
                            .foregroundStyle(.secondary)
                        Text(lastXMLPath.isEmpty ? "None" : lastXMLPath)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("NMAPDIR")
                            .foregroundStyle(.secondary)
                        Text(Bundle.main.resourceURL?.path ?? "Unavailable")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Bundled binary")
                            .foregroundStyle(.secondary)
                        Text(nmapBinaryPath() ?? "Not found")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }

            if let selectedHost {
                GroupBox("Selected Host") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(selectedHost.displayName)
                                    .font(.headline)
                                    .textSelection(.enabled)

                                Text(selectedHost.address)
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }

                            Spacer()

                            Text(selectedHost.status)
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(.quaternary, in: Capsule())
                        }

                        HStack(spacing: 12) {
                            scanMetricCard(title: "Host Ports", value: "\(selectedHost.ports.count)", systemImage: "number")
                            scanMetricCard(title: "Open", value: "\(hostPortStateCount(selectedHost, state: "open"))", systemImage: "checkmark.circle")
                            scanMetricCard(title: "Filtered", value: "\(hostPortStateCount(selectedHost, state: "filtered"))", systemImage: "line.3.horizontal.decrease.circle")
                            scanMetricCard(title: "Closed", value: "\(hostPortStateCount(selectedHost, state: "closed"))", systemImage: "xmark.circle")
                        }

                        if selectedHost.ports.isEmpty {
                            Text("No port results were parsed for this host.")
                                .foregroundStyle(.secondary)
                        } else {
                            Table(sortedPorts(selectedHost.ports)) {
                                TableColumn("Port") { port in
                                    Text("\(port.portNumber)/\(port.protocolName)")
                                        .font(.system(.body, design: .monospaced))
                                }
                                TableColumn("State") { port in
                                    Text(port.state)
                                }
                                TableColumn("Service") { port in
                                    Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                                }
                                TableColumn("Version") { port in
                                    Text(port.serviceSummary.isEmpty ? "-" : port.serviceSummary)
                                }
                            }
                            .frame(minHeight: 160)
                        }
                    }
                }
            } else {
                emptyResultsView("Select a host in the Hosts tab to view host details here.")
            }

            Spacer()
        }
        .padding()
    }
}
