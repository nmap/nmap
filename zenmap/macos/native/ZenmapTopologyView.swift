import Foundation
import SwiftUI

extension ContentView {
    var topologyView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Topology")
                        .font(.headline)
                    Text("Hosts from the current scan arranged as a simple network map.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text("\(hosts.count) host\(hosts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedHostAddress()
                } label: {
                    Label("Copy Address", systemImage: "number")
                }
                .disabled(selectedHost == nil)
                .help("Copy the selected topology host address")

                Button {
                    copySelectedHostSummary()
                } label: {
                    Label("Copy Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedHost == nil)
                .help("Copy a summary of the selected topology host")

                Button {
                    copySelectedHostOpenPorts()
                } label: {
                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                }
                .disabled(selectedHost == nil)
                .help("Copy open ports for the selected topology host")

                Button {
                    selectedTab = "Details"
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .disabled(selectedHost == nil)
                .help("Show details for the selected topology host")
            }

            if hosts.isEmpty {
                emptyResultsView("Run or open a scan to populate the topology map.")
            } else {
                GeometryReader { geometry in
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Color.secondary.opacity(0.08))

                        if hosts.count > 1 {
                            ForEach(Array(hosts.enumerated()), id: \.element.id) { index, host in
                                let center = CGPoint(x: geometry.size.width / 2, y: geometry.size.height / 2)
                                let point = topologyPoint(for: index, total: hosts.count, in: geometry.size)

                                Path { path in
                                    path.move(to: center)
                                    path.addLine(to: point)
                                }
                                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                            }
                        }

                        VStack(spacing: 4) {
                            Image(systemName: "network")
                                .font(.title2)
                            Text("Scan")
                                .font(.caption.bold())
                            Text("\(allPorts.count) ports")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .padding(12)
                        .background(
                            Circle()
                                .fill(Color(nsColor: .windowBackgroundColor))
                                .shadow(radius: 4)
                        )
                        .position(x: geometry.size.width / 2, y: geometry.size.height / 2)

                        ForEach(Array(hosts.enumerated()), id: \.element.id) { index, host in
                            let point = topologyPoint(for: index, total: hosts.count, in: geometry.size)

                            Button {
                                selectedHostID = host.id
                            } label: {
                                topologyNode(host)
                            }
                            .buttonStyle(.plain)
                            .contextMenu {
                                Button("Copy Address") {
                                    selectedHostID = host.id
                                    copySelectedHostAddress()
                                }

                                Button("Copy Host Summary") {
                                    selectedHostID = host.id
                                    copySelectedHostSummary()
                                }

                                Button("Copy Open Ports") {
                                    selectedHostID = host.id
                                    copySelectedHostOpenPorts()
                                }

                                Divider()

                                Button("Show Details") {
                                    selectedHostID = host.id
                                    selectedTab = "Details"
                                }
                            }
                            .position(point)
                        }
                    }
                }
                .frame(minHeight: 430)

                if let selectedHost {
                    GroupBox("Selected Host") {
                        VStack(alignment: .leading, spacing: 10) {
                            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                                GridRow {
                                    Text("Address")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.address)
                                        .font(.system(.body, design: .monospaced))
                                        .textSelection(.enabled)
                                }

                                GridRow {
                                    Text("Hostname")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.hostname.isEmpty ? "-" : selectedHost.hostname)
                                        .textSelection(.enabled)
                                }

                                GridRow {
                                    Text("Status")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.status)
                                }

                                GridRow {
                                    Text("Open Ports")
                                        .foregroundStyle(.secondary)
                                    Text("\(selectedHost.openPortCount)")
                                }
                            }

                            HStack {
                                Button {
                                    copySelectedHostAddress()
                                } label: {
                                    Label("Copy Address", systemImage: "number")
                                }

                                Button {
                                    copySelectedHostSummary()
                                } label: {
                                    Label("Copy Summary", systemImage: "doc.on.doc")
                                }

                                Button {
                                    copySelectedHostOpenPorts()
                                } label: {
                                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                                }

                                Button {
                                    selectedTab = "Details"
                                } label: {
                                    Label("Details", systemImage: "info.circle")
                                }

                                Spacer()
                            }
                        }
                    }
                } else {
                    Text("Select a host node to show details.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }

    func topologyNode(_ host: ScannedHost) -> some View {
        let isSelected = host.id == selectedHostID
        let openPorts = host.openPortCount
        let width = min(190, max(120, 120 + (openPorts * 8)))

        return VStack(spacing: 5) {
            HStack(spacing: 6) {
                Circle()
                    .fill(openPorts > 0 ? Color.green : Color.secondary)
                    .frame(width: 8, height: 8)

                Text(host.displayName)
                    .font(.caption.bold())
                    .lineLimit(1)
            }

            Text(host.address)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Text("\(openPorts) open port\(openPorts == 1 ? "" : "s")")
                .font(.caption2)
                .foregroundStyle(.secondary)

            Text(host.status)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(width: CGFloat(width))
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(isSelected ? Color.accentColor.opacity(0.18) : Color(nsColor: .controlBackgroundColor))
                .shadow(radius: isSelected ? 5 : 2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(isSelected ? Color.accentColor : Color.secondary.opacity(0.25), lineWidth: isSelected ? 2 : 1)
        )
    }

    func topologyPoint(for index: Int, total: Int, in size: CGSize) -> CGPoint {
        let width = max(size.width, 1)
        let height = max(size.height, 1)
        let center = CGPoint(x: width / 2, y: height / 2)

        guard total > 1 else {
            return center
        }

        let radius = max(120, min(width, height) * 0.36)
        let angle = (Double(index) / Double(total)) * Double.pi * 2 - Double.pi / 2

        return CGPoint(
            x: center.x + CGFloat(cos(angle)) * radius,
            y: center.y + CGFloat(sin(angle)) * radius
        )
    }
}
