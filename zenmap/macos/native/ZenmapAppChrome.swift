import Foundation
import SwiftUI

extension ContentView {
    var sidebar: some View {
        List(selection: $selectedTab) {
            Section("Scan") {
                Label("Output", systemImage: "terminal")
                    .tag("Output")
                Label("Hosts", systemImage: "desktopcomputer")
                    .tag("Hosts")
                Label("Ports", systemImage: "list.bullet.rectangle")
                    .tag("Ports")
                Label("Services", systemImage: "network")
                    .tag("Services")
                Label("Details", systemImage: "info.circle")
                    .tag("Details")
            }
            
            Section("History") {
                Label("Saved Scans", systemImage: "archivebox")
                    .tag("Saved Scans")
                Label("Compare", systemImage: "rectangle.split.2x1")
                    .tag("Compare")
            }

            Section("Later") {
                Label("Topology", systemImage: "point.3.connected.trianglepath.dotted")
                    .tag("Topology")
                Label("Profiles", systemImage: "slider.horizontal.3")
                    .tag("Profiles")
                Label("Settings", systemImage: "gearshape")
                    .tag("Settings")
            }
        }
        .navigationTitle("Nmap")
    }

    var tabView: some View {
        TabView(selection: $selectedTab) {
            outputView
                .tabItem { Label("Output", systemImage: "terminal") }
                .tag("Output")
            
            hostsView
                .tabItem { Label("Hosts", systemImage: "desktopcomputer") }
                .tag("Hosts")
            
            portsView
                .tabItem { Label("Ports", systemImage: "list.bullet.rectangle") }
                .tag("Ports")
            
            servicesView
                .tabItem { Label("Services", systemImage: "network") }
                .tag("Services")
            
            detailsView
                .tabItem { Label("Details", systemImage: "info.circle") }
                .tag("Details")
            
            savedScansView
                .tabItem { Label("Saved Scans", systemImage: "archivebox") }
                .tag("Saved Scans")
            
            scanComparisonView
                .tabItem { Label("Compare", systemImage: "rectangle.split.2x1") }
                .tag("Compare")
            
            topologyView
                .tabItem { Label("Topology", systemImage: "point.3.connected.trianglepath.dotted") }
                .tag("Topology")
            
            profilesView
                .tabItem { Label("Profiles", systemImage: "slider.horizontal.3") }
                .tag("Profiles")
            
            settingsView
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag("Settings")
        }
    }

    var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(isRunning ? .orange : .green)
                    .frame(width: 8, height: 8)

                Text(status)
                    .foregroundStyle(.secondary)

                Spacer()

                if isRunning {
                    if let scanProgressPercent {
                        ProgressView(value: scanProgressPercent, total: 100)
                            .frame(width: 160)

                        Text(String(format: "Overall %.0f%%", scanProgressPercent))
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else if !scanProgressMessage.isEmpty {
                        Text(scanProgressMessage)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    if !scanElapsedText.isEmpty {
                        Text(scanElapsedText)
                            .foregroundStyle(.secondary)
                    } else if let started = scanStartedAt {
                        Text("Started \(started.formatted(date: .omitted, time: .standard))")
                            .foregroundStyle(.secondary)
                    }
                }

                if let exitStatus {
                    Text("Exit \(exitStatus)")
                        .foregroundColor(exitStatus == 0 ? .secondary : .red)
                }
            }

            if isRunning {
                HStack(spacing: 10) {
                    Text(scanPhaseProgressText.isEmpty ? "Phase: waiting for Nmap timing" : scanPhaseProgressText)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if !scanEstimatedCompletionText.isEmpty {
                        Text(scanEstimatedCompletionText)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()
                }
                .font(.caption)
                .padding(.leading, 18)

                HStack(spacing: 10) {
                    Text(scanPhaseBreakdownText)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Spacer()
                }
                .font(.caption)
                .padding(.leading, 18)
            }
        }
        .font(.callout)
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
}
