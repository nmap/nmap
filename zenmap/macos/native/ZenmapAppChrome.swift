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
        let scanSession = currentScanSessionSnapshot

        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(scanSession.isFooterActive ? .orange : .green)
                    .frame(width: 8, height: 8)

                Text(scanSession.footerStatusText)
                    .foregroundStyle(.secondary)

                Spacer()

                if scanSession.isFooterActive {
                    if let progressPercent = scanSession.footerProgressPercent {
                        ProgressView(value: progressPercent, total: 100)
                            .frame(width: 160)

                        Text(scanSession.footerOverallProgressText)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else if !scanSession.footerProgressMessageText.isEmpty {
                        Text(scanSession.footerProgressMessageText)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    if !scanSession.footerElapsedText.isEmpty {
                        Text(scanSession.footerElapsedText)
                            .foregroundStyle(.secondary)
                    } else if !scanSession.footerStartedText.isEmpty {
                        Text(scanSession.footerStartedText)
                            .foregroundStyle(.secondary)
                    }
                }

                if let exitStatus = scanSession.footerExitStatus {
                    Text("Exit \(exitStatus)")
                        .foregroundColor(exitStatus == 0 ? .secondary : .red)
                }
            }

            if scanSession.isFooterActive {
                HStack(spacing: 10) {
                    Text(scanSession.footerPhaseProgressText)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if !scanSession.footerEstimatedCompletionText.isEmpty {
                        Text(scanSession.footerEstimatedCompletionText)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()
                }
                .font(.caption)
                .padding(.leading, 18)

                HStack(spacing: 10) {
                    Text(scanSession.footerPhaseBreakdownText)
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
