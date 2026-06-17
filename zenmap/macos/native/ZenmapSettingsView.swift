import Foundation
import SwiftUI

extension ContentView {
    var settingsView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Settings")
                        .font(.title2.bold())
                    Text("Control default scan behavior and startup values.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Apply Defaults Now") {
                    applyScanDefaults()
                }

                Button("Reset Defaults") {
                    resetScanDefaults()
                }
            }

            GroupBox("Scan Behavior") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                    GridRow {
                        Text("Verbose output")
                            .foregroundStyle(.secondary)
                        Toggle("Auto-add -v when no verbose/debug flag is present", isOn: $autoAddVerbose)
                    }

                    GridRow {
                        Text("Progress stats")
                            .foregroundStyle(.secondary)
                        Toggle("Auto-add --stats-every", isOn: $autoAddStatsEvery)
                    }

                    GridRow {
                        Text("Stats interval")
                            .foregroundStyle(.secondary)
                        Picker("Stats interval", selection: $statsEveryValue) {
                            Text("5 seconds").tag("5s")
                            Text("10 seconds").tag("10s")
                            Text("30 seconds").tag("30s")
                            Text("60 seconds").tag("60s")
                        }
                        .labelsHidden()
                        .disabled(!autoAddStatsEvery)
                    }
                }
                .padding(.vertical, 4)
            }

            GroupBox("Defaults") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                    GridRow {
                        Text("Default target")
                            .foregroundStyle(.secondary)
                        TextField("scanme.nmap.org", text: $defaultTarget)
                            .textFieldStyle(.roundedBorder)
                    }

                    GridRow {
                        Text("Default profile")
                            .foregroundStyle(.secondary)
                        Picker("Default profile", selection: $defaultProfileName) {
                            ForEach(profiles) { profile in
                                Text(profile.name).tag(profile.name)
                            }
                        }
                        .labelsHidden()
                    }
                }
                .padding(.vertical, 4)
            }

            GroupBox("Current Effective Defaults") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    GridRow {
                        Text("Target")
                            .foregroundStyle(.secondary)
                        Text(defaultTarget.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "scanme.nmap.org" : defaultTarget)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }

                    GridRow {
                        Text("Profile")
                            .foregroundStyle(.secondary)
                        Text(defaultProfileName)
                    }

                    GridRow {
                        Text("Auto arguments")
                            .foregroundStyle(.secondary)
                        Text(settingsAutoArgumentsSummary)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }

            Spacer()
        }
        .padding()
    }
}
