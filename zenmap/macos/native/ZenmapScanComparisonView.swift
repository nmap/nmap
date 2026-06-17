import Foundation
import SwiftUI

extension ContentView {
    var scanComparisonView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Compare Saved Scans")
                        .font(.title2.bold())
                    Text("Choose two saved XML scans to see host, port, and service changes.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Open Baseline") {
                    if let baselineCompareScanID {
                        reloadSavedScan(id: baselineCompareScanID)
                    }
                }
                .disabled(baselineCompareScanID == nil)

                Button("Open Comparison") {
                    if let comparisonCompareScanID {
                        reloadSavedScan(id: comparisonCompareScanID)
                    }
                }
                .disabled(comparisonCompareScanID == nil)

                Button("Copy Report") {
                    copyScanComparisonReport()
                }
                .disabled(currentScanComparison == nil)

                Button("Export Report...") {
                    exportScanComparisonReport()
                }
                .disabled(currentScanComparison == nil)

                Button("Clear") {
                    baselineCompareScanID = nil
                    comparisonCompareScanID = nil
                }
                .disabled(baselineCompareScanID == nil && comparisonCompareScanID == nil)
            }

            if scanHistory.savedScans.count < 2 {
                emptyResultsView("Save at least two scans to compare them.")
            } else {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Baseline")
                            .font(.headline)
                        Picker("Baseline", selection: $baselineCompareScanID) {
                            Text("Choose scan").tag(Optional<SavedScan.ID>.none)
                            ForEach(scanHistory.savedScans) { scan in
                                Text(scanComparisonScanLabel(scan)).tag(Optional(scan.id))
                            }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 420)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Comparison")
                            .font(.headline)
                        Picker("Comparison", selection: $comparisonCompareScanID) {
                            Text("Choose scan").tag(Optional<SavedScan.ID>.none)
                            ForEach(scanHistory.savedScans) { scan in
                                Text(scanComparisonScanLabel(scan)).tag(Optional(scan.id))
                            }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 420)
                    }
                }

                HStack(alignment: .top, spacing: 12) {
                    if let baselineScan = selectedBaselineComparisonScan {
                        scanComparisonMetadataCard(title: "Baseline Metadata", scan: baselineScan)
                    }

                    if let comparisonScan = selectedComparisonComparisonScan {
                        scanComparisonMetadataCard(title: "Comparison Metadata", scan: comparisonScan)
                    }
                }

                if baselineCompareScanID == comparisonCompareScanID && baselineCompareScanID != nil {
                    emptyResultsView("Choose two different saved scans.")
                } else if let comparison = currentScanComparison {
                    scanComparisonSummaryView(comparison)
                } else {
                    emptyResultsView("Choose a baseline scan and a comparison scan.")
                }
            }
        }
        .padding()
    }

    var selectedBaselineComparisonScan: SavedScan? {
        guard let baselineCompareScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == baselineCompareScanID }
    }

    var selectedComparisonComparisonScan: SavedScan? {
        guard let comparisonCompareScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == comparisonCompareScanID }
    }

    func scanComparisonMetadataCard(title: String, scan: SavedScan) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 6) {
                Text(scan.title)
                    .font(.headline)
                    .textSelection(.enabled)

                Text(scan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(.secondary)

                Text("Command: \(scan.command)")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)

                Text("Hosts: \(scan.hostCount)    Ports: \(scan.portCount)")
                    .foregroundStyle(.secondary)

                Text("Tags: \(scan.tags.isEmpty ? "(none)" : scan.tags)")
                    .textSelection(.enabled)

                Text("Notes: \(scan.notes.isEmpty ? "(none)" : scan.notes)")
                    .textSelection(.enabled)
                    .lineLimit(4)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    func scanComparisonSummaryView(_ comparison: ScanComparison) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    scanComparisonMetricCard(title: "New Hosts", value: comparison.newHosts.count, systemImage: "plus.circle")
                    scanComparisonMetricCard(title: "Missing Hosts", value: comparison.missingHosts.count, systemImage: "minus.circle")
                    scanComparisonMetricCard(title: "New Open Ports", value: comparison.newOpenPorts.count, systemImage: "lock.open")
                    scanComparisonMetricCard(title: "Closed Ports", value: comparison.closedPorts.count, systemImage: "lock")
                    scanComparisonMetricCard(title: "Service Changes", value: comparison.changedServices.count, systemImage: "arrow.triangle.2.circlepath")
                }

                scanComparisonSection(title: "New Hosts", rows: comparison.newHosts)
                scanComparisonSection(title: "Missing Hosts", rows: comparison.missingHosts)
                scanComparisonSection(title: "New Open Ports", rows: comparison.newOpenPorts)
                scanComparisonSection(title: "Closed Ports", rows: comparison.closedPorts)
                scanComparisonSection(title: "Changed Services", rows: comparison.changedServices)
            }
        }
    }

    func scanComparisonMetricCard(title: String, value: Int, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
                Spacer()
            }

            Text("\(value)")
                .font(.title.bold())

            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }

    func scanComparisonSection(title: String, rows: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)

            if rows.isEmpty {
                Text("No changes")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(rows, id: \.self) { row in
                        Text(row)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 3)
                    }
                }
                .padding()
                .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }
}
