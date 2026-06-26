import Foundation
import SwiftUI

extension ContentView {
    var savedScansView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Saved Scans")
                    .font(.headline)

                Spacer()

                Text("\(scanHistory.savedScans.count) saved")
                    .foregroundStyle(.secondary)

                Button {
                    openXML()
                } label: {
                    Image(systemName: "plus")
                }
                .help("Open Nmap XML")
                .disabled(isRunning)

                Button {
                    reloadSelectedSavedScan()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Reload Selected Scan")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanCommand()
                } label: {
                    Image(systemName: "arrow.uturn.forward")
                }
                .help("Use Command in Scan Form")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    copySelectedSavedScanCommand()
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .help("Copy Scan Command")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    copySelectedSavedScanSummary()
                } label: {
                    Image(systemName: "doc.plaintext")
                }
                .help("Copy Scan Summary")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanAsBaseline()
                } label: {
                    Image(systemName: "1.circle")
                }
                .help("Use Selected Scan as Comparison Baseline")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanAsComparison()
                } label: {
                    Image(systemName: "2.circle")
                }
                .help("Use Selected Scan as Comparison Target")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    revealSelectedSavedScanInFinder()
                } label: {
                    Image(systemName: "folder")
                }
                .help("Reveal XML in Finder")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    openSelectedSavedScanExternally()
                } label: {
                    Image(systemName: "arrow.up.right.square")
                }
                .help("Open XML Externally")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    exportSavedScanHistory()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .help("Export Saved Scan History")
                .disabled(scanHistory.savedScans.isEmpty)

                Button {
                    importSavedScanHistory()
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .help("Import Saved Scan History")

                Button(role: .destructive) {
                    deleteSelectedSavedScan()
                } label: {
                    Image(systemName: "trash")
                }
                .help("Remove Selected Scan(s)")
                .disabled(selectedSavedScanIDsForDeletion.isEmpty)
            }
            if scanHistory.savedScans.isEmpty {
                emptyResultsView("Completed scans and opened XML files will appear here for quick reload during this app session.")
            } else {
                savedScansFilterBar

                if filteredSavedScans.isEmpty {
                    emptyResultsView("No saved scans match the current filter.")
                } else {
                    Table(filteredSavedScans, selection: $scanHistory.selectedSavedScanIDs) {
                        TableColumn("Date") { scan in
                            Text(scan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                        }
                        TableColumn("Title") { scan in
                            Text(scan.title)
                        }
                        TableColumn("Command") { scan in
                            Text(scan.command)
                                .font(.system(.body, design: .monospaced))
                        }
                        TableColumn("Hosts") { scan in
                            Text("\(scan.hostCount)")
                        }
                        TableColumn("Ports") { scan in
                            Text("\(scan.portCount)")
                        }
                        TableColumn("Tags") { scan in
                            Text(scan.tags.isEmpty ? "-" : scan.tags)
                        }
                        TableColumn("XML") { scan in
                            Text(scan.xmlPath)
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    .contextMenu {
                        Button("Use as Baseline") {
                            useSelectedSavedScanAsBaseline()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Use as Comparison Target") {
                            useSelectedSavedScanAsComparison()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Divider()

                        Button("Copy Scan Summary") {
                            copySelectedSavedScanSummary()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Copy Scan Command") {
                            copySelectedSavedScanCommand()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Divider()

                        Button("Reveal XML in Finder") {
                            revealSelectedSavedScanInFinder()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Open XML Externally") {
                            openSelectedSavedScanExternally()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)
                    }
                .onChange(of: scanHistory.selectedSavedScanIDs) { _, selectedIDs in
                    syncPrimarySavedScanSelection(selectedIDs)
                }


                    savedScanMetadataEditor
                }

                HStack {
                    Spacer()

                    Button(role: .destructive) {
                        scanHistory.clearSavedScans(deleteFiles: true)
                    } label: {
                        Label("Clear History", systemImage: "trash.slash")
                    }
                }
            }
        }
        .padding()
    }
}
