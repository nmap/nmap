import Foundation
import SwiftUI

extension ContentView {
    var savedScansFilterBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)

            TextField("Filter saved scans by title, command, date, XML path, host count, or port count", text: $savedScansFilterText)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    // Consume Return so the window's default Run button does not start a new scan.
                }

            if isFilteringSavedScans {
                Button("Clear") {
                    savedScansFilterText = ""
                }
                .keyboardShortcut(.cancelAction)
            }
        }
    }

    var savedScanMetadataEditor: some View {
        GroupBox("Saved Scan Notes") {
            if let selectedSavedScan {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(selectedSavedScan.title)
                            .font(.headline)

                        Button {
                            useSelectedSavedScanAsBaseline()
                        } label: {
                            Label("Compare as Baseline", systemImage: "1.circle")
                        }

                        Button {
                            useSelectedSavedScanAsComparison()
                        } label: {
                            Label("Compare as Target", systemImage: "2.circle")
                        }

                        Spacer()

                        Text(selectedSavedScan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }

                    TextField("Tags, comma separated", text: $savedScanTagsText)
                        .textFieldStyle(.roundedBorder)

                    TextEditor(text: $savedScanNotesText)
                        .font(.body)
                        .frame(minHeight: 70)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(.quaternary)
                        )

                    HStack {
                        Button {
                            saveSelectedSavedScanMetadata()
                        } label: {
                            Label("Save Notes", systemImage: "square.and.arrow.down")
                        }

                        Button {
                            clearSelectedSavedScanMetadata()
                        } label: {
                            Label("Clear Notes", systemImage: "eraser")
                        }
                        .disabled(savedScanNotesText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && savedScanTagsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                        Spacer()
                    }
                }
            } else {
                Text("Select a saved scan to add notes or tags.")
                    .foregroundStyle(.secondary)
            }
        }
        .onChange(of: scanHistory.selectedSavedScanID) { _, _ in
            loadSelectedSavedScanMetadata()
        }
        .onAppear {
            loadSelectedSavedScanMetadata()
        }
    }
}
