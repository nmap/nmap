import AppKit
import Foundation
import UniformTypeIdentifiers

extension ContentView {
    func loadSelectedSavedScanMetadata() {
        guard let selectedSavedScan else {
            savedScanNotesText = ""
            savedScanTagsText = ""
            return
        }

        savedScanNotesText = selectedSavedScan.notes
        savedScanTagsText = selectedSavedScan.tags
    }

    func saveSelectedSavedScanMetadata() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let scanIndex = scanHistory.savedScans.firstIndex(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        var updatedScans = scanHistory.savedScans
        updatedScans[scanIndex].notes = savedScanNotesText.trimmingCharacters(in: .whitespacesAndNewlines)
        updatedScans[scanIndex].tags = normalizedSavedScanTags(savedScanTagsText)
        scanHistory.savedScans = updatedScans
        loadSelectedSavedScanMetadata()
        output += "\nSaved notes for saved scan: \(updatedScans[scanIndex].title)"
    }

    func clearSelectedSavedScanMetadata() {
        savedScanNotesText = ""
        savedScanTagsText = ""
        saveSelectedSavedScanMetadata()
    }

    func normalizedSavedScanTags(_ tags: String) -> String {
        tags
            .split { character in
                character == "," || character.isWhitespace
            }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ", ")
    }

    func useSelectedSavedScanAsBaseline() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        baselineCompareScanID = selectedSavedScanID
        if comparisonCompareScanID == selectedSavedScanID {
            comparisonCompareScanID = nil
        }
        selectedTab = "Compare"
        output += "\nSet selected saved scan as comparison baseline."
    }

    func useSelectedSavedScanAsComparison() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        comparisonCompareScanID = selectedSavedScanID
        if baselineCompareScanID == selectedSavedScanID {
            baselineCompareScanID = nil
        }
        selectedTab = "Compare"
        output += "\nSet selected saved scan as comparison target."
    }

    func reloadSelectedSavedScan() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        reloadSavedScan(id: selectedSavedScanID)
    }

    func revealSelectedSavedScanInFinder() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSWorkspace.shared.activateFileViewerSelecting([
            URL(fileURLWithPath: savedScan.xmlPath)
        ])
    }

    func openSelectedSavedScanExternally() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSWorkspace.shared.open(URL(fileURLWithPath: savedScan.xmlPath))
    }

    func useSelectedSavedScanCommand() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        let parsedCommand = scanFormValues(fromSavedCommand: savedScan.command)
        guard !parsedCommand.target.isEmpty else {
            output += "\nCould not load saved scan command into scan form: no target found."
            return
        }

        arguments = parsedCommand.arguments
        target = parsedCommand.target
        lastCommand = savedScan.command
        selectedTab = "Output"
        output += "\nLoaded saved scan command into scan form."
        output += "\nTarget: \(target)"
        output += "\nArguments: \(arguments.isEmpty ? "(none)" : arguments)"
    }

    func scanFormValues(fromSavedCommand command: String) -> (arguments: String, target: String) {
        var parts = shellSplit(command)

        if let firstPart = parts.first {
            let firstName = URL(fileURLWithPath: firstPart).lastPathComponent
            if firstPart == "nmap" || firstName == "nmap" {
                parts.removeFirst()
            }
        }

        var argumentValues: [String] = []
        var targetValues: [String] = []
        var index = 0

        while index < parts.count {
            let part = parts[index]

            if part == "-oX" || part == "-oA" || part == "-oN" || part == "-oG" || part == "-oS" {
                index += 2
                continue
            }

            if part.hasPrefix("-oX") || part.hasPrefix("-oA") || part.hasPrefix("-oN") || part.hasPrefix("-oG") || part.hasPrefix("-oS") {
                index += 1
                continue
            }

            if part == "--stylesheet" || part == "--webxml" || part == "--resume" || part == "-iL" || part == "-iR" {
                argumentValues.append(part)
                if index + 1 < parts.count {
                    argumentValues.append(parts[index + 1])
                    index += 2
                } else {
                    index += 1
                }
                continue
            }

            if part.hasPrefix("-") {
                argumentValues.append(part)
            } else {
                targetValues.append(part)
            }

            index += 1
        }

        return (argumentValues.joined(separator: " "), targetValues.joined(separator: " "))
    }

    func copySelectedSavedScanCommand() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(savedScan.command, forType: .string)
        output += "\nCopied saved scan command to clipboard: \(savedScan.command)"
    }

    func copySelectedSavedScanSummary() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        let summary = savedScanSummaryText(savedScan)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(summary, forType: .string)
        output += "\nCopied saved scan summary to clipboard."
    }

    func savedScanSummaryText(_ savedScan: SavedScan) -> String {
        [
            "Nmap Saved Scan Summary",
            "Title: \(savedScan.title)",
            "Date: \(savedScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "Command: \(savedScan.command)",
            "Hosts: \(savedScan.hostCount)",
            "Ports: \(savedScan.portCount)",
            "Tags: \(savedScan.tags.isEmpty ? "(none)" : savedScan.tags)",
            "Notes: \(savedScan.notes.isEmpty ? "(none)" : savedScan.notes)",
            "XML: \(savedScan.xmlPath)"
        ].joined(separator: "\n")
    }

    func reloadSavedScan(id savedScanID: SavedScan.ID) {
        guard let savedScan = scanHistory.savedScans.first(where: { $0.id == savedScanID }) else {
            return
        }

        scanHistory.selectedSavedScanID = savedScanID
        scanHistory.selectedSavedScanIDs = [savedScanID]

        let url = URL(fileURLWithPath: savedScan.xmlPath)
        let parsedHosts = parseNmapXML(at: url)
        let parsedPorts = parsedHosts.flatMap { $0.ports }

        hosts = parsedHosts
        selectedHostID = parsedHosts.first?.id
        lastXMLPath = savedScan.xmlPath
        lastCommand = savedScan.command
        exitStatus = nil
        status = parsedHosts.isEmpty ? "Reloaded saved scan with no hosts" : "Reloaded saved scan"
        selectedTab = "Hosts"

        output = "Reloaded saved scan: \(savedScan.xmlPath)\n"
        output += "Parsed \(parsedHosts.count) host\(parsedHosts.count == 1 ? "" : "s").\n"
        output += "Parsed \(parsedPorts.count) port result\(parsedPorts.count == 1 ? "" : "s")."
    }

    func exportSavedScanHistory() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.nameFieldStringValue = "nmap-saved-scan-history.json"

        guard panel.runModal() == .OK,
              let url = panel.url else {
            return
        }

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(scanHistory.savedScans)
            try data.write(to: url, options: .atomic)
            output += "\nExported \(scanHistory.savedScans.count) saved scan history item\(scanHistory.savedScans.count == 1 ? "" : "s") to: \(url.path)"
        } catch {
            output += "\nFailed to export saved scan history: \(error.localizedDescription)"
        }
    }

    func importSavedScanHistory() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true

        guard panel.runModal() == .OK,
              let url = panel.url else {
            return
        }

        do {
            let data = try Data(contentsOf: url)
            let importedScans = try JSONDecoder().decode([SavedScan].self, from: data)
                .filter { !$0.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

            guard !importedScans.isEmpty else {
                output += "\nNo saved scan history items found in selected JSON file."
                return
            }

            mergeImportedSavedScans(importedScans)
            output += "\nImported \(importedScans.count) saved scan history item\(importedScans.count == 1 ? "" : "s")."
        } catch {
            output += "\nFailed to import saved scan history: \(error.localizedDescription)"
        }
    }

    func mergeImportedSavedScans(_ importedScans: [SavedScan]) {
        var mergedScans = scanHistory.savedScans

        for importedScan in importedScans {
            if let existingIndex = mergedScans.firstIndex(where: { $0.id == importedScan.id || $0.xmlPath == importedScan.xmlPath }) {
                mergedScans[existingIndex] = importedScan
            } else {
                mergedScans.append(importedScan)
            }
        }

        mergedScans.sort { $0.scannedAt > $1.scannedAt }
        scanHistory.savedScans = mergedScans

        if let newestImportedScan = importedScans.sorted(by: { $0.scannedAt > $1.scannedAt }).first {
            scanHistory.selectedSavedScanID = newestImportedScan.id
            scanHistory.selectedSavedScanIDs = [newestImportedScan.id]
            loadSelectedSavedScanMetadata()
        }
    }

    var selectedSavedScanIDsForDeletion: Set<SavedScan.ID> {
        if !scanHistory.selectedSavedScanIDs.isEmpty {
            return scanHistory.selectedSavedScanIDs
        }

        if let selectedSavedScanID = scanHistory.selectedSavedScanID {
            return [selectedSavedScanID]
        }

        return []
    }

    func syncPrimarySavedScanSelection(_ selectedIDs: Set<SavedScan.ID>) {
        guard !selectedIDs.isEmpty else {
            scanHistory.selectedSavedScanID = nil
            loadSelectedSavedScanMetadata()
            return
        }

        if let selectedSavedScanID = scanHistory.selectedSavedScanID,
           selectedIDs.contains(selectedSavedScanID) {
            loadSelectedSavedScanMetadata()
            return
        }

        scanHistory.selectedSavedScanID = scanHistory.savedScans.first { selectedIDs.contains($0.id) }?.id
        loadSelectedSavedScanMetadata()
    }

    func deleteSelectedSavedScan() {
        let selectedIDs = selectedSavedScanIDsForDeletion
        guard !selectedIDs.isEmpty else {
            return
        }

        for savedScanID in selectedIDs {
            scanHistory.removeSavedScan(id: savedScanID, deleteFile: true)
        }

        scanHistory.selectedSavedScanIDs.removeAll()
        scanHistory.selectedSavedScanID = nil
        loadSelectedSavedScanMetadata()

        output += "\nDeleted \(selectedIDs.count) saved scan\(selectedIDs.count == 1 ? "" : "s")."
    }
    
    var selectedSavedScan: SavedScan? {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == selectedSavedScanID }
    }
}
