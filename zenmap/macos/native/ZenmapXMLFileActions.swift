import AppKit
import Foundation
import UniformTypeIdentifiers

extension ContentView {
    func saveCurrentXML() {
        guard !lastXMLPath.isEmpty else {
            output += "\nNo XML scan result is available to save."
            return
        }

        let sourceURL = URL(fileURLWithPath: lastXMLPath)

        let panel = NSSavePanel()
        panel.title = "Save Nmap XML"
        panel.nameFieldStringValue = "nmap-scan.xml"
        panel.allowedContentTypes = [.xml]
        panel.canCreateDirectories = true

        if panel.runModal() == .OK, let destinationURL = panel.url {
            do {
                if FileManager.default.fileExists(atPath: destinationURL.path) {
                    try FileManager.default.removeItem(at: destinationURL)
                }
                try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                output += "\nSaved XML to: \(destinationURL.path)"
            } catch {
                output += "\nFailed to save XML: \(error.localizedDescription)"
            }
        }
    }

    func saveAllScansToDirectory() {
        guard !scanHistory.savedScans.isEmpty else {
            output += "\nNo saved scans are available to export."
            return
        }

        let panel = NSOpenPanel()
        panel.title = "Save All Scans to Directory"
        panel.prompt = "Choose"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false

        if panel.runModal() == .OK, let directoryURL = panel.url {
            var savedCount = 0
            var failedCount = 0

            for scan in scanHistory.savedScans {
                let sourceURL = URL(fileURLWithPath: scan.xmlPath)
                let destinationName = savedScanFilename(title: scan.title, date: scan.scannedAt)
                let destinationURL = directoryURL.appendingPathComponent(destinationName)

                do {
                    if FileManager.default.fileExists(atPath: destinationURL.path) {
                        try FileManager.default.removeItem(at: destinationURL)
                    }
                    try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
                    savedCount += 1
                } catch {
                    failedCount += 1
                }
            }

            output += "\nSaved \(savedCount) scan\(savedCount == 1 ? "" : "s") to: \(directoryURL.path)"
            if failedCount > 0 {
                output += "\nFailed to save \(failedCount) scan\(failedCount == 1 ? "" : "s")."
            }
        }
    }

    func openXML() {
        let panel = NSOpenPanel()
        panel.title = "Open Nmap XML"
        panel.allowedContentTypes = [.xml]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true

        if panel.runModal() == .OK, let url = panel.url {
            let parsedHosts = parseNmapXML(at: url)

            hosts = parsedHosts
            selectedHostID = parsedHosts.first?.id
            lastXMLPath = url.path
            lastCommand = "Opened XML file"
            exitStatus = nil
            status = parsedHosts.isEmpty ? "Opened XML with no hosts" : "Opened XML"
            selectedTab = "Hosts"

            let parsedPorts = parsedHosts.flatMap { $0.ports }
            addSavedScan(title: url.lastPathComponent, command: "Opened XML file", xmlPath: url.path, parsedHosts: parsedHosts)
            output = "Opened XML: \(url.path)\n"
            output += "Parsed \(parsedHosts.count) host\(parsedHosts.count == 1 ? "" : "s").\n"
            output += "Parsed \(parsedPorts.count) port result\(parsedPorts.count == 1 ? "" : "s")."
        }
    }
    
    func addSavedScan(title: String, command: String, xmlPath: String, parsedHosts: [ScannedHost]) {
        let durableXMLPath = copyXMLToSavedScansDirectory(sourcePath: xmlPath, title: title) ?? xmlPath

        let savedScan = SavedScan(
            title: title,
            command: command,
            xmlPath: durableXMLPath,
            scannedAt: Date(),
            hostCount: parsedHosts.count,
            portCount: parsedHosts.flatMap { $0.ports }.count
        )

        scanHistory.savedScans.removeAll { $0.xmlPath == durableXMLPath }
        scanHistory.savedScans.insert(savedScan, at: 0)
        scanHistory.selectedSavedScanID = savedScan.id
        scanHistory.selectedSavedScanIDs = [savedScan.id]
    }

    func copyXMLToSavedScansDirectory(sourcePath: String, title: String) -> String? {
        let sourceURL = URL(fileURLWithPath: sourcePath)

        guard FileManager.default.fileExists(atPath: sourceURL.path),
              let savedScansDirectory = savedScansDirectoryURL() else {
            return nil
        }

        do {
            try FileManager.default.createDirectory(
                at: savedScansDirectory,
                withIntermediateDirectories: true
            )

            let filename = savedScanFilename(title: title, date: Date())
            let destinationURL = savedScansDirectory.appendingPathComponent(filename)

            if FileManager.default.fileExists(atPath: destinationURL.path) {
                try FileManager.default.removeItem(at: destinationURL)
            }

            try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
            return destinationURL.path
        } catch {
            output += "\nFailed to copy saved scan XML: \(error.localizedDescription)"
            return nil
        }
    }

    func savedScanFilename(title: String, date: Date) -> String {
        let timestamp = ISO8601DateFormatter()
            .string(from: date)
            .replacingOccurrences(of: ":", with: "-")
        let baseTitle = (title as NSString).deletingPathExtension
        let safeTitle = baseTitle
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
            .replacingOccurrences(of: " ", with: "_")
        let finalTitle = safeTitle.isEmpty ? "nmap-scan" : safeTitle

        return "\(timestamp)-\(finalTitle).xml"
    }

    func savedScansDirectoryURL() -> URL? {
        guard let applicationSupportURL = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            return nil
        }

        return applicationSupportURL
            .appendingPathComponent("Zenmap", isDirectory: true)
            .appendingPathComponent("SavedScans", isDirectory: true)
    }
}
