import AppKit
import Foundation

extension ContentView {
    func copyOutput() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }

    func copyDiagnosticInfo() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(diagnosticInfoText(), forType: .string)
        output += "\nCopied diagnostic info to clipboard."
    }

    func diagnosticInfoText() -> String {
        let nmapPath = nmapBinaryPath() ?? "unavailable"
        let nmapDirectory = nmapPath == "unavailable" ? "unavailable" : nmapDataDirectory(for: nmapPath)
        let bundlePath = Bundle.main.bundlePath
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
        let appBuild = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
        let processInfo = ProcessInfo.processInfo
        let macOSVersion = processInfo.operatingSystemVersionString
        let hostName = Host.current().localizedName ?? Host.current().name ?? "unknown"
        let nmapVersion = nmapVersionText(nmapPath: nmapPath, nmapDirectory: nmapDirectory)

        return [
            "Zenmap Diagnostic Info",
            "",
            "App:",
            "Bundle: \(bundlePath)",
            "Version: \(appVersion)",
            "Build: \(appBuild)",
            "",
            "System:",
            "macOS: \(macOSVersion)",
            "Host: \(hostName)",
            "Architecture: \(processInfo.machineHardwareName)",
            "",
            "Nmap Runtime:",
            "Nmap binary: \(nmapPath)",
            "NMAPDIR: \(nmapDirectory)",
            "Nmap version:",
            nmapVersion,
            "",
            "Last Scan:",
            "Command: \(lastCommand.isEmpty ? "none" : lastCommand)",
            "XML: \(lastXMLPath.isEmpty ? "none" : lastXMLPath)",
            "Exit status: \(exitStatus.map(String.init) ?? "none")",
            "Status: \(status)",
            "Hosts parsed: \(hosts.count)",
            "Ports parsed: \(allPorts.count)",
            "",
            "Privilege:",
            "Currently running: \(isRunning ? "yes" : "no")",
            "Privileged scan PID: \(privilegedScanPID.map(String.init) ?? "none")"
        ].joined(separator: "\n")
    }

    func nmapVersionText(nmapPath: String, nmapDirectory: String) -> String {
        guard nmapPath != "unavailable",
              FileManager.default.isExecutableFile(atPath: nmapPath) else {
            return "unavailable"
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: nmapPath)
        process.arguments = ["--version"]

        var environment = ProcessInfo.processInfo.environment
        if nmapDirectory != "unavailable" {
            environment["NMAPDIR"] = nmapDirectory
        }
        process.environment = environment

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "unavailable"
        } catch {
            return "unavailable (\(error.localizedDescription))"
        }
    }

    func printOutput() {
        let printView = NSTextView(frame: NSRect(x: 0, y: 0, width: 720, height: 960))
        printView.string = output
        printView.isEditable = false
        printView.font = NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)

        let printOperation = NSPrintOperation(view: printView)
        printOperation.jobTitle = lastCommand.isEmpty ? "Nmap Scan Output" : lastCommand
        printOperation.run()
    }
}
