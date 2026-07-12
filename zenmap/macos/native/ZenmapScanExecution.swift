import AppKit
import Foundation
import SwiftUI

extension ContentView {
    func isVerboseOrDebugArgument(_ argument: String) -> Bool {
        argument == "-v" ||
        argument == "-vv" ||
        argument == "-d" ||
        argument.hasPrefix("-v") ||
        argument.hasPrefix("-d") ||
        argument == "--verbose" ||
        argument.hasPrefix("--verbose=")
    }

    func resetPendingScanOutput() {
        pendingScanOutputFlushWorkItem?.cancel()
        pendingScanOutputFlushWorkItem = nil
        pendingScanOutputBuffer = ""
        pendingScanProgressBuffer = ""
    }

    func appendBufferedScanOutput(_ text: String, updateProgress: Bool = true) {
        guard !text.isEmpty else {
            return
        }

        pendingScanOutputBuffer += text
        if updateProgress {
            pendingScanProgressBuffer += text
        }

        schedulePendingScanOutputFlush()
    }

    func schedulePendingScanOutputFlush() {
        guard pendingScanOutputFlushWorkItem == nil else {
            return
        }

        let workItem = DispatchWorkItem {
            flushPendingScanOutput()
        }

        pendingScanOutputFlushWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.30, execute: workItem)
    }

    func flushPendingScanOutput() {
        pendingScanOutputFlushWorkItem?.cancel()
        pendingScanOutputFlushWorkItem = nil

        let outputText = pendingScanOutputBuffer
        let progressText = pendingScanProgressBuffer
        pendingScanOutputBuffer = ""
        pendingScanProgressBuffer = ""

        if !outputText.isEmpty {
            output += outputText
        }

        if !progressText.isEmpty {
            updateScanProgress(from: progressText)
        }
    }

    func runScan() {
        selectedTab = "Output"
        let targetList = splitTargets(target)
        let trimmedTarget = targetList.joined(separator: " ")
        guard !targetList.isEmpty else {
            output += "\nNo target specified."
            status = "Idle"
            return
        }

        let xmlURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Zenmap-\(UUID().uuidString).xml")
        var args = shellSplit(arguments)
        if autoAddStatsEvery && !args.contains("--stats-every") && !args.contains(where: { $0.hasPrefix("--stats-every=") }) {
            args.append(contentsOf: ["--stats-every", statsEveryValue])
        }
        if autoAddVerbose && !args.contains(where: isVerboseOrDebugArgument) {
            args.append("-v")
        }
        args.append(contentsOf: ["-oX", xmlURL.path])
        args.append(contentsOf: targetList)

        isRunning = true
        exitStatus = nil
        status = "Running"
        scanStartedAt = Date()
        scanProgressPercent = nil
        isUsingEstimatedScanProgress = false
        scanEstimatedCompletionText = ""
        scanProgressMessage = "Waiting for Nmap progress"
        scanPhaseProgressText = ""
        scanPortPhasePercent = nil
        scanServicePhasePercent = nil
        scanScriptPhasePercent = nil
        scanElapsedText = ""
        scanProgressBuffer = ""
        resetPendingScanOutput()
        lastCommand = commandPreview
        lastXMLPath = xmlURL.path
        hosts = []
        selectedHostID = nil
        let scanStartupLines = [
            "Running \(commandPreview)...",
            "XML output: \(xmlURL.path)",
            ""
        ]
        output = scanStartupLines.joined(separator: "\n") + "\n"

        switch ScanPrivilegeEvaluator.requirement(for: args) {
        case .normalUser:
            break

        case .administrator(let reason):
            Task {
                await runPrivilegedScan(
                    args: args,
                    xmlURL: xmlURL,
                    trimmedTarget: trimmedTarget,
                    reason: reason
                )
            }
            return
        }
        
        let process = Process()
        let pipe = Pipe()

        process.standardOutput = pipe
        process.standardError = pipe

        guard let binary = nmapBinaryPath() else {
            output += "Failed to run nmap: no executable nmap was found. Checked bundled Resources/bin/nmap, /Applications/nmap.app/Contents/Resources/bin/nmap, /usr/local/bin/nmap, and /opt/homebrew/bin/nmap."
            status = "Failed"
            isRunning = false
            scanStartedAt = nil
            return
        }

        let dataDirectory = nmapDataDirectory(for: binary)
        output = (
            scanStartupLines + [
                "Using nmap: \(binary)",
                "Using NMAPDIR: \(dataDirectory)",
                "Privilege mode: normal user",
                ""
            ]
        ).joined(separator: "\n") + "\n"

        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = args

        var env = ProcessInfo.processInfo.environment
        env["NMAPDIR"] = dataDirectory
        process.environment = env

        runningProcess = process

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                return
            }

            let text = String(data: data, encoding: .utf8) ?? ""
            DispatchQueue.main.async {
                appendBufferedScanOutput(text)
            }
        }

        process.terminationHandler = { finishedProcess in
            pipe.fileHandleForReading.readabilityHandler = nil
            let parsedHosts = parseNmapXML(at: xmlURL)

            DispatchQueue.main.async {
                flushPendingScanOutput()
                exitStatus = finishedProcess.terminationStatus
                output += "\nExit status: \(finishedProcess.terminationStatus)"
                updateScanProgress(from: output)
                status = finishedProcess.terminationStatus == 0 ? "Completed" : "Exited with errors"
                hosts = parsedHosts
                selectedHostID = parsedHosts.first?.id
                if finishedProcess.terminationStatus == 0 {
                    addSavedScan(title: trimmedTarget, command: lastCommand, xmlPath: xmlURL.path, parsedHosts: parsedHosts)
                }
                if finishedProcess.terminationStatus == 0 {
                    isUsingEstimatedScanProgress = false
                    scanProgressPercent = 100
                    scanProgressMessage = "Overall 100%"
                    scanPhaseProgressText = "Phase: complete"
                    scanPortPhasePercent = scanPortPhasePercent ?? 100
                    scanServicePhasePercent = scanServicePhasePercent ?? 100
                    scanScriptPhasePercent = scanScriptPhasePercent ?? 100
                    scanEstimatedCompletionText = ""
                }
                isRunning = false
                runningProcess = nil
                scanStartedAt = nil
            }
        }

        do {
            try process.run()
        } catch {
            pipe.fileHandleForReading.readabilityHandler = nil
            flushPendingScanOutput()
            output += "Failed to run nmap: \(error.localizedDescription)\n"
            output += "Expected bundled Resources/bin/nmap, /Applications/nmap.app/Contents/Resources/bin/nmap, /usr/local/bin/nmap, or /opt/homebrew/bin/nmap."
            status = "Failed"
            scanProgressPercent = nil
            isUsingEstimatedScanProgress = false
            scanProgressMessage = ""
            scanPhaseProgressText = ""
            scanPortPhasePercent = nil
            scanServicePhasePercent = nil
            scanScriptPhasePercent = nil
            scanEstimatedCompletionText = ""
            scanElapsedText = ""
            scanProgressBuffer = ""
            resetPendingScanOutput()
            isRunning = false
            runningProcess = nil
            scanStartedAt = nil
        }
    }

    @MainActor
    func confirmPrivilegedScan(reason: String) async -> Bool {
        let alert = NSAlert()
        alert.messageText = "Administrator Privileges Required"
        alert.informativeText = """
        This scan uses options that require root privileges.

        \(reason)

        Only the nmap scan process will be run as administrator. The GUI will continue running as your normal user.
        """
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Run as Administrator")
        alert.addButton(withTitle: "Cancel")

        return alert.runModal() == .alertFirstButtonReturn
    }

    @MainActor
    func runPrivilegedScan(args: [String], xmlURL: URL, trimmedTarget: String, reason: String) async {
        let shouldRun = await confirmPrivilegedScan(reason: reason)

        guard shouldRun else {
            output += "\nPrivileged scan cancelled by user.\n"
            status = "Cancelled"
            exitStatus = nil
            scanProgressPercent = nil
            isUsingEstimatedScanProgress = false
            scanProgressMessage = ""
            scanPhaseProgressText = ""
            scanPortPhasePercent = nil
            scanServicePhasePercent = nil
            scanScriptPhasePercent = nil
            scanEstimatedCompletionText = ""
            scanElapsedText = ""
            scanProgressBuffer = ""
            isRunning = false
            runningProcess = nil
            scanStartedAt = nil
            return
        }

        let logURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Zenmap-\(UUID().uuidString)-privileged.log")
        let statusURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Zenmap-\(UUID().uuidString)-privileged.status")
        let doneURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Zenmap-\(UUID().uuidString)-privileged.done")
        let childPIDURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("Zenmap-\(UUID().uuidString)-privileged.childpid")

        var privilegedStartupLines: [String]
        do {
            let privilegedBinary = try PrivilegedNmapRunner.bundledNmapPath()
            let privilegedDataDirectory = PrivilegedNmapRunner.nmapDataDirectory(for: privilegedBinary)
            privilegedStartupLines = [
                "Using nmap: \(privilegedBinary)",
                "Using NMAPDIR: \(privilegedDataDirectory)",
                "Privilege mode: administrator"
            ]
        } catch {
            privilegedStartupLines = [
                "Using nmap: unavailable before administrator launch (\(error.localizedDescription))",
                "Privilege mode: administrator"
            ]
        }
        privilegedStartupLines.append("Administrator authorization requested. Running nmap as root...")
        privilegedStartupLines.append("Privileged output log: \(logURL.path)")
        output += privilegedStartupLines.joined(separator: "\n") + "\n"
        status = "Running as administrator"
        scanProgressMessage = "Waiting for privileged Nmap scan"
        scanPhaseProgressText = "Phase: privileged scan starting"

        do {
            let pid = try await PrivilegedNmapRunner.start(
                arguments: args,
                logPath: logURL.path,
                statusPath: statusURL.path,
                donePath: doneURL.path,
                childPIDPath: childPIDURL.path
            )
            privilegedScanPID = pid
            privilegedChildPIDPath = childPIDURL.path
            output += "Privileged nmap PID: \(pid)\n"
            scanPhaseProgressText = "Phase: privileged scan running"
            resetPendingScanOutput()

            var lastOffset: UInt64 = 0

            while !FileManager.default.fileExists(atPath: doneURL.path) && PrivilegedNmapRunner.isRunning(pid: pid) {
                let newTextAndOffset = readNewText(from: logURL, startingAt: lastOffset)
                lastOffset = newTextAndOffset.offset

                if !newTextAndOffset.text.isEmpty {
                    appendBufferedScanOutput(newTextAndOffset.text)
                }

                try await Task.sleep(nanoseconds: 750_000_000)
            }

            let finalTextAndOffset = readNewText(from: logURL, startingAt: lastOffset)
            lastOffset = finalTextAndOffset.offset

            if !finalTextAndOffset.text.isEmpty {
                appendBufferedScanOutput(finalTextAndOffset.text)
                flushPendingScanOutput()
            }

            let parsedHosts = parseNmapXML(at: xmlURL)
            let realExitStatus = readExitStatus(from: statusURL) ?? 1
            let succeeded = realExitStatus == 0 && FileManager.default.fileExists(atPath: xmlURL.path)

            flushPendingScanOutput()
            output += "\nExit status: \(realExitStatus)\n"
            updateScanProgress(from: output)

            status = succeeded ? "Completed" : "Privileged scan exited with errors"
            exitStatus = Int32(realExitStatus)
            hosts = parsedHosts
            selectedHostID = parsedHosts.first?.id

            if succeeded {
                addSavedScan(
                    title: trimmedTarget,
                    command: lastCommand,
                    xmlPath: xmlURL.path,
                    parsedHosts: parsedHosts
                )

                isUsingEstimatedScanProgress = false
                scanProgressPercent = 100
                scanProgressMessage = "Overall 100%"
                scanPhaseProgressText = "Phase: complete"
                scanPortPhasePercent = scanPortPhasePercent ?? 100
                scanServicePhasePercent = scanServicePhasePercent ?? 100
                scanScriptPhasePercent = scanScriptPhasePercent ?? 100
                scanEstimatedCompletionText = ""
            } else {
                scanProgressPercent = nil
                isUsingEstimatedScanProgress = false
                scanProgressMessage = ""
                scanPhaseProgressText = ""
                scanPortPhasePercent = nil
                scanServicePhasePercent = nil
                scanScriptPhasePercent = nil
                scanEstimatedCompletionText = ""
            }
        } catch {
            let parsedHosts = parseNmapXML(at: xmlURL)

            flushPendingScanOutput()
            output += "\nFailed to run privileged nmap: \(error.localizedDescription)\n"
            output += "\nExit status: 1"

            status = "Privileged scan failed"
            exitStatus = 1
            hosts = parsedHosts
            selectedHostID = parsedHosts.first?.id
            scanProgressPercent = nil
            isUsingEstimatedScanProgress = false
            scanProgressMessage = ""
            scanPhaseProgressText = ""
            scanPortPhasePercent = nil
            scanServicePhasePercent = nil
            scanScriptPhasePercent = nil
            scanEstimatedCompletionText = ""
        }

        isRunning = false
        runningProcess = nil
        privilegedScanPID = nil
        privilegedChildPIDPath = nil
        scanStartedAt = nil
    }

    func readNewText(from url: URL, startingAt offset: UInt64) -> (text: String, offset: UInt64) {
        guard FileManager.default.fileExists(atPath: url.path),
              let handle = try? FileHandle(forReadingFrom: url) else {
            return ("", offset)
        }

        defer {
            try? handle.close()
        }

        do {
            try handle.seek(toOffset: offset)
            let data = handle.readDataToEndOfFile()
            let newOffset = offset + UInt64(data.count)
            let text = String(data: data, encoding: .utf8) ?? ""
            return (text, newOffset)
        } catch {
            return ("", offset)
        }
    }

    func readExitStatus(from url: URL) -> Int? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return nil
        }

        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    func stopScan() {
        if let process = runningProcess {
            process.terminate()
            status = "Stopping"
            output += "\n\nStopping scan...\n"
            return
        }

        if let pid = privilegedScanPID {
            status = "Stopping privileged scan"
            output += "\n\nStopping privileged scan PID \(pid)...\n"

            Task {
                do {
                    try await PrivilegedNmapRunner.stop(pid: pid, childPIDPath: privilegedChildPIDPath)
                    await MainActor.run {
                        output += "Privileged scan stop requested.\n"
                        privilegedScanPID = nil
                        privilegedChildPIDPath = nil
                        isRunning = false
                        status = "Stopped"
                        scanStartedAt = nil
                    }
                } catch {
                    await MainActor.run {
                        output += "Failed to stop privileged scan: \(error.localizedDescription)\n"
                    }
                }
            }
            return
        }
    }

    func clearResults() {
        output = "Ready. Choose a profile, enter a target, then run a scan."
        status = "Idle"
        exitStatus = nil
        scanStartedAt = nil
        lastCommand = ""
        lastXMLPath = ""
        hosts = []
        selectedHostID = nil
        scanProgressPercent = nil
        isUsingEstimatedScanProgress = false
        scanEstimatedCompletionText = ""
        scanProgressMessage = ""
        scanPhaseProgressText = ""
        scanPortPhasePercent = nil
        scanServicePhasePercent = nil
        scanScriptPhasePercent = nil
        scanElapsedText = ""
        scanProgressBuffer = ""
        outputFindText = ""
        outputFindSelection = 0
        resultsFilterText = ""
        selectedTab = "Output"
    }

    func nmapDataDirectory(for binaryPath: String) -> String {
        let nmapURL = URL(fileURLWithPath: binaryPath)
        var candidates: [String] = []

        candidates.append(
            nmapURL
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("share/nmap")
                .path
        )

        if let resourcePath = Bundle.main.resourceURL?.appendingPathComponent("share/nmap").path {
            candidates.append(resourcePath)
        }

        if let resourcePath = Bundle.main.resourceURL?.path {
            candidates.append(resourcePath)
        }

        candidates.append("/Applications/nmap.app/Contents/Resources/share/nmap")
        candidates.append("/usr/local/share/nmap")
        candidates.append("/opt/homebrew/share/nmap")

        for path in candidates {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
               isDirectory.boolValue {
                return path
            }
        }

        return Bundle.main.resourceURL?.path ?? ""
    }

    func nmapBinaryPath() -> String? {
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("bin/nmap").path,
            Bundle.main.resourceURL?.appendingPathComponent("nmap").path,
            "/Applications/nmap.app/Contents/Resources/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap"
        ].compactMap { $0 }

        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }

        return nil
    }

    func splitTargets(_ string: String) -> [String] {
        shellSplit(string)
    }

    func shellSplit(_ string: String) -> [String] {
        var result: [String] = []
        var current = ""
        var isInSingleQuotes = false
        var isInDoubleQuotes = false
        var shouldEscapeNext = false
        
        for character in string {
            if shouldEscapeNext {
                current.append(character)
                shouldEscapeNext = false
                continue
            }
            
            if character == "\\" {
                shouldEscapeNext = true
                continue
            }
            
            if character == "'" && !isInDoubleQuotes {
                isInSingleQuotes.toggle()
                continue
            }
            
            if character == "\"" && !isInSingleQuotes {
                isInDoubleQuotes.toggle()
                continue
            }
            
            if character.isWhitespace && !isInSingleQuotes && !isInDoubleQuotes {
                if !current.isEmpty {
                    result.append(current)
                    current = ""
                }
                continue
            }
            
            current.append(character)
        }
        
        if !current.isEmpty {
            result.append(current)
        }
        
        return result
    }
}
