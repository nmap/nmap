import Foundation

extension ContentView {
    func progressPercentText(from line: String) -> String? {
        guard let aboutRange = line.range(of: "About", options: [.caseInsensitive]),
              let percentRange = line[aboutRange.upperBound...].range(of: "%") else {
            return nil
        }

        let candidate = line[aboutRange.upperBound..<percentRange.lowerBound]
        let allowed = CharacterSet(charactersIn: "0123456789.")
        let percentText = String(candidate.unicodeScalars.filter { allowed.contains($0) })
        return percentText.isEmpty ? nil : percentText
    }

    func overallProgressPercent(from line: String, phasePercent: Double) -> (percent: Double, overallMessage: String, phaseMessage: String)? {
        let normalizedPhasePercent = min(max(phasePercent, 0), 100)

        if line.contains("Connect Scan Timing:") || line.contains("SYN Stealth Scan Timing:") {
            scanPortPhasePercent = normalizedPhasePercent
            let overall = min(15 + (normalizedPhasePercent * 0.50), 65)
            return (
                overall,
                String(format: "Overall %.0f%%", overall),
                String(format: "Phase: port scan %.1f%%", normalizedPhasePercent)
            )
        }

        if line.contains("Service scan Timing:") {
            scanServicePhasePercent = normalizedPhasePercent
            let overall = min(65 + (normalizedPhasePercent * 0.15), 80)
            return (
                overall,
                String(format: "Overall %.0f%%", overall),
                String(format: "Phase: service scan %.1f%%", normalizedPhasePercent)
            )
        }

        if line.contains("NSE Timing:") {
            scanScriptPhasePercent = normalizedPhasePercent
            let overall = min(80 + (normalizedPhasePercent * 0.16), 96)
            return (
                overall,
                String(format: "Overall %.0f%%", overall),
                String(format: "Phase: script scan %.1f%%", normalizedPhasePercent)
            )
        }

        return nil
    }

    func progressFloorPercent(from line: String) -> Double? {
        if line.hasPrefix("Completed Connect Scan") || line.hasPrefix("Completed SYN Stealth Scan") {
            scanPortPhasePercent = 100
            return 65
        }

        if line.hasPrefix("Completed Service scan") {
            scanServicePhasePercent = 100
            return 80
        }

        if line.hasPrefix("Nmap done") {
            return 98
        }

        if line.hasPrefix("Nmap scan report") {
            return nil
        }

        if line.contains("NSE Timing:") || line.hasPrefix("NSE: Script scanning") {
            return 85
        }

        if line.contains("Service scan Timing:") || line.contains("undergoing Service Scan") || line.hasPrefix("Initiating Service scan") {
            return 70
        }

        if line.contains("Connect Scan Timing:") || line.contains("SYN Stealth Scan Timing:") || line.contains("undergoing Connect Scan") || line.contains("undergoing SYN Stealth Scan") {
            return 25
        }

        if line.hasPrefix("Completed Ping Scan") || line.hasPrefix("Initiating Connect Scan") || line.hasPrefix("Initiating SYN Stealth Scan") {
            return 15
        }

        if line.hasPrefix("Initiating Ping Scan") || line.hasPrefix("Scanning ") {
            return 5
        }

        return nil
    }

    func updateScanProgress(from text: String) {
        guard isRunning else {
            return
        }

        scanProgressBuffer += text
        if scanProgressBuffer.count > 20000 {
            scanProgressBuffer = String(scanProgressBuffer.suffix(20000))
        }

        let normalizedProgressText = scanProgressBuffer
            .replacingOccurrences(of: "\r", with: "\n")
        let lines = normalizedProgressText.components(separatedBy: .newlines)
        for line in lines {
            let trimmedLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedLine.isEmpty else {
                continue
            }

            if let percentText = progressPercentText(from: trimmedLine),
               let phasePercent = Double(percentText) {
                let wasUsingEstimatedScanProgress = isUsingEstimatedScanProgress
                isUsingEstimatedScanProgress = false
                let normalizedPhasePercent = min(max(phasePercent, 0), 100)
                if let overallProgress = overallProgressPercent(from: trimmedLine, phasePercent: normalizedPhasePercent) {
                    if wasUsingEstimatedScanProgress {
                        scanProgressPercent = overallProgress.percent
                    } else {
                        scanProgressPercent = max(scanProgressPercent ?? 0, overallProgress.percent)
                    }
                    scanProgressMessage = overallProgress.overallMessage
                    scanPhaseProgressText = overallProgress.phaseMessage
                    updateEstimatedCompletionFromPercent(scanProgressPercent ?? overallProgress.percent)
                } else {
                    isUsingEstimatedScanProgress = true
                    let estimatedDuration = estimatedScanDurationSeconds()
                    let elapsedInterval = scanStartedAt.map { Date().timeIntervalSince($0) } ?? 0
                    let estimatedOverall = min(95, max(scanProgressPercent ?? 1, (elapsedInterval / estimatedDuration) * 100))
                    scanProgressPercent = estimatedOverall
                    scanProgressMessage = String(format: "Overall %.0f%% estimated", estimatedOverall)
                    scanPhaseProgressText = String(format: "Phase: Nmap %.1f%%", normalizedPhasePercent)
                    updateEstimatedCompletionFromPercent(estimatedOverall)
                }
            } else if let floorPercent = progressFloorPercent(from: trimmedLine) {
                isUsingEstimatedScanProgress = true
                scanProgressPercent = max(scanProgressPercent ?? 0, floorPercent)
                scanProgressMessage = String(format: "Overall %.0f%% estimated", scanProgressPercent ?? floorPercent)
                if scanPhaseProgressText.isEmpty || scanPhaseProgressText == "Phase: waiting for Nmap timing" {
                    scanPhaseProgressText = "Phase: waiting for Nmap timing"
                }
                updateEstimatedCompletionFromPercent(scanProgressPercent ?? floorPercent)
            }

            if let etcRange = trimmedLine.range(of: #"ETC:\s*[^()]+"#, options: .regularExpression) {
                let etcText = String(trimmedLine[etcRange])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !etcText.isEmpty {
                    scanEstimatedCompletionText = etcText
                }
            }

            if let remainingRange = trimmedLine.range(of: #"\([^)]*remaining\)"#, options: .regularExpression) {
                let remainingText = String(trimmedLine[remainingRange])
                    .trimmingCharacters(in: CharacterSet(charactersIn: "()"))

                if scanEstimatedCompletionText.isEmpty {
                    scanEstimatedCompletionText = remainingText
                } else if !scanEstimatedCompletionText.contains(remainingText) {
                    scanEstimatedCompletionText += " " + remainingText
                }
            }

            if trimmedLine.hasPrefix("Stats:") ||
                trimmedLine.contains("Timing:") ||
                trimmedLine.hasPrefix("Initiating ") ||
                trimmedLine.hasPrefix("Completed ") ||
                trimmedLine.hasPrefix("Scanning ") ||
                trimmedLine.hasPrefix("Discovered ") ||
                trimmedLine.hasPrefix("Nmap scan report") {
                if progressPercentText(from: trimmedLine) == nil {
                    scanPhaseProgressText = trimmedLine
                }
            }
        }

        updateScanElapsedTime()
    }

    func updateEstimatedCompletionFromPercent(_ percent: Double) {
        guard percent > 0,
              percent < 100,
              let started = scanStartedAt else {
            return
        }

        let elapsed = Date().timeIntervalSince(started)
        guard elapsed > 0 else {
            return
        }

        let totalEstimatedSeconds = elapsed / (percent / 100)
        let remainingSeconds = max(0, Int(totalEstimatedSeconds - elapsed))
        let remainingMinutes = remainingSeconds / 60
        let remainingRemainderSeconds = remainingSeconds % 60
        let completionDate = Date().addingTimeInterval(TimeInterval(remainingSeconds))
        scanEstimatedCompletionText = String(
            format: "ETA %@ (%d:%02d remaining)",
            completionDate.formatted(date: .omitted, time: .shortened),
            remainingMinutes,
            remainingRemainderSeconds
        )
    }

    func estimatedScanDurationSeconds() -> Double {
        let args = arguments.lowercased()

        if args.contains("-su") || args.contains("-sU".lowercased()) {
            return 420
        }

        if args.contains("-a") || args.contains("-A".lowercased()) {
            return 180
        }

        if args.contains("-sv") || args.contains("-sV".lowercased()) {
            return 120
        }

        if args.contains("-sn") {
            return 45
        }

        if target.contains("/") {
            return 240
        }

        return 90
    }

    func updateScanElapsedTime() {
        guard isRunning, let started = scanStartedAt else {
            return
        }

        let elapsedInterval = Date().timeIntervalSince(started)
        let elapsed = Int(elapsedInterval)
        let minutes = elapsed / 60
        let seconds = elapsed % 60
        scanElapsedText = String(format: "Elapsed %d:%02d", minutes, seconds)

        if scanProgressPercent == nil || isUsingEstimatedScanProgress {
            isUsingEstimatedScanProgress = true
            let estimatedDuration = estimatedScanDurationSeconds()
            let estimatedPercent = min(95, max(scanProgressPercent ?? 1, (elapsedInterval / estimatedDuration) * 100))
            scanProgressPercent = estimatedPercent
            scanProgressMessage = String(format: "Overall %.0f%% estimated", estimatedPercent)
            if scanPhaseProgressText.isEmpty {
                scanPhaseProgressText = "Phase: waiting for Nmap timing"
            }
            updateEstimatedCompletionFromPercent(estimatedPercent)
        } else if scanProgressMessage == "Waiting for Nmap progress", elapsed >= 5 {
            scanProgressMessage = "Nmap is running"
        }
    }
}
