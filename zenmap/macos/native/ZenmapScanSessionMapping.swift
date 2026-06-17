import Foundation

extension ContentView {
    /// Read-only snapshot of the current SwiftUI scan state as a platform-neutral model.
    ///
    /// This is the first bridge from the current ContentView-owned state toward a
    /// reusable scan/session model that can later be shared by macOS, GTK, or
    /// Windows front ends.
    var currentScanSessionSnapshot: ZenmapScanSession {
        ZenmapScanSession(
            command: currentScanCommandSnapshot,
            executionMode: currentScanExecutionModeSnapshot,
            lifecycleState: currentScanLifecycleStateSnapshot,
            progress: currentScanProgressSnapshot,
            startedAt: scanStartedAt,
            completedAt: currentScanCompletedAtSnapshot,
            outputText: output,
            xmlOutputPath: lastXMLPath.isEmpty ? nil : lastXMLPath,
            parsedHosts: hosts
        )
    }

    var currentScanCommandSnapshot: ZenmapScanCommand {
        ZenmapScanCommand(
            binaryDisplayName: "nmap",
            arguments: shellSplit(arguments),
            targets: splitTargets(target),
            xmlOutputPath: lastXMLPath.isEmpty ? nil : lastXMLPath
        )
    }

    var currentScanExecutionModeSnapshot: ZenmapScanExecutionMode {
        privilegedScanPID == nil ? .normalUser : .administrator(reason: "Privileged scan is running.")
    }

    var currentScanLifecycleStateSnapshot: ZenmapScanLifecycleState {
        if isRunning {
            if status.localizedCaseInsensitiveContains("stopping") {
                return .stopping
            }

            if status.localizedCaseInsensitiveContains("administrator") ||
                status.localizedCaseInsensitiveContains("privileged") {
                return privilegedScanPID == nil ? .waitingForAuthorization : .running
            }

            return .running
        }

        if status.localizedCaseInsensitiveContains("cancelled") {
            return .cancelled
        }

        if let exitStatus {
            if exitStatus == 0 {
                return .completed(exitStatus: exitStatus)
            }

            return .failed(message: status, exitStatus: exitStatus)
        }

        if status.localizedCaseInsensitiveContains("failed") ||
            status.localizedCaseInsensitiveContains("error") {
            return .failed(message: status, exitStatus: nil)
        }

        return .idle
    }

    var currentScanCompletedAtSnapshot: Date? {
        guard !isRunning, exitStatus != nil else {
            return nil
        }

        return nil
    }

    var currentScanProgressSnapshot: ZenmapScanProgressSnapshot {
        ZenmapScanProgressSnapshot(
            overallPercent: scanProgressPercent,
            isEstimated: isUsingEstimatedScanProgress,
            message: scanProgressMessage,
            estimatedCompletionText: scanEstimatedCompletionText,
            elapsedText: scanElapsedText,
            phases: currentScanPhaseProgressSnapshot
        )
    }

    var currentScanPhaseProgressSnapshot: ZenmapScanPhaseProgress {
        ZenmapScanPhaseProgress(
            portPercent: scanPortPhasePercent,
            servicePercent: scanServicePhasePercent,
            scriptPercent: scanScriptPhasePercent,
            phaseText: scanPhaseProgressText
        )
    }
}
