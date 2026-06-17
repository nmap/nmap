import Foundation

extension ZenmapScanSession {
    var isFooterActive: Bool {
        switch lifecycleState {
        case .preparing, .waitingForAuthorization, .running, .stopping:
            return true
        case .idle, .completed, .failed, .cancelled:
            return false
        }
    }

    var footerStatusText: String {
        switch lifecycleState {
        case .idle:
            return "Idle"
        case .preparing:
            return "Preparing"
        case .waitingForAuthorization:
            return "Waiting for administrator authorization"
        case .running:
            return "Running"
        case .stopping:
            return "Stopping"
        case .completed:
            return "Completed"
        case .failed(let message, _):
            return message.isEmpty ? "Failed" : message
        case .cancelled:
            return "Cancelled"
        }
    }

    var footerExitStatus: Int32? {
        switch lifecycleState {
        case .completed(let exitStatus):
            return exitStatus
        case .failed(_, let exitStatus):
            return exitStatus
        case .idle, .preparing, .waitingForAuthorization, .running, .stopping, .cancelled:
            return nil
        }
    }

    var footerProgressPercent: Double? {
        progress.overallPercent
    }

    var footerOverallProgressText: String {
        guard let overallPercent = progress.overallPercent else {
            return ""
        }

        return String(format: "Overall %.0f%%", overallPercent)
    }

    var footerProgressMessageText: String {
        progress.message
    }

    var footerElapsedText: String {
        progress.elapsedText
    }

    var footerStartedText: String {
        guard let startedAt else {
            return ""
        }

        return "Started \(startedAt.formatted(date: .omitted, time: .standard))"
    }

    var footerPhaseProgressText: String {
        progress.phases.phaseText.isEmpty ? "Phase: waiting for Nmap timing" : progress.phases.phaseText
    }

    var footerEstimatedCompletionText: String {
        progress.estimatedCompletionText
    }

    var footerPhaseBreakdownText: String {
        "Phases: Port \(Self.phasePercentDisplay(progress.phases.portPercent)) | Service \(Self.phasePercentDisplay(progress.phases.servicePercent)) | Script \(Self.phasePercentDisplay(progress.phases.scriptPercent))"
    }

    private static func phasePercentDisplay(_ percent: Double?) -> String {
        guard let percent else {
            return "--"
        }

        return String(format: "%.1f%%", percent)
    }
}
