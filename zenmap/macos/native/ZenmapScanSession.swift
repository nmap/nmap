import Foundation

/// Platform-neutral execution mode for a Zenmap scan.
///
/// This type is intentionally independent of SwiftUI/AppKit so the same
/// scan/session state shape can later be shared by macOS, GTK, or Windows UI
/// front ends.
enum ZenmapScanExecutionMode: Equatable {
    case normalUser
    case administrator(reason: String)
}

/// Platform-neutral lifecycle state for a scan session.
enum ZenmapScanLifecycleState: Equatable {
    case idle
    case preparing
    case waitingForAuthorization
    case running
    case stopping
    case completed(exitStatus: Int32)
    case failed(message: String, exitStatus: Int32?)
    case cancelled
}

/// Platform-neutral per-phase progress snapshot.
struct ZenmapScanPhaseProgress: Equatable {
    var portPercent: Double?
    var servicePercent: Double?
    var scriptPercent: Double?
    var phaseText: String

    static let empty = ZenmapScanPhaseProgress(
        portPercent: nil,
        servicePercent: nil,
        scriptPercent: nil,
        phaseText: ""
    )
}

/// Platform-neutral progress snapshot for scan execution.
struct ZenmapScanProgressSnapshot: Equatable {
    var overallPercent: Double?
    var isEstimated: Bool
    var message: String
    var estimatedCompletionText: String
    var elapsedText: String
    var phases: ZenmapScanPhaseProgress

    static let empty = ZenmapScanProgressSnapshot(
        overallPercent: nil,
        isEstimated: false,
        message: "",
        estimatedCompletionText: "",
        elapsedText: "",
        phases: .empty
    )
}

/// Platform-neutral command description for a scan.
struct ZenmapScanCommand: Equatable {
    var binaryDisplayName: String
    var arguments: [String]
    var targets: [String]
    var xmlOutputPath: String?

    var displayText: String {
        let joinedArguments = arguments.joined(separator: " ")
        let joinedTargets = targets.joined(separator: " ")

        if joinedArguments.isEmpty {
            return "\(binaryDisplayName) \(joinedTargets)"
        }

        return "\(binaryDisplayName) \(joinedArguments) \(joinedTargets)"
    }
}

/// Platform-neutral scan session model.
///
/// This is a foundation layer for future portability work. The current SwiftUI
/// app can be migrated toward this shape incrementally while later UI ports can
/// consume the same session concepts without depending on AppKit or SwiftUI.
struct ZenmapScanSession: Identifiable, Equatable {
    let id: UUID
    var command: ZenmapScanCommand
    var executionMode: ZenmapScanExecutionMode
    var lifecycleState: ZenmapScanLifecycleState
    var progress: ZenmapScanProgressSnapshot
    var startedAt: Date?
    var completedAt: Date?
    var outputText: String
    var xmlOutputPath: String?
    var parsedHosts: [ScannedHost]

    init(
        id: UUID = UUID(),
        command: ZenmapScanCommand,
        executionMode: ZenmapScanExecutionMode = .normalUser,
        lifecycleState: ZenmapScanLifecycleState = .idle,
        progress: ZenmapScanProgressSnapshot = .empty,
        startedAt: Date? = nil,
        completedAt: Date? = nil,
        outputText: String = "",
        xmlOutputPath: String? = nil,
        parsedHosts: [ScannedHost] = []
    ) {
        self.id = id
        self.command = command
        self.executionMode = executionMode
        self.lifecycleState = lifecycleState
        self.progress = progress
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.outputText = outputText
        self.xmlOutputPath = xmlOutputPath
        self.parsedHosts = parsedHosts
    }
}
