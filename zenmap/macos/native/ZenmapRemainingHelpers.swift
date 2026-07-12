import AppKit
import Foundation
import SwiftUI

extension ContentView {
    var selectedHost: ScannedHost? {
        guard let selectedHostID else {
            return hosts.first
        }
        return hosts.first { $0.id == selectedHostID }
    }

    var nseScriptHelperDisplayText: String {
        nseScriptHelperMessage.isEmpty ? nseScriptHelperStatusText : nseScriptHelperMessage
    }

    var nseScriptHelperDisplayIsWarning: Bool {
        nseScriptCategoryIsRiskyOrSlow(selectedNSEScriptCategory) ||
        nseScriptHelperMessage.hasPrefix("Already") ||
        nseScriptHelperMessage.hasPrefix("Warning") ||
        nseScriptHelperMessage.hasPrefix("Note")
    }

    var profileScriptArgsHelperText: String {
        let activeValue = profileScriptArgsValue()
        if !activeValue.isEmpty {
            return "Active script args: --script-args \(activeValue). Clear removes them from Arguments."
        }

        return "Optional NSE args. Apply writes --script-args to Arguments. Only use values appropriate for the selected scripts."
    }

    var nseScriptHelperStatusText: String {
        let databaseStatus = nseScriptEntries.isEmpty
            ? "Bundled NSE script database not found; common categories are still available."
            : "Loaded \(nseScriptEntries.count) bundled NSE scripts."

        let selectedCategoryText = "Selected category \(selectedNSEScriptCategory). Click Add Category to add --script \(selectedNSEScriptCategory), or choose a script and click Add Script."
        let warning = nseScriptCategoryWarningText(selectedNSEScriptCategory)

        if warning.isEmpty {
            return "\(selectedCategoryText) \(databaseStatus)"
        }

        return "\(warning) \(selectedCategoryText) \(databaseStatus)"
    }

    func nseScriptCategoryDisplayName(_ category: String) -> String {
        switch category {
        case "default":
            return "default - normal"
        case "safe":
            return "safe - low risk"
        case "vuln":
            return "vuln - vulnerability checks"
        case "auth":
            return "auth - authentication checks"
        case "discovery":
            return "discovery - noisy"
        case "version":
            return "version - version scripts"
        case "all":
            return "all - very slow/noisy"
        default:
            return category
        }
    }

    func nseScriptCategoryWarningText(_ category: String) -> String {
        switch category {
        case "all":
            return "Warning: all can be very slow and noisy."
        case "vuln":
            return "Warning: vuln runs vulnerability checks."
        case "auth":
            return "Warning: auth scripts may test authentication behavior."
        case "discovery":
            return "Note: discovery can be noisy on larger networks."
        default:
            return ""
        }
    }

    func nseScriptCategoryIsRiskyOrSlow(_ category: String) -> Bool {
        ["all", "vuln", "auth", "discovery"].contains(category)
    }

    var settingsAutoArgumentsSummary: String {
        var values: [String] = []

        if autoAddVerbose {
            values.append("-v")
        }

        if autoAddStatsEvery {
            values.append("--stats-every \(statsEveryValue)")
        }

        return values.isEmpty ? "None" : values.joined(separator: " ")
    }

    func applyScanDefaults() {
        let trimmedDefaultTarget = defaultTarget.trimmingCharacters(in: .whitespacesAndNewlines)
        target = trimmedDefaultTarget.isEmpty ? "scanme.nmap.org" : trimmedDefaultTarget

        if let profile = profiles.first(where: { $0.name == defaultProfileName }) {
            selectedProfile = profile
            selectedProfileID = profile.id
            arguments = profile.arguments
        }

        selectedTab = "Output"
    }

    func resetScanDefaults() {
        autoAddVerbose = true
        autoAddStatsEvery = true
        statsEveryValue = "5s"
        defaultTarget = "scanme.nmap.org"
        defaultProfileName = "Service Detection"
        applyScanDefaults()
    }

    var scanPhaseBreakdownText: String {
        "Phases: Port \(phasePercentDisplay(scanPortPhasePercent)) | Service \(phasePercentDisplay(scanServicePhasePercent)) | Script \(phasePercentDisplay(scanScriptPhasePercent))"
    }

    var commandPreview: String {
        let trimmedArgs = arguments.trimmingCharacters(in: .whitespacesAndNewlines)
        let targetList = splitTargets(target)
        let displayTargets = targetList.isEmpty ? target.trimmingCharacters(in: .whitespacesAndNewlines) : targetList.joined(separator: " ")
        
        if trimmedArgs.isEmpty {
            return "nmap \(displayTargets)"
        } else {
            return "nmap \(trimmedArgs) \(displayTargets)"
        }
    }

    func phasePercentDisplay(_ percent: Double?) -> String {
        guard let percent else {
            return "--"
        }

        return String(format: "%.1f%%", percent)
    }

    func copyProfileArguments() {
        let trimmedArguments = newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedArguments.isEmpty else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(trimmedArguments, forType: .string)
        nseScriptHelperMessage = "Copied profile arguments to clipboard."
    }
}
