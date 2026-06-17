import SwiftUI
import Combine
import Foundation
import AppKit
import UniformTypeIdentifiers
import Darwin
 
@main
struct ZenmapApp: App {
    @StateObject private var scanHistory = ScanHistoryStore()

    var body: some Scene {
        WindowGroup("Zenmap", id: "main") {
            ContentView()
                .environmentObject(scanHistory)
                .frame(minWidth: 1250, minHeight: 850)
        }
        .commands {
            NewWindowCommands()
            CommandGroup(replacing: .help) {
                Button("Nmap Reference Guide") {
                    openHelpURL("https://nmap.org/docs.html")
                }

                Button("Nmap Book") {
                    openHelpURL("https://nmap.org/book/")
                }

                Button("Nmap Man Page") {
                    openHelpURL("https://nmap.org/book/man.html")
                }

                Button("NSE Script Documentation") {
                    openHelpURL("https://nmap.org/nsedoc/")
                }

                Divider()

                Button("Zenmap User Guide") {
                    openHelpURL("https://nmap.org/book/zenmap.html")
                }

                Divider()

                Button("Copy Diagnostic Info") {
                    NotificationCenter.default.post(name: .zenmapCopyDiagnosticInfo, object: nil)
                }

                Button("Report a Bug") {
                    openHelpURL("https://github.com/nmap/nmap/issues")
                }

                Button("Nmap Website") {
                    openHelpURL("https://nmap.org/")
                }
            }
            CommandGroup(after: .pasteboard) {
                Divider()

                Button("Find in Output...") {
                    NotificationCenter.default.post(name: .zenmapFindOutput, object: nil)
                }
                .keyboardShortcut("f", modifiers: [.command])

                Button("Copy Output") {
                    NotificationCenter.default.post(name: .zenmapCopyOutput, object: nil)
                }
                .keyboardShortcut("c", modifiers: [.command, .shift])

                Button("Clear Output") {
                    NotificationCenter.default.post(name: .zenmapClearOutput, object: nil)
                }
            }
            CommandGroup(after: .newItem) {
                Button("Open Scan...") {
                    NotificationCenter.default.post(name: .zenmapOpenXML, object: nil)
                }
                .keyboardShortcut("o", modifiers: [.command])

                Button("Open Scan in This Window...") {
                    NotificationCenter.default.post(name: .zenmapOpenXML, object: nil)
                }

                Menu("Recent Scans") {
                    if scanHistory.savedScans.isEmpty {
                        Text("No Recent Scans")
                    } else {
                        ForEach(scanHistory.savedScans.prefix(10)) { scan in
                            Button(scan.title) {
                                NotificationCenter.default.post(name: .zenmapOpenRecentScan, object: scan.id)
                            }
                        }

                        Divider()

                        Button("Clear Recent Scans") {
                            scanHistory.clearSavedScans(deleteFiles: true)
                        }
                    }
                }

                Divider()

                Button("Save Scan") {
                    NotificationCenter.default.post(name: .zenmapSaveXML, object: nil)
                }
                .keyboardShortcut("s", modifiers: [.command])

                Button("Save All Scans to Directory...") {
                    NotificationCenter.default.post(name: .zenmapSaveAllScans, object: nil)
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])

                Divider()

                Button("Print...") {
                    NotificationCenter.default.post(name: .zenmapPrintOutput, object: nil)
                }
                .keyboardShortcut("p", modifiers: [.command])
            }
            CommandMenu("Scan") {
                Button("Start Scan") {
                    NotificationCenter.default.post(name: .zenmapStartScan, object: nil)
                }
                .keyboardShortcut("r", modifiers: [.command])

                Button("Stop Scan") {
                    NotificationCenter.default.post(name: .zenmapStopScan, object: nil)
                }
                .keyboardShortcut(".", modifiers: [.command])

                Divider()

                Button("Clear Results") {
                    NotificationCenter.default.post(name: .zenmapClearResults, object: nil)
                }
                .keyboardShortcut("k", modifiers: [.command, .shift])

                Divider()

                Button("Show Output") {
                    NotificationCenter.default.post(name: .zenmapShowTab, object: "Output")
                }
                .keyboardShortcut("1", modifiers: [.command])

                Button("Show Hosts") {
                    NotificationCenter.default.post(name: .zenmapShowTab, object: "Hosts")
                }
                .keyboardShortcut("2", modifiers: [.command])

                Button("Show Ports") {
                    NotificationCenter.default.post(name: .zenmapShowTab, object: "Ports")
                }
                .keyboardShortcut("3", modifiers: [.command])

                Button("Show Services") {
                    NotificationCenter.default.post(name: .zenmapShowTab, object: "Services")
                }
                .keyboardShortcut("4", modifiers: [.command])

                Button("Show Details") {
                    NotificationCenter.default.post(name: .zenmapShowTab, object: "Details")
                }
                .keyboardShortcut("5", modifiers: [.command])
            }
        }
    }
}

struct NewWindowCommands: Commands {
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Window") {
                openWindow(id: "main")
            }
            .keyboardShortcut("n", modifiers: [.command])
        }
    }
}

// Keep command-menu notifications centralized so menu actions can reach the
// active SwiftUI view without tightly coupling the app scene to ContentView.
extension Notification.Name {
    static let zenmapCopyDiagnosticInfo = Notification.Name("zenmapCopyDiagnosticInfo")
    static let zenmapOpenXML = Notification.Name("ZenmapOpenXML")
    static let zenmapOpenRecentScan = Notification.Name("ZenmapOpenRecentScan")
    static let zenmapSaveXML = Notification.Name("ZenmapSaveXML")
    static let zenmapSaveAllScans = Notification.Name("ZenmapSaveAllScans")
    static let zenmapPrintOutput = Notification.Name("ZenmapPrintOutput")
    static let zenmapFindOutput = Notification.Name("ZenmapFindOutput")
    static let zenmapCopyOutput = Notification.Name("ZenmapCopyOutput")
    static let zenmapClearOutput = Notification.Name("ZenmapClearOutput")
    static let zenmapStartScan = Notification.Name("ZenmapStartScan")
    static let zenmapStopScan = Notification.Name("ZenmapStopScan")
    static let zenmapClearResults = Notification.Name("ZenmapClearResults")
    static let zenmapShowTab = Notification.Name("ZenmapShowTab")
}

struct ContentView: View {
    @EnvironmentObject var scanHistory: ScanHistoryStore
    static let customProfilesDefaultsKey = "Zenmap.CustomProfiles"
    let elapsedTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    @AppStorage("Zenmap.AutoAddVerbose") var autoAddVerbose = true
    @AppStorage("Zenmap.AutoAddStatsEvery") var autoAddStatsEvery = true
    @AppStorage("Zenmap.StatsEveryValue") var statsEveryValue = "5s"
    @AppStorage("Zenmap.DefaultTarget") var defaultTarget = "scanme.nmap.org"
    @AppStorage("Zenmap.DefaultProfileName") var defaultProfileName = "Service Detection"

    @State var profiles: [ScanProfile] = Self.builtInProfiles
    
    @State var selectedProfile: ScanProfile
    @State var target = UserDefaults.standard.string(forKey: "Zenmap.DefaultTarget") ?? "scanme.nmap.org"
    @State var arguments = "-sV"
    @State var newProfileName = ""
    @State var newProfileArguments = "-sV"
    @State var newProfileDescription = "Custom scan profile."
    @State var selectedProfileID: ScanProfile.ID?
    @State var profileFilterText = ""
    @State var output = "Ready. Choose a profile, enter a target, then run a scan."
    @State var status = "Idle"
    @State var exitStatus: Int32?
    @State var isRunning = false
    @State var selectedTab = "Output"
    @State var baselineCompareScanID: SavedScan.ID?
    @State var comparisonCompareScanID: SavedScan.ID?
    @State var isOutputFindVisible = false
    @State var isOutputAutoScrollEnabled = true
    @State var outputFindText = ""
    @State var outputFindSelection = 0
    @FocusState var isOutputFindFocused: Bool
    
    @State var runningProcess: Process?
    @State var privilegedScanPID: Int32?
    @State var privilegedChildPIDPath: String?
    @State var scanStartedAt: Date?
    @State var scanProgressPercent: Double?
    @State var isUsingEstimatedScanProgress = false
    @State var scanEstimatedCompletionText = ""
    @State var scanProgressMessage = ""
    @State var scanPhaseProgressText = ""
    @State var scanPortPhasePercent: Double?
    @State var scanServicePhasePercent: Double?
    @State var scanScriptPhasePercent: Double?
    @State var scanElapsedText = ""
    @State var scanProgressBuffer = ""
    @State var pendingScanOutputBuffer = ""
    @State var pendingScanProgressBuffer = ""
    @State var pendingScanOutputFlushWorkItem: DispatchWorkItem?
    @State var lastCommand = ""
    @State var lastXMLPath = ""
    
    @State var hosts: [ScannedHost] = []
    @State var selectedHostID: ScannedHost.ID?
    @State var selectedPortID: ScannedPort.ID?
    @State var selectedServicePortID: ScannedPort.ID?
    @State var resultsFilterText = ""
    @State var savedScansFilterText = ""
    @State var savedScanNotesText = ""
    @State var savedScanTagsText = ""
    @State var didInstallDiagnosticInfoObserver = false
    @State var selectedNSEScriptCategory = "default"
    @State var selectedNSEScriptName = ""
    @State var nseScriptHelperMessage = ""
    @State var nseScriptArgsText = ""
    @State var nseScriptEntries: [NSEScriptEntry] = []
    
    init() {
        let savedCustomProfiles = Self.loadSavedCustomProfiles() ?? []
        let allProfiles = Self.builtInProfiles + savedCustomProfiles
        let savedDefaultProfileName = UserDefaults.standard.string(forKey: "Zenmap.DefaultProfileName") ?? "Service Detection"
        let defaultProfile = allProfiles.first { $0.name == savedDefaultProfileName }
            ?? allProfiles.first { $0.name == "Service Detection" }
            ?? allProfiles.first
            ?? ScanProfile(
                name: "Service Detection",
                arguments: "-sV",
                description: "Detect service and version information."
            )

        _profiles = State(initialValue: allProfiles)
        _selectedProfile = State(initialValue: defaultProfile)
        _arguments = State(initialValue: defaultProfile.arguments)
    }
    
    struct FindableOutputTextView: NSViewRepresentable {
        @Binding var text: String
        var findText: String
        var selectedMatchIndex: Int
        var autoScrollEnabled: Bool

        func makeCoordinator() -> Coordinator {
            Coordinator(self)
        }

        func makeNSView(context: Context) -> NSScrollView {
            let scrollView = NSScrollView()
            scrollView.hasVerticalScroller = true
            scrollView.hasHorizontalScroller = true
            scrollView.autohidesScrollers = false
            scrollView.borderType = .noBorder

            let textView = NSTextView()
            textView.isEditable = true
            textView.isSelectable = true
            textView.isRichText = false
            textView.usesFontPanel = false
            textView.allowsUndo = true
            textView.drawsBackground = true
            textView.backgroundColor = NSColor.textBackgroundColor
            textView.textColor = NSColor.textColor
            textView.insertionPointColor = NSColor.textColor
            textView.font = NSFont.monospacedSystemFont(
                ofSize: NSFont.systemFontSize,
                weight: .regular
            )
            textView.minSize = NSSize(width: 0, height: 0)
            textView.maxSize = NSSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            )
            textView.isHorizontallyResizable = true
            textView.isVerticallyResizable = true
            textView.autoresizingMask = [.width]
            textView.textContainer?.containerSize = NSSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            )
            textView.textContainer?.widthTracksTextView = false
            textView.delegate = context.coordinator

            scrollView.documentView = textView
            context.coordinator.textView = textView
            return scrollView
        }

        func updateNSView(_ scrollView: NSScrollView, context: Context) {
            guard let textView = scrollView.documentView as? NSTextView else {
                return
            }

            context.coordinator.parent = self

            if textView.string != text {
                textView.string = text

                if autoScrollEnabled {
                    scrollOutputToBottom(scrollView, textView: textView)

                    DispatchQueue.main.async {
                        scrollOutputToBottom(scrollView, textView: textView)
                    }
                }
            }

            context.coordinator.applyFindHighlight()
        }

        private func scrollOutputToBottom(_ scrollView: NSScrollView, textView: NSTextView) {
            guard let textContainer = textView.textContainer else {
                return
            }

            textView.layoutManager?.ensureLayout(for: textContainer)

            let endRange = NSRange(location: max(textView.string.count - 1, 0), length: 1)
            textView.scrollRangeToVisible(endRange)

            let documentHeight = textView.bounds.height
            let visibleHeight = scrollView.contentView.bounds.height
            let y = max(0, documentHeight - visibleHeight)
            scrollView.contentView.scroll(to: NSPoint(x: 0, y: y))
            scrollView.reflectScrolledClipView(scrollView.contentView)
        }

        final class Coordinator: NSObject, NSTextViewDelegate {
            var parent: FindableOutputTextView
            weak var textView: NSTextView?

            init(_ parent: FindableOutputTextView) {
                self.parent = parent
            }

            func textDidChange(_ notification: Notification) {
                guard let textView else {
                    return
                }

                parent.text = textView.string
            }

            func applyFindHighlight() {
                guard let textView else {
                    return
                }

                let text = textView.string as NSString
                let fullRange = NSRange(location: 0, length: text.length)
                textView.textStorage?.removeAttribute(.backgroundColor, range: fullRange)
                textView.textStorage?.addAttribute(.foregroundColor, value: NSColor.textColor, range: fullRange)

                if let font = textView.font {
                    textView.textStorage?.addAttribute(.font, value: font, range: fullRange)
                }
                
                let query = parent.findText.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !query.isEmpty else {
                    return
                }

                var searchRange = NSRange(location: 0, length: text.length)
                var matches: [NSRange] = []

                while searchRange.location < text.length {
                    let foundRange = text.range(
                        of: query,
                        options: [.caseInsensitive],
                        range: searchRange
                    )

                    if foundRange.location == NSNotFound {
                        break
                    }

                    matches.append(foundRange)

                    let nextLocation = foundRange.location + max(foundRange.length, 1)
                    searchRange = NSRange(
                        location: nextLocation,
                        length: text.length - nextLocation
                    )
                }

                guard !matches.isEmpty else {
                    return
                }

                let normalMatchBackground = NSColor.systemYellow.withAlphaComponent(0.90)
                let normalMatchForeground = NSColor.black
                let selectedMatchBackground = NSColor.systemOrange.withAlphaComponent(0.95)
                let selectedMatchForeground = NSColor.black

                for match in matches {
                    textView.textStorage?.addAttribute(
                        .backgroundColor,
                        value: normalMatchBackground,
                        range: match
                    )
                    textView.textStorage?.addAttribute(
                        .foregroundColor,
                        value: normalMatchForeground,
                        range: match
                    )
                }

                let selectedIndex = min(max(parent.selectedMatchIndex, 0), matches.count - 1)
                let selectedRange = matches[selectedIndex]

                textView.textStorage?.addAttribute(
                    .backgroundColor,
                    value: selectedMatchBackground,
                    range: selectedRange
                )
                textView.textStorage?.addAttribute(
                    .foregroundColor,
                    value: selectedMatchForeground,
                    range: selectedRange
                )
                textView.scrollRangeToVisible(selectedRange)
            }
        }
    }
    
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

    private var nseScriptHelperStatusText: String {
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

    private func nseScriptCategoryWarningText(_ category: String) -> String {
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

    private func nseScriptCategoryIsRiskyOrSlow(_ category: String) -> Bool {
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
    
    var outputFindMatchCount: Int {
        let query = outputFindText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            return 0
        }

        return output.lowercased().components(separatedBy: query.lowercased()).count - 1
    }

    var outputFindSummary: String {
        let count = outputFindMatchCount
        guard count > 0 else {
            return outputFindText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "" : "No matches"
        }

        let displayIndex = min(outputFindSelection + 1, count)
        return "\(displayIndex) of \(count)"
    }

    private func forceOutputScrollToBottom(_ scrollView: NSScrollView, textView: NSTextView) {
        textView.layoutManager?.ensureLayout(for: textView.textContainer!)

        let endRange = NSRange(location: max(textView.string.count - 1, 0), length: 1)
        textView.scrollRangeToVisible(endRange)

        let documentHeight = textView.bounds.height
        let visibleHeight = scrollView.contentView.bounds.height
        let y = max(0, documentHeight - visibleHeight)
        scrollView.contentView.scroll(to: NSPoint(x: 0, y: y))
        scrollView.reflectScrolledClipView(scrollView.contentView)
    }

    func moveToNextOutputMatch() {
        let count = outputFindMatchCount
        guard count > 0 else {
            return
        }

        outputFindSelection = (outputFindSelection + 1) % count
    }

    func moveToPreviousOutputMatch() {
        let count = outputFindMatchCount
        guard count > 0 else {
            return
        }

        outputFindSelection = (outputFindSelection - 1 + count) % count
    }
    

    private func phasePercentDisplay(_ percent: Double?) -> String {
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




    
    func parseNmapXML(at url: URL) -> [ScannedHost] {
        guard let parser = XMLParser(contentsOf: url) else {
            return []
        }
        
        let delegate = NmapXMLParserDelegate()
        parser.delegate = delegate
        
        guard parser.parse() else {
            return []
        }
        
        return delegate.hosts
    }
    
    private final class NmapXMLParserDelegate: NSObject, XMLParserDelegate {
        private(set) var hosts: [ScannedHost] = []
        
        private var currentHost: ScannedHost?
        private var currentPort: ScannedPort?
        private var isInsideHostnames = false
        
        func parser(
            _ parser: XMLParser,
            didStartElement elementName: String,
            namespaceURI: String?,
            qualifiedName qName: String?,
            attributes attributeDict: [String: String] = [:]
        ) {
            switch elementName {
            case "host":
                currentHost = ScannedHost(address: "", hostname: "", status: "unknown", ports: [])
                
            case "status":
                currentHost?.status = attributeDict["state"] ?? "unknown"
                
            case "address":
                if currentHost?.address.isEmpty == true {
                    currentHost?.address = attributeDict["addr"] ?? ""
                }
                
            case "hostnames":
                isInsideHostnames = true
                
            case "hostname":
                if isInsideHostnames, currentHost?.hostname.isEmpty == true {
                    currentHost?.hostname = attributeDict["name"] ?? ""
                }
                
            case "port":
                currentPort = ScannedPort(
                    hostAddress: currentHost?.address ?? "",
                    protocolName: attributeDict["protocol"] ?? "",
                    portNumber: attributeDict["portid"] ?? "",
                    state: "unknown",
                    serviceName: "",
                    product: "",
                    version: "",
                    extraInfo: ""
                )
                
            case "state":
                currentPort?.state = attributeDict["state"] ?? "unknown"
                
            case "service":
                currentPort?.serviceName = attributeDict["name"] ?? ""
                currentPort?.product = attributeDict["product"] ?? ""
                currentPort?.version = attributeDict["version"] ?? ""
                currentPort?.extraInfo = attributeDict["extrainfo"] ?? ""
                
            default:
                break
            }
        }
        
        func parser(
            _ parser: XMLParser,
            didEndElement elementName: String,
            namespaceURI: String?,
            qualifiedName qName: String?
        ) {
            switch elementName {
            case "hostnames":
                isInsideHostnames = false
                
            case "port":
                if let currentPort {
                    currentHost?.ports.append(currentPort)
                }
                currentPort = nil
                
            case "host":
                if let currentHost {
                    hosts.append(currentHost)
                }
                currentHost = nil
                
            default:
                break
            }
        }
    }
    
    
}
