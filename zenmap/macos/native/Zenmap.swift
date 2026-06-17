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
    private let elapsedTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

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
    
    @State private var runningProcess: Process?
    @State var privilegedScanPID: Int32?
    @State private var privilegedChildPIDPath: String?
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
    @State private var pendingScanOutputBuffer = ""
    @State private var pendingScanProgressBuffer = ""
    @State private var pendingScanOutputFlushWorkItem: DispatchWorkItem?
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
    @State private var didInstallDiagnosticInfoObserver = false
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
    
    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            VStack(spacing: 0) {
                header
                Divider()
                tabView
                Divider()
                footer
            }
        }
        .toolbar {
            ToolbarItemGroup {
                Button {
                    openXML()
                } label: {
                    Label("Open XML", systemImage: "folder")
                }
                .help("Open Nmap XML")
                .disabled(isRunning)

                Button {
                    saveCurrentXML()
                } label: {
                    Label("Save XML", systemImage: "square.and.arrow.down")
                }
                .help("Save Current XML")
                .disabled(lastXMLPath.isEmpty)

                Button {
                    selectedTab = "Saved Scans"
                } label: {
                    Label("Saved Scans", systemImage: "archivebox")
                }
                .help("Show Saved Scans")
            }

            ToolbarItemGroup {
                Button {
                    selectedTab = "Output"
                    isOutputFindVisible = true
                    DispatchQueue.main.async {
                        isOutputFindFocused = true
                    }
                } label: {
                    Label("Find", systemImage: "magnifyingglass")
                }
                .help("Find in Output")

                Button(role: .destructive) {
                    stopScan()
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .help("Stop Scan")
                .disabled(!isRunning)

                Button {
                    runScan()
                } label: {
                    Label("Scan", systemImage: "play.fill")
                }
                .help("Start Scan")
                .disabled(isRunning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    .keyboardShortcut(.return, modifiers: [])
            }
        }
        .onReceive(elapsedTimer) { _ in
            updateScanElapsedTime()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapOpenXML)) { _ in
            guard !isRunning else {
                return
            }
            openXML()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapOpenRecentScan)) { notification in
            guard !isRunning,
                  let savedScanID = notification.object as? SavedScan.ID else {
                return
            }
            reloadSavedScan(id: savedScanID)
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapSaveXML)) { _ in
            saveCurrentXML()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapSaveAllScans)) { _ in
            saveAllScansToDirectory()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapPrintOutput)) { _ in
            printOutput()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapFindOutput)) { _ in
            selectedTab = "Output"
            isOutputFindVisible = true
            DispatchQueue.main.async {
                isOutputFindFocused = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapCopyOutput)) { _ in
            copyOutput()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapClearOutput)) { _ in
            guard !isRunning else {
                return
            }
            output = ""
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapStartScan)) { _ in
            guard !isRunning,
                  !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return
            }
            runScan()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapStopScan)) { _ in
            guard isRunning else {
                return
            }
            stopScan()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapClearResults)) { _ in
            guard !isRunning else {
                return
            }
            clearResults()
        }
        .onReceive(NotificationCenter.default.publisher(for: .zenmapShowTab)) { notification in
            guard let tabName = notification.object as? String else {
                return
            }
            selectedTab = tabName
        }
        .onAppear {
            installDiagnosticInfoObserverIfNeeded()
            loadNSEScriptDatabaseIfNeeded()
        }
    }

    private func installDiagnosticInfoObserverIfNeeded() {
        guard !didInstallDiagnosticInfoObserver else {
            return
        }

        didInstallDiagnosticInfoObserver = true
        NotificationCenter.default.addObserver(
            forName: .zenmapCopyDiagnosticInfo,
            object: nil,
            queue: .main
        ) { _ in
            copyDiagnosticInfo()
        }
    }
    
    private func loadNSEScriptDatabaseIfNeeded() {
        guard nseScriptEntries.isEmpty else {
            return
        }

        nseScriptEntries = parseBundledNSEScriptDatabase()
    }
    
    private var sidebar: some View {
        List(selection: $selectedTab) {
            Section("Scan") {
                Label("Output", systemImage: "terminal")
                    .tag("Output")
                Label("Hosts", systemImage: "desktopcomputer")
                    .tag("Hosts")
                Label("Ports", systemImage: "list.bullet.rectangle")
                    .tag("Ports")
                Label("Services", systemImage: "network")
                    .tag("Services")
                Label("Details", systemImage: "info.circle")
                    .tag("Details")
            }
            
            Section("History") {
                Label("Saved Scans", systemImage: "archivebox")
                    .tag("Saved Scans")
                Label("Compare", systemImage: "rectangle.split.2x1")
                    .tag("Compare")
            }

            Section("Later") {
                Label("Topology", systemImage: "point.3.connected.trianglepath.dotted")
                    .tag("Topology")
                Label("Profiles", systemImage: "slider.horizontal.3")
                    .tag("Profiles")
                Label("Settings", systemImage: "gearshape")
                    .tag("Settings")
            }
        }
        .navigationTitle("Nmap")
    }
    
    
    private var tabView: some View {
        TabView(selection: $selectedTab) {
            outputView
                .tabItem { Label("Output", systemImage: "terminal") }
                .tag("Output")
            
            hostsView
                .tabItem { Label("Hosts", systemImage: "desktopcomputer") }
                .tag("Hosts")
            
            portsView
                .tabItem { Label("Ports", systemImage: "list.bullet.rectangle") }
                .tag("Ports")
            
            servicesView
                .tabItem { Label("Services", systemImage: "network") }
                .tag("Services")
            
            detailsView
                .tabItem { Label("Details", systemImage: "info.circle") }
                .tag("Details")
            
            savedScansView
                .tabItem { Label("Saved Scans", systemImage: "archivebox") }
                .tag("Saved Scans")
            
            scanComparisonView
                .tabItem { Label("Compare", systemImage: "rectangle.split.2x1") }
                .tag("Compare")
            
            topologyView
                .tabItem { Label("Topology", systemImage: "point.3.connected.trianglepath.dotted") }
                .tag("Topology")
            
            profilesView
                .tabItem { Label("Profiles", systemImage: "slider.horizontal.3") }
                .tag("Profiles")
            
            settingsView
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag("Settings")
        }
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

    private var footer: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(isRunning ? .orange : .green)
                    .frame(width: 8, height: 8)

                Text(status)
                    .foregroundStyle(.secondary)

                Spacer()

                if isRunning {
                    if let scanProgressPercent {
                        ProgressView(value: scanProgressPercent, total: 100)
                            .frame(width: 160)

                        Text(String(format: "Overall %.0f%%", scanProgressPercent))
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else if !scanProgressMessage.isEmpty {
                        Text(scanProgressMessage)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    if !scanElapsedText.isEmpty {
                        Text(scanElapsedText)
                            .foregroundStyle(.secondary)
                    } else if let started = scanStartedAt {
                        Text("Started \(started.formatted(date: .omitted, time: .standard))")
                            .foregroundStyle(.secondary)
                    }
                }

                if let exitStatus {
                    Text("Exit \(exitStatus)")
                        .foregroundColor(exitStatus == 0 ? .secondary : .red)
                }
            }

            if isRunning {
                HStack(spacing: 10) {
                    Text(scanPhaseProgressText.isEmpty ? "Phase: waiting for Nmap timing" : scanPhaseProgressText)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    if !scanEstimatedCompletionText.isEmpty {
                        Text(scanEstimatedCompletionText)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }

                    Spacer()
                }
                .font(.caption)
                .padding(.leading, 18)

                HStack(spacing: 10) {
                    Text(scanPhaseBreakdownText)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    Spacer()
                }
                .font(.caption)
                .padding(.leading, 18)
            }
        }
        .font(.callout)
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
    
    private var scanPhaseBreakdownText: String {
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

    private func isVerboseOrDebugArgument(_ argument: String) -> Bool {
        argument == "-v" ||
        argument == "-vv" ||
        argument == "-d" ||
        argument.hasPrefix("-v") ||
        argument.hasPrefix("-d") ||
        argument == "--verbose" ||
        argument.hasPrefix("--verbose=")
    }

    private func resetPendingScanOutput() {
        pendingScanOutputFlushWorkItem?.cancel()
        pendingScanOutputFlushWorkItem = nil
        pendingScanOutputBuffer = ""
        pendingScanProgressBuffer = ""
    }

    private func appendBufferedScanOutput(_ text: String, updateProgress: Bool = true) {
        guard !text.isEmpty else {
            return
        }

        pendingScanOutputBuffer += text
        if updateProgress {
            pendingScanProgressBuffer += text
        }

        schedulePendingScanOutputFlush()
    }

    private func schedulePendingScanOutputFlush() {
        guard pendingScanOutputFlushWorkItem == nil else {
            return
        }

        let workItem = DispatchWorkItem {
            flushPendingScanOutput()
        }

        pendingScanOutputFlushWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.30, execute: workItem)
    }

    private func flushPendingScanOutput() {
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
    private func confirmPrivilegedScan(reason: String) async -> Bool {
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
    private func runPrivilegedScan(args: [String], xmlURL: URL, trimmedTarget: String, reason: String) async {
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
    
    private func readNewText(from url: URL, startingAt offset: UInt64) -> (text: String, offset: UInt64) {
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
    
    private func readExitStatus(from url: URL) -> Int? {
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
    
    private func clearResults() {
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
    
    func copyProfileArguments() {
        let trimmedArguments = newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedArguments.isEmpty else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(trimmedArguments, forType: .string)
        nseScriptHelperMessage = "Copied profile arguments to clipboard."
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
    
    private func splitTargets(_ string: String) -> [String] {
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
