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

    @AppStorage("Zenmap.AutoAddVerbose") private var autoAddVerbose = true
    @AppStorage("Zenmap.AutoAddStatsEvery") private var autoAddStatsEvery = true
    @AppStorage("Zenmap.StatsEveryValue") private var statsEveryValue = "5s"
    @AppStorage("Zenmap.DefaultTarget") private var defaultTarget = "scanme.nmap.org"
    @AppStorage("Zenmap.DefaultProfileName") private var defaultProfileName = "Service Detection"

    @State var profiles: [ScanProfile] = Self.builtInProfiles
    
    @State private var selectedProfile: ScanProfile
    @State var target = UserDefaults.standard.string(forKey: "Zenmap.DefaultTarget") ?? "scanme.nmap.org"
    @State var arguments = "-sV"
    @State var newProfileName = ""
    @State var newProfileArguments = "-sV"
    @State private var newProfileDescription = "Custom scan profile."
    @State var selectedProfileID: ScanProfile.ID?
    @State var profileFilterText = ""
    @State private var output = "Ready. Choose a profile, enter a target, then run a scan."
    @State private var status = "Idle"
    @State private var exitStatus: Int32?
    @State var isRunning = false
    @State private var selectedTab = "Output"
    @State private var baselineCompareScanID: SavedScan.ID?
    @State private var comparisonCompareScanID: SavedScan.ID?
    @State private var isOutputFindVisible = false
    @State private var isOutputAutoScrollEnabled = true
    @State private var outputFindText = ""
    @State private var outputFindSelection = 0
    @FocusState private var isOutputFindFocused: Bool
    
    @State private var runningProcess: Process?
    @State private var privilegedScanPID: Int32?
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
    @State private var lastCommand = ""
    @State private var lastXMLPath = ""
    
    @State var hosts: [ScannedHost] = []
    @State private var selectedHostID: ScannedHost.ID?
    @State private var selectedPortID: ScannedPort.ID?
    @State private var selectedServicePortID: ScannedPort.ID?
    @State var resultsFilterText = ""
    @State var savedScansFilterText = ""
    @State private var savedScanNotesText = ""
    @State private var savedScanTagsText = ""
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
    
    private var selectedHost: ScannedHost? {
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
    
    private var header: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading) {
                    Text("Nmap for macOS")
                        .font(.largeTitle.bold())
                    Text("Native SwiftUI wrapper around bundled Nmap")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if isRunning {
                    ProgressView()
                        .controlSize(.small)
                }

                Button(role: .destructive) {
                    stopScan()
                } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .disabled(!isRunning)

                Button {
                    runScan()
                } label: {
                    Label(isRunning ? "Running..." : "Scan", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .disabled(isRunning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Target")
                        .foregroundStyle(.secondary)
                    TextField("scanme.nmap.org, 192.168.1.0/24, etc.", text: $target)
                        .textFieldStyle(.roundedBorder)
                }

                GridRow {
                    Text("Profile")
                        .foregroundStyle(.secondary)
                    Picker("Profile", selection: $selectedProfile) {
                        ForEach(profiles) { profile in
                            Text(profile.name).tag(profile)
                        }
                    }
                    .onChange(of: selectedProfile) { _, newProfile in
                        arguments = newProfile.arguments
                    }
                }

                GridRow {
                    Text("Arguments")
                        .foregroundStyle(.secondary)
                    TextField("Nmap arguments", text: $arguments)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                }

                GridRow {
                    Text("Preview")
                        .foregroundStyle(.secondary)
                    Text(commandPreview)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.5))
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }

            Text(selectedProfile.description)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .padding()
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
    
    private var outputView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Raw Output")
                    .font(.headline)
                Spacer()

                Toggle("Auto-scroll", isOn: $isOutputAutoScrollEnabled)
                    .toggleStyle(.switch)
                    .help("Automatically follow the latest scan output")

                Button {
                    isOutputFindVisible.toggle()
                    if isOutputFindVisible {
                        selectedTab = "Output"
                        DispatchQueue.main.async {
                            isOutputFindFocused = true
                        }
                    }
                } label: {
                    Label("Find", systemImage: "magnifyingglass")
                }

                Button {
                    copyOutput()
                } label: {
                    Label("Copy", systemImage: "doc.on.doc")
                }
                
                Button {
                    output = ""
                } label: {
                    Label("Clear", systemImage: "trash")
                }
                .disabled(isRunning)
            }

            if isOutputFindVisible {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)

                    TextField("Find in output", text: $outputFindText)
                        .textFieldStyle(.roundedBorder)
                        .focused($isOutputFindFocused)
                        .onChange(of: outputFindText) { _, _ in
                            outputFindSelection = 0
                        }
                    
                    Text(outputFindSummary)
                        .foregroundStyle(.secondary)

                    Button {
                        moveToPreviousOutputMatch()
                    } label: {
                        Image(systemName: "chevron.up")
                    }
                    .help("Previous Match")
                    .disabled(outputFindMatchCount == 0)

                    Button {
                        moveToNextOutputMatch()
                    } label: {
                        Image(systemName: "chevron.down")
                    }
                    .help("Next Match")
                    .disabled(outputFindMatchCount == 0)

                    Button {
                        outputFindText = ""
                        outputFindSelection = 0
                        isOutputFindVisible = false
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
            }
            
            FindableOutputTextView(
                text: $output,
                findText: outputFindText,
                selectedMatchIndex: outputFindSelection,
                autoScrollEnabled: isOutputAutoScrollEnabled
            )
            .border(.separator)
        }
        .padding()
    }
    
    private var hostsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Hosts")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredHosts.count) of \(hosts.count) hosts" : "\(hosts.count) host\(hosts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedHostAddress()
                } label: {
                    Label("Copy Address", systemImage: "number")
                }
                .disabled(selectedHost == nil)
                .help("Copy the selected host address")

                Button {
                    copySelectedHostSummary()
                } label: {
                    Label("Copy Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedHost == nil)
                .help("Copy a summary of the selected host")

                Button {
                    copySelectedHostOpenPorts()
                } label: {
                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                }
                .disabled(selectedHost == nil)
                .help("Copy open ports for the selected host")

                Button {
                    selectedTab = "Details"
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .disabled(selectedHost == nil)
                .help("Show details for the selected host")
            }
            
            resultsFilterBar

            if hosts.isEmpty {
                emptyResultsView("Run a scan to populate discovered hosts.")
            } else if filteredHosts.isEmpty {
                emptyResultsView("No hosts match the current filter.")
            } else {
                Table(filteredHosts, selection: $selectedHostID) {
                    TableColumn("Address") { host in
                        Text(host.address)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Hostname") { host in
                        Text(host.hostname.isEmpty ? "-" : host.hostname)
                    }
                    TableColumn("Status") { host in
                        Text(host.status)
                    }
                    TableColumn("Open Ports") { host in
                        Text("\(host.openPortCount)")
                    }
                }
                .contextMenu {
                    Button("Copy Address") {
                        copySelectedHostAddress()
                    }
                    .disabled(selectedHost == nil)

                    Button("Copy Host Summary") {
                        copySelectedHostSummary()
                    }
                    .disabled(selectedHost == nil)

                    Button("Copy Open Ports") {
                        copySelectedHostOpenPorts()
                    }
                    .disabled(selectedHost == nil)

                    Divider()

                    Button("Show Details") {
                        selectedTab = "Details"
                    }
                    .disabled(selectedHost == nil)
                }
            }
        }
        .padding()
    }
    
    private var selectedPort: ScannedPort? {
        guard let selectedPortID else {
            return nil
        }

        return allPorts.first { $0.id == selectedPortID }
    }

    private var selectedServicePort: ScannedPort? {
        guard let selectedServicePortID else {
            return nil
        }

        return allServicePorts.first { $0.id == selectedServicePortID }
    }

    private var portsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Ports")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredPorts.count) of \(allPorts.count) port results" : "\(allPorts.count) port result\(allPorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedPortHostPort()
                } label: {
                    Label("Copy Host:Port", systemImage: "number")
                }
                .disabled(selectedPort == nil)
                .help("Copy the selected host and port")

                Button {
                    copySelectedPortSummary()
                } label: {
                    Label("Copy Port Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedPort == nil)
                .help("Copy a summary of the selected port")

                Button {
                    showSelectedPortHostDetails()
                } label: {
                    Label("Host Details", systemImage: "info.circle")
                }
                .disabled(selectedPort == nil)
                .help("Show details for the selected port's host")
            }
            
            resultsFilterBar

            if allPorts.isEmpty {
                emptyResultsView("Run a scan to populate port results.")
            } else if filteredPorts.isEmpty {
                emptyResultsView("No ports match the current filter.")
            } else {
                Table(filteredPorts, selection: $selectedPortID) {
                    TableColumn("Host") { port in
                        Text(port.hostAddress)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Port") { port in
                        Text("\(port.portNumber)/\(port.protocolName)")
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("State") { port in
                        Text(port.state)
                    }
                    TableColumn("Service") { port in
                        Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                    }
                    TableColumn("Version") { port in
                        Text(port.serviceSummary.isEmpty ? "-" : port.serviceSummary)
                    }
                }
                .contextMenu {
                    Button("Copy Host:Port") {
                        copySelectedPortHostPort()
                    }
                    .disabled(selectedPort == nil)

                    Button("Copy Port Summary") {
                        copySelectedPortSummary()
                    }
                    .disabled(selectedPort == nil)

                    Divider()

                    Button("Show Host Details") {
                        showSelectedPortHostDetails()
                    }
                    .disabled(selectedPort == nil)
                }
            }
        }
        .padding()
    }
    
    private var servicesView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Services")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredServicePorts.count) of \(allServicePorts.count) service results" : "\(filteredServicePorts.count) service result\(filteredServicePorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedServiceHostPort()
                } label: {
                    Label("Copy Host:Port", systemImage: "number")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy the selected service host and port")

                Button {
                    copySelectedServiceSummary()
                } label: {
                    Label("Copy Service", systemImage: "doc.on.doc")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy a summary of the selected service")

                Button {
                    copySelectedServiceProductVersion()
                } label: {
                    Label("Copy Version", systemImage: "shippingbox")
                }
                .disabled(selectedServicePort == nil)
                .help("Copy product and version for the selected service")

                Button {
                    showSelectedServiceHostDetails()
                } label: {
                    Label("Host Details", systemImage: "info.circle")
                }
                .disabled(selectedServicePort == nil)
                .help("Show details for the selected service's host")
            }
            
            resultsFilterBar

            if allServicePorts.isEmpty {
                emptyResultsView("Run a service detection scan to populate service results.")
            } else if filteredServicePorts.isEmpty {
                emptyResultsView("No services match the current filter.")
            } else {
                Table(filteredServicePorts, selection: $selectedServicePortID) {
                    TableColumn("Host") { port in
                        Text(port.hostAddress)
                            .font(.system(.body, design: .monospaced))
                    }
                    TableColumn("Service") { port in
                        Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                    }
                    TableColumn("Product") { port in
                        Text(port.product.isEmpty ? "-" : port.product)
                    }
                    TableColumn("Version") { port in
                        Text(port.version.isEmpty ? "-" : port.version)
                    }
                    TableColumn("Extra Info") { port in
                        Text(port.extraInfo.isEmpty ? "-" : port.extraInfo)
                    }
                }
                .contextMenu {
                    Button("Copy Host:Port") {
                        copySelectedServiceHostPort()
                    }
                    .disabled(selectedServicePort == nil)

                    Button("Copy Service Summary") {
                        copySelectedServiceSummary()
                    }
                    .disabled(selectedServicePort == nil)

                    Button("Copy Product/Version") {
                        copySelectedServiceProductVersion()
                    }
                    .disabled(selectedServicePort == nil)

                    Divider()

                    Button("Show Host Details") {
                        showSelectedServiceHostDetails()
                    }
                    .disabled(selectedServicePort == nil)
                }
            }
        }
        .padding()
    }
    
    private var detailsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Scan Details", systemImage: "info.circle")
                    .font(.title2.bold())

                Spacer()

                Button {
                    copyScanDetailsSummary()
                } label: {
                    Label("Copy Scan Summary", systemImage: "doc.plaintext")
                }
                .disabled(hosts.isEmpty && lastCommand.isEmpty && lastXMLPath.isEmpty)

                if selectedHost != nil {
                    Button {
                        copySelectedHostSummary()
                    } label: {
                        Label("Copy Host Summary", systemImage: "doc.on.doc")
                    }

                    Button {
                        copySelectedHostOpenPorts()
                    } label: {
                        Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                    }
                }
            }

            HStack(spacing: 12) {
                scanMetricCard(title: "Hosts", value: "\(hosts.count)", systemImage: "desktopcomputer")
                scanMetricCard(title: "Ports", value: "\(allPorts.count)", systemImage: "network")
                scanMetricCard(title: "Open", value: "\(scanPortStateCount("open"))", systemImage: "checkmark.circle")
                scanMetricCard(title: "Filtered", value: "\(scanPortStateCount("filtered"))", systemImage: "line.3.horizontal.decrease.circle")
                scanMetricCard(title: "Closed", value: "\(scanPortStateCount("closed"))", systemImage: "xmark.circle")
            }

            GroupBox("Scan Context") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    GridRow {
                        Text("Status")
                            .foregroundStyle(.secondary)
                        Text(status)
                    }
                    GridRow {
                        Text("Last command")
                            .foregroundStyle(.secondary)
                        Text(lastCommand.isEmpty ? "None" : lastCommand)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Exit status")
                            .foregroundStyle(.secondary)
                        Text(exitStatus.map(String.init) ?? "None")
                    }
                    GridRow {
                        Text("XML output")
                            .foregroundStyle(.secondary)
                        Text(lastXMLPath.isEmpty ? "None" : lastXMLPath)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("NMAPDIR")
                            .foregroundStyle(.secondary)
                        Text(Bundle.main.resourceURL?.path ?? "Unavailable")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    GridRow {
                        Text("Bundled binary")
                            .foregroundStyle(.secondary)
                        Text(nmapBinaryPath() ?? "Not found")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }

            if let selectedHost {
                GroupBox("Selected Host") {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(selectedHost.displayName)
                                    .font(.headline)
                                    .textSelection(.enabled)

                                Text(selectedHost.address)
                                    .font(.system(.body, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }

                            Spacer()

                            Text(selectedHost.status)
                                .font(.caption.bold())
                                .padding(.horizontal, 8)
                                .padding(.vertical, 4)
                                .background(.quaternary, in: Capsule())
                        }

                        HStack(spacing: 12) {
                            scanMetricCard(title: "Host Ports", value: "\(selectedHost.ports.count)", systemImage: "number")
                            scanMetricCard(title: "Open", value: "\(hostPortStateCount(selectedHost, state: "open"))", systemImage: "checkmark.circle")
                            scanMetricCard(title: "Filtered", value: "\(hostPortStateCount(selectedHost, state: "filtered"))", systemImage: "line.3.horizontal.decrease.circle")
                            scanMetricCard(title: "Closed", value: "\(hostPortStateCount(selectedHost, state: "closed"))", systemImage: "xmark.circle")
                        }

                        if selectedHost.ports.isEmpty {
                            Text("No port results were parsed for this host.")
                                .foregroundStyle(.secondary)
                        } else {
                            Table(sortedPorts(selectedHost.ports)) {
                                TableColumn("Port") { port in
                                    Text("\(port.portNumber)/\(port.protocolName)")
                                        .font(.system(.body, design: .monospaced))
                                }
                                TableColumn("State") { port in
                                    Text(port.state)
                                }
                                TableColumn("Service") { port in
                                    Text(port.serviceName.isEmpty ? "-" : port.serviceName)
                                }
                                TableColumn("Version") { port in
                                    Text(port.serviceSummary.isEmpty ? "-" : port.serviceSummary)
                                }
                            }
                            .frame(minHeight: 160)
                        }
                    }
                }
            } else {
                emptyResultsView("Select a host in the Hosts tab to view host details here.")
            }

            Spacer()
        }
        .padding()
    }

    private var topologyView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Topology")
                        .font(.headline)
                    Text("Hosts from the current scan arranged as a simple network map.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Text("\(hosts.count) host\(hosts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)

                Button {
                    copySelectedHostAddress()
                } label: {
                    Label("Copy Address", systemImage: "number")
                }
                .disabled(selectedHost == nil)
                .help("Copy the selected topology host address")

                Button {
                    copySelectedHostSummary()
                } label: {
                    Label("Copy Summary", systemImage: "doc.on.doc")
                }
                .disabled(selectedHost == nil)
                .help("Copy a summary of the selected topology host")

                Button {
                    copySelectedHostOpenPorts()
                } label: {
                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                }
                .disabled(selectedHost == nil)
                .help("Copy open ports for the selected topology host")

                Button {
                    selectedTab = "Details"
                } label: {
                    Label("Details", systemImage: "info.circle")
                }
                .disabled(selectedHost == nil)
                .help("Show details for the selected topology host")
            }

            if hosts.isEmpty {
                emptyResultsView("Run or open a scan to populate the topology map.")
            } else {
                GeometryReader { geometry in
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Color.secondary.opacity(0.08))

                        if hosts.count > 1 {
                            ForEach(Array(hosts.enumerated()), id: \.element.id) { index, host in
                                let center = CGPoint(x: geometry.size.width / 2, y: geometry.size.height / 2)
                                let point = topologyPoint(for: index, total: hosts.count, in: geometry.size)

                                Path { path in
                                    path.move(to: center)
                                    path.addLine(to: point)
                                }
                                .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
                            }
                        }

                        VStack(spacing: 4) {
                            Image(systemName: "network")
                                .font(.title2)
                            Text("Scan")
                                .font(.caption.bold())
                            Text("\(allPorts.count) ports")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        .padding(12)
                        .background(
                            Circle()
                                .fill(Color(nsColor: .windowBackgroundColor))
                                .shadow(radius: 4)
                        )
                        .position(x: geometry.size.width / 2, y: geometry.size.height / 2)

                        ForEach(Array(hosts.enumerated()), id: \.element.id) { index, host in
                            let point = topologyPoint(for: index, total: hosts.count, in: geometry.size)

                            Button {
                                selectedHostID = host.id
                            } label: {
                                topologyNode(host)
                            }
                            .buttonStyle(.plain)
                            .contextMenu {
                                Button("Copy Address") {
                                    selectedHostID = host.id
                                    copySelectedHostAddress()
                                }

                                Button("Copy Host Summary") {
                                    selectedHostID = host.id
                                    copySelectedHostSummary()
                                }

                                Button("Copy Open Ports") {
                                    selectedHostID = host.id
                                    copySelectedHostOpenPorts()
                                }

                                Divider()

                                Button("Show Details") {
                                    selectedHostID = host.id
                                    selectedTab = "Details"
                                }
                            }
                            .position(point)
                        }
                    }
                }
                .frame(minHeight: 430)

                if let selectedHost {
                    GroupBox("Selected Host") {
                        VStack(alignment: .leading, spacing: 10) {
                            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                                GridRow {
                                    Text("Address")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.address)
                                        .font(.system(.body, design: .monospaced))
                                        .textSelection(.enabled)
                                }

                                GridRow {
                                    Text("Hostname")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.hostname.isEmpty ? "-" : selectedHost.hostname)
                                        .textSelection(.enabled)
                                }

                                GridRow {
                                    Text("Status")
                                        .foregroundStyle(.secondary)
                                    Text(selectedHost.status)
                                }

                                GridRow {
                                    Text("Open Ports")
                                        .foregroundStyle(.secondary)
                                    Text("\(selectedHost.openPortCount)")
                                }
                            }

                            HStack {
                                Button {
                                    copySelectedHostAddress()
                                } label: {
                                    Label("Copy Address", systemImage: "number")
                                }

                                Button {
                                    copySelectedHostSummary()
                                } label: {
                                    Label("Copy Summary", systemImage: "doc.on.doc")
                                }

                                Button {
                                    copySelectedHostOpenPorts()
                                } label: {
                                    Label("Copy Open Ports", systemImage: "list.bullet.rectangle")
                                }

                                Button {
                                    selectedTab = "Details"
                                } label: {
                                    Label("Details", systemImage: "info.circle")
                                }

                                Spacer()
                            }
                        }
                    }
                } else {
                    Text("Select a host node to show details.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }

    private func topologyNode(_ host: ScannedHost) -> some View {
        let isSelected = host.id == selectedHostID
        let openPorts = host.openPortCount
        let width = min(190, max(120, 120 + (openPorts * 8)))

        return VStack(spacing: 5) {
            HStack(spacing: 6) {
                Circle()
                    .fill(openPorts > 0 ? Color.green : Color.secondary)
                    .frame(width: 8, height: 8)

                Text(host.displayName)
                    .font(.caption.bold())
                    .lineLimit(1)
            }

            Text(host.address)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)

            Text("\(openPorts) open port\(openPorts == 1 ? "" : "s")")
                .font(.caption2)
                .foregroundStyle(.secondary)

            Text(host.status)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(width: CGFloat(width))
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(isSelected ? Color.accentColor.opacity(0.18) : Color(nsColor: .controlBackgroundColor))
                .shadow(radius: isSelected ? 5 : 2)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(isSelected ? Color.accentColor : Color.secondary.opacity(0.25), lineWidth: isSelected ? 2 : 1)
        )
    }

    private func topologyPoint(for index: Int, total: Int, in size: CGSize) -> CGPoint {
        let width = max(size.width, 1)
        let height = max(size.height, 1)
        let center = CGPoint(x: width / 2, y: height / 2)

        guard total > 1 else {
            return center
        }

        let radius = max(120, min(width, height) * 0.36)
        let angle = (Double(index) / Double(total)) * Double.pi * 2 - Double.pi / 2

        return CGPoint(
            x: center.x + CGFloat(cos(angle)) * radius,
            y: center.y + CGFloat(sin(angle)) * radius
        )
    }

    private var scanComparisonView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Compare Saved Scans")
                        .font(.title2.bold())
                    Text("Choose two saved XML scans to see host, port, and service changes.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Open Baseline") {
                    if let baselineCompareScanID {
                        reloadSavedScan(id: baselineCompareScanID)
                    }
                }
                .disabled(baselineCompareScanID == nil)

                Button("Open Comparison") {
                    if let comparisonCompareScanID {
                        reloadSavedScan(id: comparisonCompareScanID)
                    }
                }
                .disabled(comparisonCompareScanID == nil)

                Button("Copy Report") {
                    copyScanComparisonReport()
                }
                .disabled(currentScanComparison == nil)

                Button("Export Report...") {
                    exportScanComparisonReport()
                }
                .disabled(currentScanComparison == nil)

                Button("Clear") {
                    baselineCompareScanID = nil
                    comparisonCompareScanID = nil
                }
                .disabled(baselineCompareScanID == nil && comparisonCompareScanID == nil)
            }

            if scanHistory.savedScans.count < 2 {
                emptyResultsView("Save at least two scans to compare them.")
            } else {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Baseline")
                            .font(.headline)
                        Picker("Baseline", selection: $baselineCompareScanID) {
                            Text("Choose scan").tag(Optional<SavedScan.ID>.none)
                            ForEach(scanHistory.savedScans) { scan in
                                Text(scanComparisonScanLabel(scan)).tag(Optional(scan.id))
                            }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 420)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Comparison")
                            .font(.headline)
                        Picker("Comparison", selection: $comparisonCompareScanID) {
                            Text("Choose scan").tag(Optional<SavedScan.ID>.none)
                            ForEach(scanHistory.savedScans) { scan in
                                Text(scanComparisonScanLabel(scan)).tag(Optional(scan.id))
                            }
                        }
                        .labelsHidden()
                        .frame(maxWidth: 420)
                    }
                }

                HStack(alignment: .top, spacing: 12) {
                    if let baselineScan = selectedBaselineComparisonScan {
                        scanComparisonMetadataCard(title: "Baseline Metadata", scan: baselineScan)
                    }

                    if let comparisonScan = selectedComparisonComparisonScan {
                        scanComparisonMetadataCard(title: "Comparison Metadata", scan: comparisonScan)
                    }
                }

                if baselineCompareScanID == comparisonCompareScanID && baselineCompareScanID != nil {
                    emptyResultsView("Choose two different saved scans.")
                } else if let comparison = currentScanComparison {
                    scanComparisonSummaryView(comparison)
                } else {
                    emptyResultsView("Choose a baseline scan and a comparison scan.")
                }
            }
        }
        .padding()
    }

    private var selectedBaselineComparisonScan: SavedScan? {
        guard let baselineCompareScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == baselineCompareScanID }
    }

    private var selectedComparisonComparisonScan: SavedScan? {
        guard let comparisonCompareScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == comparisonCompareScanID }
    }

    private func scanComparisonMetadataCard(title: String, scan: SavedScan) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 6) {
                Text(scan.title)
                    .font(.headline)
                    .textSelection(.enabled)

                Text(scan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(.secondary)

                Text("Command: \(scan.command)")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)

                Text("Hosts: \(scan.hostCount)    Ports: \(scan.portCount)")
                    .foregroundStyle(.secondary)

                Text("Tags: \(scan.tags.isEmpty ? "(none)" : scan.tags)")
                    .textSelection(.enabled)

                Text("Notes: \(scan.notes.isEmpty ? "(none)" : scan.notes)")
                    .textSelection(.enabled)
                    .lineLimit(4)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func scanComparisonSummaryView(_ comparison: ScanComparison) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 12) {
                    scanComparisonMetricCard(title: "New Hosts", value: comparison.newHosts.count, systemImage: "plus.circle")
                    scanComparisonMetricCard(title: "Missing Hosts", value: comparison.missingHosts.count, systemImage: "minus.circle")
                    scanComparisonMetricCard(title: "New Open Ports", value: comparison.newOpenPorts.count, systemImage: "lock.open")
                    scanComparisonMetricCard(title: "Closed Ports", value: comparison.closedPorts.count, systemImage: "lock")
                    scanComparisonMetricCard(title: "Service Changes", value: comparison.changedServices.count, systemImage: "arrow.triangle.2.circlepath")
                }

                scanComparisonSection(title: "New Hosts", rows: comparison.newHosts)
                scanComparisonSection(title: "Missing Hosts", rows: comparison.missingHosts)
                scanComparisonSection(title: "New Open Ports", rows: comparison.newOpenPorts)
                scanComparisonSection(title: "Closed Ports", rows: comparison.closedPorts)
                scanComparisonSection(title: "Changed Services", rows: comparison.changedServices)
            }
        }
    }

    private func scanComparisonMetricCard(title: String, value: Int, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
                Spacer()
            }

            Text("\(value)")
                .font(.title.bold())

            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 12))
    }

    private func scanComparisonSection(title: String, rows: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)

            if rows.isEmpty {
                Text("No changes")
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(rows, id: \.self) { row in
                        Text(row)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 3)
                    }
                }
                .padding()
                .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10))
            }
        }
    }

    private var savedScansView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Saved Scans")
                    .font(.headline)

                Spacer()

                Text("\(scanHistory.savedScans.count) saved")
                    .foregroundStyle(.secondary)

                Button {
                    openXML()
                } label: {
                    Image(systemName: "plus")
                }
                .help("Open Nmap XML")
                .disabled(isRunning)

                Button {
                    reloadSelectedSavedScan()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Reload Selected Scan")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanCommand()
                } label: {
                    Image(systemName: "arrow.uturn.forward")
                }
                .help("Use Command in Scan Form")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    copySelectedSavedScanCommand()
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .help("Copy Scan Command")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    copySelectedSavedScanSummary()
                } label: {
                    Image(systemName: "doc.plaintext")
                }
                .help("Copy Scan Summary")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanAsBaseline()
                } label: {
                    Image(systemName: "1.circle")
                }
                .help("Use Selected Scan as Comparison Baseline")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    useSelectedSavedScanAsComparison()
                } label: {
                    Image(systemName: "2.circle")
                }
                .help("Use Selected Scan as Comparison Target")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    revealSelectedSavedScanInFinder()
                } label: {
                    Image(systemName: "folder")
                }
                .help("Reveal XML in Finder")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    openSelectedSavedScanExternally()
                } label: {
                    Image(systemName: "arrow.up.right.square")
                }
                .help("Open XML Externally")
                .disabled(scanHistory.selectedSavedScanID == nil)

                Button {
                    exportSavedScanHistory()
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .help("Export Saved Scan History")
                .disabled(scanHistory.savedScans.isEmpty)

                Button {
                    importSavedScanHistory()
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .help("Import Saved Scan History")

                Button(role: .destructive) {
                    deleteSelectedSavedScan()
                } label: {
                    Image(systemName: "trash")
                }
                .help("Remove Selected Scan(s)")
                .disabled(selectedSavedScanIDsForDeletion.isEmpty)
            }
            if scanHistory.savedScans.isEmpty {
                emptyResultsView("Completed scans and opened XML files will appear here for quick reload during this app session.")
            } else {
                savedScansFilterBar

                if filteredSavedScans.isEmpty {
                    emptyResultsView("No saved scans match the current filter.")
                } else {
                    Table(filteredSavedScans, selection: $scanHistory.selectedSavedScanIDs) {
                        TableColumn("Date") { scan in
                            Text(scan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                        }
                        TableColumn("Title") { scan in
                            Text(scan.title)
                        }
                        TableColumn("Command") { scan in
                            Text(scan.command)
                                .font(.system(.body, design: .monospaced))
                        }
                        TableColumn("Hosts") { scan in
                            Text("\(scan.hostCount)")
                        }
                        TableColumn("Ports") { scan in
                            Text("\(scan.portCount)")
                        }
                        TableColumn("Tags") { scan in
                            Text(scan.tags.isEmpty ? "-" : scan.tags)
                        }
                        TableColumn("XML") { scan in
                            Text(scan.xmlPath)
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                    .contextMenu {
                        Button("Use as Baseline") {
                            useSelectedSavedScanAsBaseline()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Use as Comparison Target") {
                            useSelectedSavedScanAsComparison()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Divider()

                        Button("Copy Scan Summary") {
                            copySelectedSavedScanSummary()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Copy Scan Command") {
                            copySelectedSavedScanCommand()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Divider()

                        Button("Reveal XML in Finder") {
                            revealSelectedSavedScanInFinder()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)

                        Button("Open XML Externally") {
                            openSelectedSavedScanExternally()
                        }
                        .disabled(scanHistory.selectedSavedScanID == nil)
                    }
                .onChange(of: scanHistory.selectedSavedScanIDs) { _, selectedIDs in
                    syncPrimarySavedScanSelection(selectedIDs)
                }


                    savedScanMetadataEditor
                }

                HStack {
                    Spacer()

                    Button(role: .destructive) {
                        scanHistory.clearSavedScans(deleteFiles: true)
                    } label: {
                        Label("Clear History", systemImage: "trash.slash")
                    }
                }
            }
        }
        .padding()
    }
    
    private var profileValidationWarningsView: some View {
        let warnings = profileValidationWarnings()

        return Group {
            if !warnings.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(warnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            }
        }
    }

    private var profileAdvancedOptionsRow: some View {
        HStack(spacing: 10) {
            Menu("Add Option") {
                Button("TCP Connect (-sT)") { appendProfileArgumentIfMissing("-sT") }
                Button("SYN Scan (-sS)") { appendProfileArgumentIfMissing("-sS") }
                Button("UDP Scan (-sU)") { appendProfileArgumentIfMissing("-sU") }

                Divider()

                Button("Service Detection (-sV)") { appendProfileArgumentIfMissing("-sV") }
                Button("OS Detection (-O)") { appendProfileArgumentIfMissing("-O") }
                Button("Default Scripts (-sC)") { appendProfileArgumentIfMissing("-sC") }
                Button("Aggressive (-A)") { appendProfileArgumentIfMissing("-A") }

                Divider()

                Button("Treat Hosts as Up (-Pn)") { appendProfileArgumentIfMissing("-Pn") }
                Button("Traceroute") { appendProfileArgumentIfMissing("--traceroute") }
                Button("Fast Scan (-F)") { appendProfileArgumentIfMissing("-F") }
            }

            Menu("Remove Option") {
                ForEach(["-sT", "-sS", "-sU", "-sV", "-O", "-sC", "-A", "-Pn", "--traceroute", "-F"], id: \.self) { argument in
                    Button(argument) {
                        removeProfileArgument(argument)
                    }
                    .disabled(!profileHasArgument(argument))
                }
            }

            Picker("Timing", selection: Binding(
                get: { profileTimingValue() },
                set: { setProfileTimingValue($0) }
            )) {
                Text("Default timing").tag("")
                Text("T0 Paranoid").tag("-T0")
                Text("T1 Sneaky").tag("-T1")
                Text("T2 Polite").tag("-T2")
                Text("T3 Normal").tag("-T3")
                Text("T4 Aggressive").tag("-T4")
                Text("T5 Insane").tag("-T5")
            }
            .pickerStyle(.menu)
            .frame(width: 170)

            Text("Adds/removes common options from the Arguments field.")
                .font(.caption)
                .foregroundStyle(.secondary)

            Spacer()
        }
    }

    private var profileNSEScriptRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Picker("Category", selection: $selectedNSEScriptCategory) {
                    ForEach(nseScriptCategories, id: \.self) { category in
                        Text(nseScriptCategoryDisplayName(category)).tag(category)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 190)
                .onChange(of: selectedNSEScriptCategory) { _, newCategory in
                    nseScriptHelperMessage = "Selected category \(newCategory). Click Add Category to add --script \(newCategory), or choose a script and click Add Script."
                }

                Picker("Script", selection: $selectedNSEScriptName) {
                    Text("Choose script").tag("")
                    ForEach(filteredNSEScriptEntries) { script in
                        Text(script.name).tag(script.name)
                    }
                }
                .pickerStyle(.menu)
                .frame(width: 260)
                .onChange(of: selectedNSEScriptName) { _, newScript in
                    guard !newScript.isEmpty else {
                        return
                    }

                    nseScriptHelperMessage = "Selected script \(newScript). Click Add Script to add --script \(newScript)."
                }

                Button("Add Category") {
                    appendProfileScriptExpression(selectedNSEScriptCategory)
                }
                .disabled(selectedNSEScriptCategory.isEmpty)

                Button("Add Script") {
                    appendProfileScriptExpression(selectedNSEScriptName)
                }
                .disabled(selectedNSEScriptName.isEmpty)

                Menu("Common") {
                    Button("default - normal NSE set") { appendProfileScriptExpression("default") }
                    Button("safe - low risk") { appendProfileScriptExpression("safe") }
                    Button("default,safe - broad safe set") { appendProfileScriptExpression("default,safe") }

                    Divider()

                    Button("version - version scripts") { appendProfileScriptExpression("version") }
                    Button("discovery - noisy discovery") { appendProfileScriptExpression("discovery") }
                    Button("vuln - vulnerability checks") { appendProfileScriptExpression("vuln") }
                    Button("auth - authentication checks") { appendProfileScriptExpression("auth") }

                    Divider()

                    Button("all - very slow/noisy") { appendProfileScriptExpression("all") }
                }

                Spacer()
            }

            if !profileScriptExpressions().isEmpty {
                HStack(spacing: 6) {
                    Text("Active Scripts:")
                        .font(.caption.bold())
                        .foregroundStyle(.secondary)

                    ForEach(profileScriptExpressions(), id: \.self) { expression in
                        Button {
                            removeProfileScriptExpression(expression)
                        } label: {
                            HStack(spacing: 4) {
                                Text(expression)
                                    .font(.caption)
                                Image(systemName: "xmark.circle.fill")
                                    .font(.caption2)
                            }
                            .padding(.horizontal, 6)
                            .padding(.vertical, 3)
                            .background(.quaternary, in: Capsule())
                        }
                        .buttonStyle(.plain)
                        .help("Remove --script \(expression)")
                    }
                }
            }

            Text(nseScriptHelperDisplayText)
                .font(.caption)
                .foregroundStyle(nseScriptHelperDisplayIsWarning ? Color.orange : Color.secondary)
                .lineLimit(2)

            if let selectedNSEScriptDetails {
                nseScriptDetailsView(selectedNSEScriptDetails)
            }
        }
    }

    private func nseScriptDetailsView(_ details: NSEScriptDetails) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(details.name)
                    .font(.caption.bold())

                if !details.categories.isEmpty {
                    Text(details.categories.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }

            Text(details.description.isEmpty ? "No description found in bundled NSE script." : details.description)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(4)
                .textSelection(.enabled)

            Text(details.path)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
        .padding(8)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
    }

    private var profileNSEScriptArgsRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                TextField("key=value,key2=value2", text: $nseScriptArgsText)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .onSubmit {
                        setProfileScriptArgs(nseScriptArgsText)
                    }

                Button("Apply") {
                    setProfileScriptArgs(nseScriptArgsText)
                }
                .disabled(nseScriptArgsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                Button("Clear") {
                    clearProfileScriptArgs()
                }
                .disabled(profileScriptArgsValue().isEmpty && nseScriptArgsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Text(profileScriptArgsHelperText)
                .font(.caption)
                .foregroundStyle(profileScriptArgsValue().isEmpty ? Color.secondary : Color.orange)
                .lineLimit(2)
        }
    }

    private var nseScriptHelperDisplayText: String {
        nseScriptHelperMessage.isEmpty ? nseScriptHelperStatusText : nseScriptHelperMessage
    }

    private var nseScriptHelperDisplayIsWarning: Bool {
        nseScriptCategoryIsRiskyOrSlow(selectedNSEScriptCategory) ||
        nseScriptHelperMessage.hasPrefix("Already") ||
        nseScriptHelperMessage.hasPrefix("Warning") ||
        nseScriptHelperMessage.hasPrefix("Note")
    }

    private var profileScriptArgsHelperText: String {
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

    private func nseScriptCategoryDisplayName(_ category: String) -> String {
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

    private var profilesView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Profiles")
                        .font(.title2.bold())
                    Text("Choose a profile to load its arguments into the scan form, or create a custom one.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    exportCustomProfiles()
                } label: {
                    Label("Export Custom Profiles", systemImage: "square.and.arrow.up")
                }
                .disabled(customProfiles.isEmpty)

                Button {
                    importCustomProfiles()
                } label: {
                    Label("Import Custom Profiles", systemImage: "square.and.arrow.down")
                }

                Button("Use") {
                    if let profile = selectedProfileForActions {
                        useProfile(profile)
                    }
                }
                .disabled(selectedProfileForActions == nil)

                Button("Duplicate") {
                    if let profile = selectedProfileForActions {
                        duplicateProfile(profile)
                    }
                }
                .disabled(selectedProfileForActions == nil)

                Button(role: .destructive) {
                    if let profile = selectedProfileForActions {
                        deleteProfile(profile)
                    }
                } label: {
                    Text("Delete")
                }
                .disabled(selectedProfileForActions?.isBuiltIn ?? true)

                Divider()

                Button {
                    selectedProfile = profiles.first { $0.name == "Custom" } ?? selectedProfile
                    selectedTab = "Output"
                } label: {
                    Label("Custom", systemImage: "slider.horizontal.3")
                }
            }

            GroupBox("Profile Editor") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                    GridRow {
                        Text("Name")
                            .foregroundStyle(.secondary)
                        TextField("My scan profile", text: $newProfileName)
                            .textFieldStyle(.roundedBorder)
                    }

                    GridRow {
                        Text("Arguments")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("-sV -T4", text: $newProfileArguments)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))

                            profileValidationWarningsView
                        }
                    }

                    GridRow {
                        Text("Advanced")
                            .foregroundStyle(.secondary)
                        profileAdvancedOptionsRow
                    }

                    GridRow {
                        Text("Scripts")
                            .foregroundStyle(.secondary)
                        profileNSEScriptRow
                    }

                    GridRow {
                        Text("Script Args")
                            .foregroundStyle(.secondary)
                        profileNSEScriptArgsRow
                    }

                    GridRow {
                        Text("Description")
                            .foregroundStyle(.secondary)
                        TextField("Describe when to use this profile", text: $newProfileDescription)
                            .textFieldStyle(.roundedBorder)
                    }
                }

                HStack {
                    Button {
                        copyProfileArguments()
                    } label: {
                        Label("Copy Arguments", systemImage: "doc.on.doc")
                    }
                    .disabled(newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                    Spacer()

                    Button {
                        addCustomProfile()
                    } label: {
                        Label("Add Custom Profile", systemImage: "plus")
                    }
                    .disabled(newProfileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                    Button {
                        updateSelectedCustomProfile()
                    } label: {
                        Label("Update Selected Profile", systemImage: "checkmark")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(selectedCustomProfileForEditing == nil || newProfileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                    Button {
                        clearProfileEditor()
                    } label: {
                        Label("Clear Editor", systemImage: "xmark.circle")
                    }
                }
                .padding(.top, 8)
            }
            
            HStack(spacing: 8) {
                Label("Search Profiles", systemImage: "magnifyingglass")
                    .foregroundStyle(.secondary)

                TextField("Name, arguments, description, built-in, custom", text: $profileFilterText)
                    .textFieldStyle(.roundedBorder)

                if isFilteringProfiles {
                    Button("Clear") {
                        profileFilterText = ""
                    }
                }
            }

            Table(filteredProfiles, selection: $selectedProfileID) {
                TableColumn("Name") { profile in
                    HStack {
                        Text(profile.name)
                        if !profile.isBuiltIn {
                            Text("Custom")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(.quaternary)
                                .clipShape(Capsule())
                        }
                    }
                }
                TableColumn("Arguments") { profile in
                    Text(profile.arguments.isEmpty ? "default" : profile.arguments)
                        .font(.system(.body, design: .monospaced))
                }
                TableColumn("Description") { profile in
                    Text(profile.description)
                }
            }
            .onChange(of: selectedProfileID) { _, _ in
                loadSelectedProfileForEditingIfNeeded()
            }
            
            Text("Selecting a profile loads it into the editor. Built-in profiles are view-only here; duplicate one to edit and save your own version.")
                .foregroundStyle(.secondary)
        }
        .padding()
    }
    
    private var settingsView: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Settings")
                        .font(.title2.bold())
                    Text("Control default scan behavior and startup values.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Apply Defaults Now") {
                    applyScanDefaults()
                }

                Button("Reset Defaults") {
                    resetScanDefaults()
                }
            }

            GroupBox("Scan Behavior") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                    GridRow {
                        Text("Verbose output")
                            .foregroundStyle(.secondary)
                        Toggle("Auto-add -v when no verbose/debug flag is present", isOn: $autoAddVerbose)
                    }

                    GridRow {
                        Text("Progress stats")
                            .foregroundStyle(.secondary)
                        Toggle("Auto-add --stats-every", isOn: $autoAddStatsEvery)
                    }

                    GridRow {
                        Text("Stats interval")
                            .foregroundStyle(.secondary)
                        Picker("Stats interval", selection: $statsEveryValue) {
                            Text("5 seconds").tag("5s")
                            Text("10 seconds").tag("10s")
                            Text("30 seconds").tag("30s")
                            Text("60 seconds").tag("60s")
                        }
                        .labelsHidden()
                        .disabled(!autoAddStatsEvery)
                    }
                }
                .padding(.vertical, 4)
            }

            GroupBox("Defaults") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 12) {
                    GridRow {
                        Text("Default target")
                            .foregroundStyle(.secondary)
                        TextField("scanme.nmap.org", text: $defaultTarget)
                            .textFieldStyle(.roundedBorder)
                    }

                    GridRow {
                        Text("Default profile")
                            .foregroundStyle(.secondary)
                        Picker("Default profile", selection: $defaultProfileName) {
                            ForEach(profiles) { profile in
                                Text(profile.name).tag(profile.name)
                            }
                        }
                        .labelsHidden()
                    }
                }
                .padding(.vertical, 4)
            }

            GroupBox("Current Effective Defaults") {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                    GridRow {
                        Text("Target")
                            .foregroundStyle(.secondary)
                        Text(defaultTarget.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "scanme.nmap.org" : defaultTarget)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }

                    GridRow {
                        Text("Profile")
                            .foregroundStyle(.secondary)
                        Text(defaultProfileName)
                    }

                    GridRow {
                        Text("Auto arguments")
                            .foregroundStyle(.secondary)
                        Text(settingsAutoArgumentsSummary)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
            }

            Spacer()
        }
        .padding()
    }

    private var settingsAutoArgumentsSummary: String {
        var values: [String] = []

        if autoAddVerbose {
            values.append("-v")
        }

        if autoAddStatsEvery {
            values.append("--stats-every \(statsEveryValue)")
        }

        return values.isEmpty ? "None" : values.joined(separator: " ")
    }

    private func applyScanDefaults() {
        let trimmedDefaultTarget = defaultTarget.trimmingCharacters(in: .whitespacesAndNewlines)
        target = trimmedDefaultTarget.isEmpty ? "scanme.nmap.org" : trimmedDefaultTarget

        if let profile = profiles.first(where: { $0.name == defaultProfileName }) {
            selectedProfile = profile
            selectedProfileID = profile.id
            arguments = profile.arguments
        }

        selectedTab = "Output"
    }

    private func resetScanDefaults() {
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

    private var commandPreview: String {
        let trimmedArgs = arguments.trimmingCharacters(in: .whitespacesAndNewlines)
        let targetList = splitTargets(target)
        let displayTargets = targetList.isEmpty ? target.trimmingCharacters(in: .whitespacesAndNewlines) : targetList.joined(separator: " ")
        
        if trimmedArgs.isEmpty {
            return "nmap \(displayTargets)"
        } else {
            return "nmap \(trimmedArgs) \(displayTargets)"
        }
    }
    
    private var outputFindMatchCount: Int {
        let query = outputFindText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            return 0
        }

        return output.lowercased().components(separatedBy: query.lowercased()).count - 1
    }

    private var outputFindSummary: String {
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

    private func moveToNextOutputMatch() {
        let count = outputFindMatchCount
        guard count > 0 else {
            return
        }

        outputFindSelection = (outputFindSelection + 1) % count
    }

    private func moveToPreviousOutputMatch() {
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

    private func runScan() {
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
    
    private func stopScan() {
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
    
    private func useProfile(_ profile: ScanProfile) {
        selectedProfile = profile
        arguments = profile.arguments
        selectedProfileID = profile.id
        selectedTab = "Output"
    }
    
    private func addCustomProfile() {
        let trimmedName = newProfileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            return
        }

        let profile = ScanProfile(
            name: trimmedName,
            arguments: newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines),
            description: newProfileDescription.trimmingCharacters(in: .whitespacesAndNewlines),
            isBuiltIn: false
        )

        profiles.append(profile)
        selectedProfileID = profile.id
        loadProfileIntoEditor(profile)
        saveCustomProfiles()
    }
    
    private func updateSelectedCustomProfile() {
        guard let profile = selectedCustomProfileForEditing,
              let index = profiles.firstIndex(where: { $0.id == profile.id }) else {
            return
        }

        let trimmedName = newProfileName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            return
        }

        let updated = ScanProfile(
            name: trimmedName,
            arguments: newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines),
            description: newProfileDescription.trimmingCharacters(in: .whitespacesAndNewlines),
            isBuiltIn: false
        )

        profiles[index] = updated
        selectedProfileID = updated.id

        if selectedProfile.id == profile.id {
            selectedProfile = updated
            arguments = updated.arguments
        }

        saveCustomProfiles()
    }
    
    private func duplicateProfile(_ profile: ScanProfile) {
        let copy = ScanProfile(
            name: "\(profile.name) Copy",
            arguments: profile.arguments,
            description: profile.description,
            isBuiltIn: false
        )

        profiles.append(copy)
        selectedProfileID = copy.id
        loadProfileIntoEditor(copy)
        selectedTab = "Profiles"
        saveCustomProfiles()
    }
    
    private func deleteProfile(_ profile: ScanProfile) {
        guard !profile.isBuiltIn else {
            return
        }

        profiles.removeAll { $0.id == profile.id }

        if selectedProfile.id == profile.id,
           let fallback = profiles.first {
            useProfile(fallback)
        }

        clearProfileEditor()
        saveCustomProfiles()
    }
    
    private func loadSelectedProfileForEditingIfNeeded() {
        guard let profile = selectedProfileForActions else {
            return
        }

        loadProfileIntoEditor(profile)
    }
    
    func loadProfileIntoEditor(_ profile: ScanProfile) {
        newProfileName = profile.name
        newProfileArguments = profile.arguments
        newProfileDescription = profile.description
        nseScriptHelperMessage = ""
        nseScriptArgsText = profileScriptArgsValue(from: shellSplit(profile.arguments))
    }
    
    private func clearProfileEditor() {
        selectedProfileID = nil
        newProfileName = ""
        newProfileArguments = "-sV"
        newProfileDescription = "Custom scan profile."
        nseScriptHelperMessage = ""
        nseScriptArgsText = ""
    }
    
    
    func mergeImportedCustomProfiles(_ importedProfiles: [ScanProfile]) {
        let builtIns = profiles.filter { $0.isBuiltIn }
        var mergedCustomProfiles = customProfiles

        for importedProfile in importedProfiles {
            mergedCustomProfiles.removeAll { $0.name == importedProfile.name }
            mergedCustomProfiles.append(importedProfile)
        }

        mergedCustomProfiles.sort {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }

        profiles = builtIns + mergedCustomProfiles
        saveCustomProfiles()
    }

    
    private func copyProfileArguments() {
        let trimmedArguments = newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedArguments.isEmpty else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(trimmedArguments, forType: .string)
        nseScriptHelperMessage = "Copied profile arguments to clipboard."
    }

    private func copyOutput() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }

    private func copyDiagnosticInfo() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(diagnosticInfoText(), forType: .string)
        output += "\nCopied diagnostic info to clipboard."
    }

    private func diagnosticInfoText() -> String {
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

    private func nmapVersionText(nmapPath: String, nmapDirectory: String) -> String {
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
    
    private func saveCurrentXML() {
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

    private func saveAllScansToDirectory() {
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

    private func printOutput() {
        let printView = NSTextView(frame: NSRect(x: 0, y: 0, width: 720, height: 960))
        printView.string = output
        printView.isEditable = false
        printView.font = NSFont.monospacedSystemFont(ofSize: 10, weight: .regular)

        let printOperation = NSPrintOperation(view: printView)
        printOperation.jobTitle = lastCommand.isEmpty ? "Nmap Scan Output" : lastCommand
        printOperation.run()
    }
    
    private func openXML() {
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
    
    private func addSavedScan(title: String, command: String, xmlPath: String, parsedHosts: [ScannedHost]) {
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

    private func copyXMLToSavedScansDirectory(sourcePath: String, title: String) -> String? {
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

    private func savedScanFilename(title: String, date: Date) -> String {
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

    private func savedScansDirectoryURL() -> URL? {
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

    private var currentScanComparison: ScanComparison? {
        guard let baselineCompareScanID,
              let comparisonCompareScanID,
              baselineCompareScanID != comparisonCompareScanID,
              let baselineScan = scanHistory.savedScans.first(where: { $0.id == baselineCompareScanID }),
              let comparisonScan = scanHistory.savedScans.first(where: { $0.id == comparisonCompareScanID }) else {
            return nil
        }

        let baselineHosts = parseNmapXML(at: URL(fileURLWithPath: baselineScan.xmlPath))
        let comparisonHosts = parseNmapXML(at: URL(fileURLWithPath: comparisonScan.xmlPath))
        return compareScans(baseline: baselineHosts, comparison: comparisonHosts)
    }

    private func scanComparisonScanLabel(_ scan: SavedScan) -> String {
        let date = scan.scannedAt.formatted(date: .abbreviated, time: .shortened)
        return "\(date) - \(scan.title)"
    }

    private func compareScans(baseline: [ScannedHost], comparison: [ScannedHost]) -> ScanComparison {
        let baselineHostMap = Dictionary(uniqueKeysWithValues: baseline.map { ($0.address, $0) })
        let comparisonHostMap = Dictionary(uniqueKeysWithValues: comparison.map { ($0.address, $0) })

        let baselineHostAddresses = Set(baselineHostMap.keys)
        let comparisonHostAddresses = Set(comparisonHostMap.keys)

        let newHosts = comparisonHostAddresses.subtracting(baselineHostAddresses).sorted()
        let missingHosts = baselineHostAddresses.subtracting(comparisonHostAddresses).sorted()

        var newOpenPorts: [String] = []
        var closedPorts: [String] = []
        var changedServices: [String] = []

        for hostAddress in baselineHostAddresses.intersection(comparisonHostAddresses).sorted() {
            guard let baselineHost = baselineHostMap[hostAddress],
                  let comparisonHost = comparisonHostMap[hostAddress] else {
                continue
            }

            let baselinePorts = openPortMap(for: baselineHost)
            let comparisonPorts = openPortMap(for: comparisonHost)
            let baselineKeys = Set(baselinePorts.keys)
            let comparisonKeys = Set(comparisonPorts.keys)

            for key in comparisonKeys.subtracting(baselineKeys).sorted() {
                if let port = comparisonPorts[key] {
                    newOpenPorts.append("\(hostAddress) \(port.protocolName)/\(port.portNumber) \(scanPortServiceDescription(port))")
                }
            }

            for key in baselineKeys.subtracting(comparisonKeys).sorted() {
                if let port = baselinePorts[key] {
                    closedPorts.append("\(hostAddress) \(port.protocolName)/\(port.portNumber) \(scanPortServiceDescription(port))")
                }
            }

            for key in baselineKeys.intersection(comparisonKeys).sorted() {
                guard let baselinePort = baselinePorts[key],
                      let comparisonPort = comparisonPorts[key] else {
                    continue
                }

                let baselineService = scanPortServiceDescription(baselinePort)
                let comparisonService = scanPortServiceDescription(comparisonPort)

                if baselineService != comparisonService {
                    changedServices.append("\(hostAddress) \(comparisonPort.protocolName)/\(comparisonPort.portNumber): \(baselineService) -> \(comparisonService)")
                }
            }
        }

        return ScanComparison(
            newHosts: newHosts,
            missingHosts: missingHosts,
            newOpenPorts: newOpenPorts,
            closedPorts: closedPorts,
            changedServices: changedServices
        )
    }

    private func openPortMap(for host: ScannedHost) -> [String: ScannedPort] {
        Dictionary(uniqueKeysWithValues: host.ports
            .filter { $0.state == "open" }
            .map { ("\($0.protocolName)/\($0.portNumber)", $0) })
    }

    private func scanPortServiceDescription(_ port: ScannedPort) -> String {
        let description = [port.serviceName, port.product, port.version, port.extraInfo]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")

        return description.isEmpty ? "(no service details)" : description
    }

    private func copyScanComparisonReport() {
        guard let report = scanComparisonReportText() else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
        output += "\nCopied scan comparison report to clipboard."
    }

    private func exportScanComparisonReport() {
        guard let report = scanComparisonReportText() else {
            return
        }

        let panel = NSSavePanel()
        panel.title = "Export Scan Comparison Report"
        panel.nameFieldStringValue = "nmap-scan-comparison.txt"
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true

        if panel.runModal() == .OK, let destinationURL = panel.url {
            do {
                try report.write(to: destinationURL, atomically: true, encoding: .utf8)
                output += "\nExported scan comparison report to: \(destinationURL.path)"
            } catch {
                output += "\nFailed to export scan comparison report: \(error.localizedDescription)"
            }
        }
    }

    private func scanComparisonReportText() -> String? {
        guard let baselineCompareScanID,
              let comparisonCompareScanID,
              let baselineScan = scanHistory.savedScans.first(where: { $0.id == baselineCompareScanID }),
              let comparisonScan = scanHistory.savedScans.first(where: { $0.id == comparisonCompareScanID }),
              let comparison = currentScanComparison else {
            return nil
        }

        let baselineLabel = scanComparisonScanLabel(baselineScan)
        let comparisonLabel = scanComparisonScanLabel(comparisonScan)
        let generatedAt = Date().formatted(date: .abbreviated, time: .standard)
        let changeLines = scanComparisonNdiffStyleLines(comparison)

        return [
            "Nmap Scan Comparison Report",
            "Generated: \(generatedAt)",
            "",
            "Baseline Scan:",
            "  \(baselineLabel)",
            "  Date: \(baselineScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "  Command: \(baselineScan.command)",
            "  XML: \(baselineScan.xmlPath)",
            "  Hosts: \(baselineScan.hostCount)",
            "  Ports: \(baselineScan.portCount)",
            "  Tags: \(baselineScan.tags.isEmpty ? "(none)" : baselineScan.tags)",
            "  Notes: \(baselineScan.notes.isEmpty ? "(none)" : baselineScan.notes)",
            "",
            "Comparison Scan:",
            "  \(comparisonLabel)",
            "  Date: \(comparisonScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "  Command: \(comparisonScan.command)",
            "  XML: \(comparisonScan.xmlPath)",
            "  Hosts: \(comparisonScan.hostCount)",
            "  Ports: \(comparisonScan.portCount)",
            "  Tags: \(comparisonScan.tags.isEmpty ? "(none)" : comparisonScan.tags)",
            "  Notes: \(comparisonScan.notes.isEmpty ? "(none)" : comparisonScan.notes)",
            "",
            "Summary:",
            "  New Hosts: \(comparison.newHosts.count)",
            "  Missing Hosts: \(comparison.missingHosts.count)",
            "  New Open Ports: \(comparison.newOpenPorts.count)",
            "  Closed Ports: \(comparison.closedPorts.count)",
            "  Service Changes: \(comparison.changedServices.count)",
            "",
            "Ndiff-style Changes:",
            changeLines.joined(separator: "\n"),
            "",
            "Legend:",
            "  + added in comparison scan",
            "  - removed from comparison scan",
            "  ~ changed between scans",
            "",
            "Details:",
            "New Hosts:",
            scanComparisonReportSection(comparison.newHosts),
            "",
            "Missing Hosts:",
            scanComparisonReportSection(comparison.missingHosts),
            "",
            "New Open Ports:",
            scanComparisonReportSection(comparison.newOpenPorts),
            "",
            "Closed Ports:",
            scanComparisonReportSection(comparison.closedPorts),
            "",
            "Changed Services:",
            scanComparisonReportSection(comparison.changedServices)
        ].joined(separator: "\n")
    }

    private func scanComparisonReportSection(_ rows: [String]) -> String {
        rows.isEmpty ? "No changes" : rows.map { "- \($0)" }.joined(separator: "\n")
    }

    private func scanComparisonNdiffStyleLines(_ comparison: ScanComparison) -> [String] {
        var lines: [String] = []

        lines.append(contentsOf: comparison.newHosts.map { "+ Host added: \($0)" })
        lines.append(contentsOf: comparison.missingHosts.map { "- Host removed: \($0)" })
        lines.append(contentsOf: comparison.newOpenPorts.map { "+ Open port: \($0)" })
        lines.append(contentsOf: comparison.closedPorts.map { "- Open port removed or closed: \($0)" })
        lines.append(contentsOf: comparison.changedServices.map { "~ Service changed: \($0)" })

        return lines.isEmpty ? ["No differences detected."] : lines
    }

    private func loadSelectedSavedScanMetadata() {
        guard let selectedSavedScan else {
            savedScanNotesText = ""
            savedScanTagsText = ""
            return
        }

        savedScanNotesText = selectedSavedScan.notes
        savedScanTagsText = selectedSavedScan.tags
    }

    private func saveSelectedSavedScanMetadata() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let scanIndex = scanHistory.savedScans.firstIndex(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        var updatedScans = scanHistory.savedScans
        updatedScans[scanIndex].notes = savedScanNotesText.trimmingCharacters(in: .whitespacesAndNewlines)
        updatedScans[scanIndex].tags = normalizedSavedScanTags(savedScanTagsText)
        scanHistory.savedScans = updatedScans
        loadSelectedSavedScanMetadata()
        output += "\nSaved notes for saved scan: \(updatedScans[scanIndex].title)"
    }

    private func clearSelectedSavedScanMetadata() {
        savedScanNotesText = ""
        savedScanTagsText = ""
        saveSelectedSavedScanMetadata()
    }

    private func normalizedSavedScanTags(_ tags: String) -> String {
        tags
            .split { character in
                character == "," || character.isWhitespace
            }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ", ")
    }

    private func useSelectedSavedScanAsBaseline() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        baselineCompareScanID = selectedSavedScanID
        if comparisonCompareScanID == selectedSavedScanID {
            comparisonCompareScanID = nil
        }
        selectedTab = "Compare"
        output += "\nSet selected saved scan as comparison baseline."
    }

    private func useSelectedSavedScanAsComparison() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        comparisonCompareScanID = selectedSavedScanID
        if baselineCompareScanID == selectedSavedScanID {
            baselineCompareScanID = nil
        }
        selectedTab = "Compare"
        output += "\nSet selected saved scan as comparison target."
    }

    private func reloadSelectedSavedScan() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        reloadSavedScan(id: selectedSavedScanID)
    }

    private func revealSelectedSavedScanInFinder() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSWorkspace.shared.activateFileViewerSelecting([
            URL(fileURLWithPath: savedScan.xmlPath)
        ])
    }

    private func openSelectedSavedScanExternally() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSWorkspace.shared.open(URL(fileURLWithPath: savedScan.xmlPath))
    }

    private func useSelectedSavedScanCommand() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        let parsedCommand = scanFormValues(fromSavedCommand: savedScan.command)
        guard !parsedCommand.target.isEmpty else {
            output += "\nCould not load saved scan command into scan form: no target found."
            return
        }

        arguments = parsedCommand.arguments
        target = parsedCommand.target
        lastCommand = savedScan.command
        selectedTab = "Output"
        output += "\nLoaded saved scan command into scan form."
        output += "\nTarget: \(target)"
        output += "\nArguments: \(arguments.isEmpty ? "(none)" : arguments)"
    }

    private func scanFormValues(fromSavedCommand command: String) -> (arguments: String, target: String) {
        var parts = shellSplit(command)

        if let firstPart = parts.first {
            let firstName = URL(fileURLWithPath: firstPart).lastPathComponent
            if firstPart == "nmap" || firstName == "nmap" {
                parts.removeFirst()
            }
        }

        var argumentValues: [String] = []
        var targetValues: [String] = []
        var index = 0

        while index < parts.count {
            let part = parts[index]

            if part == "-oX" || part == "-oA" || part == "-oN" || part == "-oG" || part == "-oS" {
                index += 2
                continue
            }

            if part.hasPrefix("-oX") || part.hasPrefix("-oA") || part.hasPrefix("-oN") || part.hasPrefix("-oG") || part.hasPrefix("-oS") {
                index += 1
                continue
            }

            if part == "--stylesheet" || part == "--webxml" || part == "--resume" || part == "-iL" || part == "-iR" {
                argumentValues.append(part)
                if index + 1 < parts.count {
                    argumentValues.append(parts[index + 1])
                    index += 2
                } else {
                    index += 1
                }
                continue
            }

            if part.hasPrefix("-") {
                argumentValues.append(part)
            } else {
                targetValues.append(part)
            }

            index += 1
        }

        return (argumentValues.joined(separator: " "), targetValues.joined(separator: " "))
    }

    private func copySelectedSavedScanCommand() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(savedScan.command, forType: .string)
        output += "\nCopied saved scan command to clipboard: \(savedScan.command)"
    }

    private func copySelectedSavedScanSummary() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID,
              let savedScan = scanHistory.savedScans.first(where: { $0.id == selectedSavedScanID }) else {
            return
        }

        let summary = savedScanSummaryText(savedScan)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(summary, forType: .string)
        output += "\nCopied saved scan summary to clipboard."
    }

    private func savedScanSummaryText(_ savedScan: SavedScan) -> String {
        [
            "Nmap Saved Scan Summary",
            "Title: \(savedScan.title)",
            "Date: \(savedScan.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "Command: \(savedScan.command)",
            "Hosts: \(savedScan.hostCount)",
            "Ports: \(savedScan.portCount)",
            "Tags: \(savedScan.tags.isEmpty ? "(none)" : savedScan.tags)",
            "Notes: \(savedScan.notes.isEmpty ? "(none)" : savedScan.notes)",
            "XML: \(savedScan.xmlPath)"
        ].joined(separator: "\n")
    }

    private func reloadSavedScan(id savedScanID: SavedScan.ID) {
        guard let savedScan = scanHistory.savedScans.first(where: { $0.id == savedScanID }) else {
            return
        }

        scanHistory.selectedSavedScanID = savedScanID
        scanHistory.selectedSavedScanIDs = [savedScanID]

        let url = URL(fileURLWithPath: savedScan.xmlPath)
        let parsedHosts = parseNmapXML(at: url)
        let parsedPorts = parsedHosts.flatMap { $0.ports }

        hosts = parsedHosts
        selectedHostID = parsedHosts.first?.id
        lastXMLPath = savedScan.xmlPath
        lastCommand = savedScan.command
        exitStatus = nil
        status = parsedHosts.isEmpty ? "Reloaded saved scan with no hosts" : "Reloaded saved scan"
        selectedTab = "Hosts"

        output = "Reloaded saved scan: \(savedScan.xmlPath)\n"
        output += "Parsed \(parsedHosts.count) host\(parsedHosts.count == 1 ? "" : "s").\n"
        output += "Parsed \(parsedPorts.count) port result\(parsedPorts.count == 1 ? "" : "s")."
    }

    private func exportSavedScanHistory() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.nameFieldStringValue = "nmap-saved-scan-history.json"

        guard panel.runModal() == .OK,
              let url = panel.url else {
            return
        }

        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(scanHistory.savedScans)
            try data.write(to: url, options: .atomic)
            output += "\nExported \(scanHistory.savedScans.count) saved scan history item\(scanHistory.savedScans.count == 1 ? "" : "s") to: \(url.path)"
        } catch {
            output += "\nFailed to export saved scan history: \(error.localizedDescription)"
        }
    }

    private func importSavedScanHistory() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true

        guard panel.runModal() == .OK,
              let url = panel.url else {
            return
        }

        do {
            let data = try Data(contentsOf: url)
            let importedScans = try JSONDecoder().decode([SavedScan].self, from: data)
                .filter { !$0.title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

            guard !importedScans.isEmpty else {
                output += "\nNo saved scan history items found in selected JSON file."
                return
            }

            mergeImportedSavedScans(importedScans)
            output += "\nImported \(importedScans.count) saved scan history item\(importedScans.count == 1 ? "" : "s")."
        } catch {
            output += "\nFailed to import saved scan history: \(error.localizedDescription)"
        }
    }

    private func mergeImportedSavedScans(_ importedScans: [SavedScan]) {
        var mergedScans = scanHistory.savedScans

        for importedScan in importedScans {
            if let existingIndex = mergedScans.firstIndex(where: { $0.id == importedScan.id || $0.xmlPath == importedScan.xmlPath }) {
                mergedScans[existingIndex] = importedScan
            } else {
                mergedScans.append(importedScan)
            }
        }

        mergedScans.sort { $0.scannedAt > $1.scannedAt }
        scanHistory.savedScans = mergedScans

        if let newestImportedScan = importedScans.sorted(by: { $0.scannedAt > $1.scannedAt }).first {
            scanHistory.selectedSavedScanID = newestImportedScan.id
            scanHistory.selectedSavedScanIDs = [newestImportedScan.id]
            loadSelectedSavedScanMetadata()
        }
    }

    private var selectedSavedScanIDsForDeletion: Set<SavedScan.ID> {
        if !scanHistory.selectedSavedScanIDs.isEmpty {
            return scanHistory.selectedSavedScanIDs
        }

        if let selectedSavedScanID = scanHistory.selectedSavedScanID {
            return [selectedSavedScanID]
        }

        return []
    }

    private func syncPrimarySavedScanSelection(_ selectedIDs: Set<SavedScan.ID>) {
        guard !selectedIDs.isEmpty else {
            scanHistory.selectedSavedScanID = nil
            loadSelectedSavedScanMetadata()
            return
        }

        if let selectedSavedScanID = scanHistory.selectedSavedScanID,
           selectedIDs.contains(selectedSavedScanID) {
            loadSelectedSavedScanMetadata()
            return
        }

        scanHistory.selectedSavedScanID = scanHistory.savedScans.first { selectedIDs.contains($0.id) }?.id
        loadSelectedSavedScanMetadata()
    }

    private func deleteSelectedSavedScan() {
        let selectedIDs = selectedSavedScanIDsForDeletion
        guard !selectedIDs.isEmpty else {
            return
        }

        for savedScanID in selectedIDs {
            scanHistory.removeSavedScan(id: savedScanID, deleteFile: true)
        }

        scanHistory.selectedSavedScanIDs.removeAll()
        scanHistory.selectedSavedScanID = nil
        loadSelectedSavedScanMetadata()

        output += "\nDeleted \(selectedIDs.count) saved scan\(selectedIDs.count == 1 ? "" : "s")."
    }
    
    private var selectedSavedScan: SavedScan? {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return nil
        }

        return scanHistory.savedScans.first { $0.id == selectedSavedScanID }
    }

    private var savedScanMetadataEditor: some View {
        GroupBox("Saved Scan Notes") {
            if let selectedSavedScan {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text(selectedSavedScan.title)
                            .font(.headline)

                        Button {
                            useSelectedSavedScanAsBaseline()
                        } label: {
                            Label("Compare as Baseline", systemImage: "1.circle")
                        }

                        Button {
                            useSelectedSavedScanAsComparison()
                        } label: {
                            Label("Compare as Target", systemImage: "2.circle")
                        }

                        Spacer()

                        Text(selectedSavedScan.scannedAt.formatted(date: .abbreviated, time: .shortened))
                            .foregroundStyle(.secondary)
                    }

                    TextField("Tags, comma separated", text: $savedScanTagsText)
                        .textFieldStyle(.roundedBorder)

                    TextEditor(text: $savedScanNotesText)
                        .font(.body)
                        .frame(minHeight: 70)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .stroke(.quaternary)
                        )

                    HStack {
                        Button {
                            saveSelectedSavedScanMetadata()
                        } label: {
                            Label("Save Notes", systemImage: "square.and.arrow.down")
                        }

                        Button {
                            clearSelectedSavedScanMetadata()
                        } label: {
                            Label("Clear Notes", systemImage: "eraser")
                        }
                        .disabled(savedScanNotesText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && savedScanTagsText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                        Spacer()
                    }
                }
            } else {
                Text("Select a saved scan to add notes or tags.")
                    .foregroundStyle(.secondary)
            }
        }
        .onChange(of: scanHistory.selectedSavedScanID) { _, _ in
            loadSelectedSavedScanMetadata()
        }
        .onAppear {
            loadSelectedSavedScanMetadata()
        }
    }

    private var savedScansFilterBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)

            TextField("Filter saved scans by title, command, date, XML path, host count, or port count", text: $savedScansFilterText)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    // Consume Return so the window's default Run button does not start a new scan.
                }

            if isFilteringSavedScans {
                Button("Clear") {
                    savedScansFilterText = ""
                }
                .keyboardShortcut(.cancelAction)
            }
        }
    }

    private func scanMetricCard(title: String, value: String, systemImage: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text(value)
                .font(.title3.bold())
                .textSelection(.enabled)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private func scanPortStateCount(_ state: String) -> Int {
        allPorts.filter { $0.state == state }.count
    }

    private func hostPortStateCount(_ host: ScannedHost, state: String) -> Int {
        host.ports.filter { $0.state == state }.count
    }

    private func sortedPorts(_ ports: [ScannedPort]) -> [ScannedPort] {
        ports.sorted {
            let leftNumber = Int($0.portNumber) ?? Int.max
            let rightNumber = Int($1.portNumber) ?? Int.max

            if leftNumber == rightNumber {
                return $0.protocolName < $1.protocolName
            }

            return leftNumber < rightNumber
        }
    }

    private func copyScanDetailsSummary() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(scanDetailsSummaryText(), forType: .string)
        output += "\nCopied scan details summary to clipboard."
    }

    private func copySelectedHostAddress() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHost.address, forType: .string)
        output += "\nCopied selected host address to clipboard: \(selectedHost.address)"
    }

    private func copySelectedHostSummary() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHostSummaryText(selectedHost), forType: .string)
        output += "\nCopied selected host summary to clipboard."
    }

    private func copySelectedHostOpenPorts() {
        guard let selectedHost else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedHostOpenPortsText(selectedHost), forType: .string)
        output += "\nCopied selected host open ports to clipboard."
    }

    private func copySelectedPortHostPort() {
        guard let selectedPort else {
            return
        }

        let hostPort = "\(selectedPort.hostAddress):\(selectedPort.portNumber)/\(selectedPort.protocolName)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(hostPort, forType: .string)
        output += "\nCopied selected port to clipboard: \(hostPort)"
    }

    private func copySelectedPortSummary() {
        guard let selectedPort else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedPortSummaryText(selectedPort), forType: .string)
        output += "\nCopied selected port summary to clipboard."
    }

    private func showSelectedPortHostDetails() {
        guard let selectedPort,
              let host = hosts.first(where: { $0.address == selectedPort.hostAddress }) else {
            return
        }

        selectedHostID = host.id
        selectedTab = "Details"
    }

    private func selectedPortSummaryText(_ port: ScannedPort) -> String {
        [
            "Nmap Port Summary",
            "Host: \(port.hostAddress)",
            "Port: \(port.portNumber)/\(port.protocolName)",
            "State: \(port.state)",
            "Service: \(port.serviceName.isEmpty ? "None" : port.serviceName)",
            "Product: \(port.product.isEmpty ? "None" : port.product)",
            "Version: \(port.version.isEmpty ? "None" : port.version)",
            "Extra Info: \(port.extraInfo.isEmpty ? "None" : port.extraInfo)",
            "Summary: \(scanPortServiceDescription(port))"
        ].joined(separator: "\n")
    }

    private func copySelectedServiceHostPort() {
        guard let selectedServicePort else {
            return
        }

        let hostPort = "\(selectedServicePort.hostAddress):\(selectedServicePort.portNumber)/\(selectedServicePort.protocolName)"
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(hostPort, forType: .string)
        output += "\nCopied selected service host and port to clipboard: \(hostPort)"
    }

    private func copySelectedServiceSummary() {
        guard let selectedServicePort else {
            return
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(selectedServiceSummaryText(selectedServicePort), forType: .string)
        output += "\nCopied selected service summary to clipboard."
    }

    private func copySelectedServiceProductVersion() {
        guard let selectedServicePort else {
            return
        }

        let productVersion = [
            selectedServicePort.product,
            selectedServicePort.version,
            selectedServicePort.extraInfo
        ]
        .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        .joined(separator: " ")

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(productVersion.isEmpty ? selectedServicePort.serviceName : productVersion, forType: .string)
        output += "\nCopied selected service product/version to clipboard."
    }

    private func showSelectedServiceHostDetails() {
        guard let selectedServicePort,
              let host = hosts.first(where: { $0.address == selectedServicePort.hostAddress }) else {
            return
        }

        selectedHostID = host.id
        selectedTab = "Details"
    }

    private func selectedServiceSummaryText(_ port: ScannedPort) -> String {
        [
            "Nmap Service Summary",
            "Host: \(port.hostAddress)",
            "Port: \(port.portNumber)/\(port.protocolName)",
            "State: \(port.state)",
            "Service: \(port.serviceName.isEmpty ? "None" : port.serviceName)",
            "Product: \(port.product.isEmpty ? "None" : port.product)",
            "Version: \(port.version.isEmpty ? "None" : port.version)",
            "Extra Info: \(port.extraInfo.isEmpty ? "None" : port.extraInfo)",
            "Summary: \(scanPortServiceDescription(port))"
        ].joined(separator: "\n")
    }

    private func scanDetailsSummaryText() -> String {
        [
            "Nmap Scan Details",
            "Status: \(status)",
            "Command: \(lastCommand.isEmpty ? "None" : lastCommand)",
            "Exit status: \(exitStatus.map(String.init) ?? "None")",
            "Hosts: \(hosts.count)",
            "Ports: \(allPorts.count)",
            "Open ports: \(scanPortStateCount("open"))",
            "Filtered ports: \(scanPortStateCount("filtered"))",
            "Closed ports: \(scanPortStateCount("closed"))",
            "XML: \(lastXMLPath.isEmpty ? "None" : lastXMLPath)"
        ].joined(separator: "\n")
    }

    private func selectedHostSummaryText(_ host: ScannedHost) -> String {
        var lines = [
            "Nmap Host Summary",
            "Host: \(host.displayName)",
            "Address: \(host.address)",
            "Hostname: \(host.hostname.isEmpty ? "None" : host.hostname)",
            "Status: \(host.status)",
            "Ports: \(host.ports.count)",
            "Open ports: \(hostPortStateCount(host, state: "open"))",
            "Filtered ports: \(hostPortStateCount(host, state: "filtered"))",
            "Closed ports: \(hostPortStateCount(host, state: "closed"))"
        ]

        let openPorts = sortedPorts(host.ports.filter { $0.state == "open" })
        if !openPorts.isEmpty {
            lines.append("")
            lines.append("Open Port Details:")
            lines.append(contentsOf: openPorts.map { port in
                "- \(port.portNumber)/\(port.protocolName) \(scanPortServiceDescription(port))"
            })
        }

        return lines.joined(separator: "\n")
    }

    private func selectedHostOpenPortsText(_ host: ScannedHost) -> String {
        let openPorts = sortedPorts(host.ports.filter { $0.state == "open" })

        guard !openPorts.isEmpty else {
            return "No open ports for \(host.displayName)."
        }

        return openPorts
            .map { "\($0.portNumber)/\($0.protocolName) \(scanPortServiceDescription($0))" }
            .joined(separator: "\n")
    }

    private var resultsFilterBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)

            TextField("Filter results by host, port, state, service, or version", text: $resultsFilterText)
                .textFieldStyle(.roundedBorder)
                .onSubmit {
                    // Consume Return so the window's default Run button does not start a new scan.
                }

            if isFilteringResults {
                Button("Clear") {
                    resultsFilterText = ""
                }
                .keyboardShortcut(.cancelAction)
            }
        }
    }

    private func emptyResultsView(_ message: String) -> some View {
        VStack(spacing: 12) {
            Image(systemName: "tray")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(message)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    
    private func placeholderView(title: String, systemImage: String, message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            
            Text(title)
                .font(.title.bold())
            
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 520)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
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
    
    private func parseNmapXML(at url: URL) -> [ScannedHost] {
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
    
    private struct ScanComparison {
        let newHosts: [String]
        let missingHosts: [String]
        let newOpenPorts: [String]
        let closedPorts: [String]
        let changedServices: [String]
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
