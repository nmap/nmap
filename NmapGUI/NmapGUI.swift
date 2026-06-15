import SwiftUI
import Combine
import Foundation
import AppKit
import UniformTypeIdentifiers
import Darwin
 
@main
struct NmapGUIApp: App {
    @StateObject private var scanHistory = ScanHistoryStore()

    var body: some Scene {
        WindowGroup("Nmap", id: "main") {
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
                    NotificationCenter.default.post(name: .nmapGUICopyDiagnosticInfo, object: nil)
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
                    NotificationCenter.default.post(name: .nmapGUIFindOutput, object: nil)
                }
                .keyboardShortcut("f", modifiers: [.command])

                Button("Copy Output") {
                    NotificationCenter.default.post(name: .nmapGUICopyOutput, object: nil)
                }
                .keyboardShortcut("c", modifiers: [.command, .shift])

                Button("Clear Output") {
                    NotificationCenter.default.post(name: .nmapGUIClearOutput, object: nil)
                }
            }
            CommandGroup(after: .newItem) {
                Button("Open Scan...") {
                    NotificationCenter.default.post(name: .nmapGUIOpenXML, object: nil)
                }
                .keyboardShortcut("o", modifiers: [.command])

                Button("Open Scan in This Window...") {
                    NotificationCenter.default.post(name: .nmapGUIOpenXML, object: nil)
                }

                Menu("Recent Scans") {
                    if scanHistory.savedScans.isEmpty {
                        Text("No Recent Scans")
                    } else {
                        ForEach(scanHistory.savedScans.prefix(10)) { scan in
                            Button(scan.title) {
                                NotificationCenter.default.post(name: .nmapGUIOpenRecentScan, object: scan.id)
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
                    NotificationCenter.default.post(name: .nmapGUISaveXML, object: nil)
                }
                .keyboardShortcut("s", modifiers: [.command])

                Button("Save All Scans to Directory...") {
                    NotificationCenter.default.post(name: .nmapGUISaveAllScans, object: nil)
                }
                .keyboardShortcut("s", modifiers: [.command, .shift])

                Divider()

                Button("Print...") {
                    NotificationCenter.default.post(name: .nmapGUIPrintOutput, object: nil)
                }
                .keyboardShortcut("p", modifiers: [.command])
            }
            CommandMenu("Scan") {
                Button("Start Scan") {
                    NotificationCenter.default.post(name: .nmapGUIStartScan, object: nil)
                }
                .keyboardShortcut("r", modifiers: [.command])

                Button("Stop Scan") {
                    NotificationCenter.default.post(name: .nmapGUIStopScan, object: nil)
                }
                .keyboardShortcut(".", modifiers: [.command])

                Divider()

                Button("Clear Results") {
                    NotificationCenter.default.post(name: .nmapGUIClearResults, object: nil)
                }
                .keyboardShortcut("k", modifiers: [.command, .shift])

                Divider()

                Button("Show Output") {
                    NotificationCenter.default.post(name: .nmapGUIShowTab, object: "Output")
                }
                .keyboardShortcut("1", modifiers: [.command])

                Button("Show Hosts") {
                    NotificationCenter.default.post(name: .nmapGUIShowTab, object: "Hosts")
                }
                .keyboardShortcut("2", modifiers: [.command])

                Button("Show Ports") {
                    NotificationCenter.default.post(name: .nmapGUIShowTab, object: "Ports")
                }
                .keyboardShortcut("3", modifiers: [.command])

                Button("Show Services") {
                    NotificationCenter.default.post(name: .nmapGUIShowTab, object: "Services")
                }
                .keyboardShortcut("4", modifiers: [.command])

                Button("Show Details") {
                    NotificationCenter.default.post(name: .nmapGUIShowTab, object: "Details")
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

extension Notification.Name {
    static let nmapGUICopyDiagnosticInfo = Notification.Name("nmapGUICopyDiagnosticInfo")
    static let nmapGUIOpenXML = Notification.Name("NmapGUIOpenXML")
    static let nmapGUIOpenRecentScan = Notification.Name("NmapGUIOpenRecentScan")
    static let nmapGUISaveXML = Notification.Name("NmapGUISaveXML")
    static let nmapGUISaveAllScans = Notification.Name("NmapGUISaveAllScans")
    static let nmapGUIPrintOutput = Notification.Name("NmapGUIPrintOutput")
    static let nmapGUIFindOutput = Notification.Name("NmapGUIFindOutput")
    static let nmapGUICopyOutput = Notification.Name("NmapGUICopyOutput")
    static let nmapGUIClearOutput = Notification.Name("NmapGUIClearOutput")
    static let nmapGUIStartScan = Notification.Name("NmapGUIStartScan")
    static let nmapGUIStopScan = Notification.Name("NmapGUIStopScan")
    static let nmapGUIClearResults = Notification.Name("NmapGUIClearResults")
    static let nmapGUIShowTab = Notification.Name("NmapGUIShowTab")
}

struct ScanProfile: Identifiable, Hashable, Codable {
    let id: UUID
    let name: String
    let arguments: String
    let description: String
    var isBuiltIn = true

    init(
        id: UUID = UUID(),
        name: String,
        arguments: String,
        description: String,
        isBuiltIn: Bool = true
    ) {
        self.id = id
        self.name = name
        self.arguments = arguments
        self.description = description
        self.isBuiltIn = isBuiltIn
    }
}

struct ScannedHost: Identifiable, Hashable {
    let id = UUID()
    var address: String
    var hostname: String
    var status: String
    var ports: [ScannedPort]

    var displayName: String {
        hostname.isEmpty ? address : hostname
    }

    var openPortCount: Int {
        ports.filter { $0.state == "open" }.count
    }
}

struct ScannedPort: Identifiable, Hashable {
    let id = UUID()
    var hostAddress: String
    var protocolName: String
    var portNumber: String
    var state: String
    var serviceName: String
    var product: String
    var version: String
    var extraInfo: String

    var serviceSummary: String {
        [product, version, extraInfo]
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
}


struct SavedScan: Identifiable, Hashable, Codable {
    let id: UUID
    var title: String
    var command: String
    var xmlPath: String
    var scannedAt: Date
    var hostCount: Int
    var portCount: Int

    init(
        id: UUID = UUID(),
        title: String,
        command: String,
        xmlPath: String,
        scannedAt: Date,
        hostCount: Int,
        portCount: Int
    ) {
        self.id = id
        self.title = title
        self.command = command
        self.xmlPath = xmlPath
        self.scannedAt = scannedAt
        self.hostCount = hostCount
        self.portCount = portCount
    }
}

final class ScanHistoryStore: ObservableObject {
    private static let savedScansDefaultsKey = "NmapGUI.SavedScans"

    @Published var savedScans: [SavedScan] = [] {
        didSet {
            saveSavedScans()
        }
    }
    @Published var selectedSavedScanID: SavedScan.ID?

    init() {
        savedScans = Self.loadSavedScans()
    }

    func clearSavedScans(deleteFiles: Bool = false) {
        if deleteFiles {
            for scan in savedScans {
                deleteSavedScanFile(at: scan.xmlPath)
            }
        }

        savedScans.removeAll()
        selectedSavedScanID = nil
    }

    func removeSavedScan(id savedScanID: SavedScan.ID, deleteFile: Bool = false) {
        if deleteFile,
           let scan = savedScans.first(where: { $0.id == savedScanID }) {
            deleteSavedScanFile(at: scan.xmlPath)
        }

        savedScans.removeAll { $0.id == savedScanID }

        if selectedSavedScanID == savedScanID {
            selectedSavedScanID = nil
        }
    }

    private func deleteSavedScanFile(at path: String) {
        guard FileManager.default.fileExists(atPath: path) else {
            return
        }

        try? FileManager.default.removeItem(atPath: path)
    }

    private static func loadSavedScans() -> [SavedScan] {
        guard let data = UserDefaults.standard.data(forKey: savedScansDefaultsKey),
              let decoded = try? JSONDecoder().decode([SavedScan].self, from: data) else {
            return []
        }

        return decoded.filter { FileManager.default.fileExists(atPath: $0.xmlPath) }
    }

    private func saveSavedScans() {
        guard let data = try? JSONEncoder().encode(savedScans) else {
            return
        }

        UserDefaults.standard.set(data, forKey: Self.savedScansDefaultsKey)
    }
}

    private func openHelpURL(_ string: String) {
        guard let url = URL(string: string) else {
            return
        }

        NSWorkspace.shared.open(url)
    }



private extension ProcessInfo {
    var machineHardwareName: String {
        var systemInfo = utsname()
        uname(&systemInfo)

        return withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var scanHistory: ScanHistoryStore
    private static let customProfilesDefaultsKey = "NmapGUI.CustomProfiles"
    private let elapsedTimer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    @AppStorage("NmapGUI.AutoAddVerbose") private var autoAddVerbose = true
    @AppStorage("NmapGUI.AutoAddStatsEvery") private var autoAddStatsEvery = true
    @AppStorage("NmapGUI.StatsEveryValue") private var statsEveryValue = "5s"
    @AppStorage("NmapGUI.DefaultTarget") private var defaultTarget = "scanme.nmap.org"
    @AppStorage("NmapGUI.DefaultProfileName") private var defaultProfileName = "Service Detection"

    private static let builtInProfiles: [ScanProfile] = [
        ScanProfile(
            name: "Quick Scan",
            arguments: "-T4 -F",
            description: "Fast scan of common ports."
        ),
        ScanProfile(
            name: "TCP Connect over VPN",
            arguments: "-sT -sV -T4 -v",
            description: "Uses TCP connect scanning to avoid raw-packet SYN scan behavior that can be unreliable or noisy on macOS VPN interfaces.",
            isBuiltIn: true
        ),
        ScanProfile(
            name: "Regular Scan",
            arguments: "",
            description: "Default Nmap TCP scan."
        ),
        ScanProfile(
            name: "Service Detection",
            arguments: "-sV",
            description: "Detect service and version information."
        ),
        ScanProfile(
            name: "Aggressive Scan",
            arguments: "-A",
            description: "Enable OS detection, version detection, scripts, and traceroute."
        ),
        ScanProfile(
            name: "Ping Scan",
            arguments: "-sn",
            description: "Discover live hosts without port scanning."
        ),
        ScanProfile(
            name: "List Scan",
            arguments: "-sL",
            description: "List targets without sending packets."
        ),
        ScanProfile(
            name: "Intense Scan",
            arguments: "-T4 -A -v",
            description: "More detailed scan with verbose output."
        ),
        ScanProfile(
            name: "Intense Scan + UDP",
            arguments: "-sS -sU -T4 -A -v",
            description: "Detailed TCP and UDP scan. May require privileges."
        ),
        ScanProfile(
            name: "Slow Comprehensive Scan",
            arguments: "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script default or safe",
            description: "Broad scan inspired by classic Zenmap profiles."
        ),
        ScanProfile(
            name: "Custom",
            arguments: "-sV",
            description: "Edit arguments manually."
        )
    ]
    
    @State private var profiles: [ScanProfile] = Self.builtInProfiles
    
    @State private var selectedProfile: ScanProfile
    @State private var target = UserDefaults.standard.string(forKey: "NmapGUI.DefaultTarget") ?? "scanme.nmap.org"
    @State private var arguments = "-sV"
    @State private var newProfileName = ""
    @State private var newProfileArguments = "-sV"
    @State private var newProfileDescription = "Custom scan profile."
    @State private var selectedProfileID: ScanProfile.ID?
    @State private var output = "Ready. Choose a profile, enter a target, then run a scan."
    @State private var status = "Idle"
    @State private var exitStatus: Int32?
    @State private var isRunning = false
    @State private var selectedTab = "Output"
    @State private var baselineCompareScanID: SavedScan.ID?
    @State private var comparisonCompareScanID: SavedScan.ID?
    @State private var isOutputFindVisible = false
    @State private var outputFindText = ""
    @State private var outputFindSelection = 0
    @FocusState private var isOutputFindFocused: Bool
    
    @State private var runningProcess: Process?
    @State private var privilegedScanPID: Int32?
    @State private var privilegedChildPIDPath: String?
    @State private var scanStartedAt: Date?
    @State private var scanProgressPercent: Double?
    @State private var isUsingEstimatedScanProgress = false
    @State private var scanEstimatedCompletionText = ""
    @State private var scanProgressMessage = ""
    @State private var scanPhaseProgressText = ""
    @State private var scanPortPhasePercent: Double?
    @State private var scanServicePhasePercent: Double?
    @State private var scanScriptPhasePercent: Double?
    @State private var scanElapsedText = ""
    @State private var scanProgressBuffer = ""
    @State private var lastCommand = ""
    @State private var lastXMLPath = ""
    
    @State private var hosts: [ScannedHost] = []
    @State private var selectedHostID: ScannedHost.ID?
    @State private var resultsFilterText = ""
    @State private var savedScansFilterText = ""
    @State private var didInstallDiagnosticInfoObserver = false
    
    init() {
        let savedCustomProfiles = Self.loadSavedCustomProfiles() ?? []
        let allProfiles = Self.builtInProfiles + savedCustomProfiles
        let savedDefaultProfileName = UserDefaults.standard.string(forKey: "NmapGUI.DefaultProfileName") ?? "Service Detection"
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
                let endRange = NSRange(location: max(textView.string.count - 1, 0), length: 1)
                textView.scrollRangeToVisible(endRange)

                DispatchQueue.main.async {
                    let documentHeight = textView.bounds.height
                    let visibleHeight = scrollView.contentView.bounds.height
                    let y = max(0, documentHeight - visibleHeight)
                    scrollView.contentView.scroll(to: NSPoint(x: 0, y: y))
                    scrollView.reflectScrolledClipView(scrollView.contentView)
                }
            }

            context.coordinator.applyFindHighlight()
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
    
    private var allPorts: [ScannedPort] {
        hosts.flatMap { $0.ports }
    }

    private var filteredHosts: [ScannedHost] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return hosts
        }

        return hosts.filter { hostMatchesFilter($0, query: query) }
    }

    private var filteredPorts: [ScannedPort] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return allPorts
        }

        return allPorts.filter { portMatchesFilter($0, query: query) }
    }

    private var allServicePorts: [ScannedPort] {
        allPorts.filter { !$0.serviceName.isEmpty || !$0.serviceSummary.isEmpty }
    }

    private var filteredServicePorts: [ScannedPort] {
        let query = normalizedResultsFilterText

        guard !query.isEmpty else {
            return allServicePorts
        }

        return allServicePorts.filter { portMatchesFilter($0, query: query) }
    }

    private var normalizedResultsFilterText: String {
        resultsFilterText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private var isFilteringResults: Bool {
        !normalizedResultsFilterText.isEmpty
    }

    private func hostMatchesFilter(_ host: ScannedHost, query: String) -> Bool {
        let hostText = [
            host.address,
            host.hostname,
            host.status,
            "\(host.openPortCount)"
        ]
        .joined(separator: " ")
        .lowercased()

        if hostText.contains(query) {
            return true
        }

        return host.ports.contains { portMatchesFilter($0, query: query) }
    }

    private func portMatchesFilter(_ port: ScannedPort, query: String) -> Bool {
        [
            port.hostAddress,
            port.protocolName,
            port.portNumber,
            port.state,
            port.serviceName,
            port.product,
            port.version,
            port.extraInfo,
            port.serviceSummary
        ]
        .joined(separator: " ")
        .lowercased()
        .contains(query)
    }

    private var filteredSavedScans: [SavedScan] {
        let query = normalizedSavedScansFilterText

        guard !query.isEmpty else {
            return scanHistory.savedScans
        }

        return scanHistory.savedScans.filter { savedScanMatchesFilter($0, query: query) }
    }

    private var normalizedSavedScansFilterText: String {
        savedScansFilterText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private var isFilteringSavedScans: Bool {
        !normalizedSavedScansFilterText.isEmpty
    }

    private func savedScanMatchesFilter(_ scan: SavedScan, query: String) -> Bool {
        let dateText = scan.scannedAt.formatted(date: .abbreviated, time: .shortened)

        return [
            scan.title,
            scan.command,
            scan.xmlPath,
            dateText,
            "\(scan.hostCount)",
            "\(scan.portCount)"
        ]
        .joined(separator: " ")
        .lowercased()
        .contains(query)
    }

    
    private var selectedHost: ScannedHost? {
        guard let selectedHostID else {
            return hosts.first
        }
        return hosts.first { $0.id == selectedHostID }
    }
    
    private var selectedProfileForActions: ScanProfile? {
        guard let selectedProfileID else {
            return nil
        }

        return profiles.first { $0.id == selectedProfileID }
    }
    
    private var selectedCustomProfileForEditing: ScanProfile? {
        guard let profile = selectedProfileForActions,
              !profile.isBuiltIn else {
            return nil
        }

        return profile
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
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIOpenXML)) { _ in
            guard !isRunning else {
                return
            }
            openXML()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIOpenRecentScan)) { notification in
            guard !isRunning,
                  let savedScanID = notification.object as? SavedScan.ID else {
                return
            }
            reloadSavedScan(id: savedScanID)
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUISaveXML)) { _ in
            saveCurrentXML()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUISaveAllScans)) { _ in
            saveAllScansToDirectory()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIPrintOutput)) { _ in
            printOutput()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIFindOutput)) { _ in
            selectedTab = "Output"
            isOutputFindVisible = true
            DispatchQueue.main.async {
                isOutputFindFocused = true
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUICopyOutput)) { _ in
            copyOutput()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIClearOutput)) { _ in
            guard !isRunning else {
                return
            }
            output = ""
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIStartScan)) { _ in
            guard !isRunning,
                  !target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return
            }
            runScan()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIStopScan)) { _ in
            guard isRunning else {
                return
            }
            stopScan()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIClearResults)) { _ in
            guard !isRunning else {
                return
            }
            clearResults()
        }
        .onReceive(NotificationCenter.default.publisher(for: .nmapGUIShowTab)) { notification in
            guard let tabName = notification.object as? String else {
                return
            }
            selectedTab = tabName
        }
        .onAppear {
            installDiagnosticInfoObserverIfNeeded()
        }
    }

    private func installDiagnosticInfoObserverIfNeeded() {
        guard !didInstallDiagnosticInfoObserver else {
            return
        }

        didInstallDiagnosticInfoObserver = true
        NotificationCenter.default.addObserver(
            forName: .nmapGUICopyDiagnosticInfo,
            object: nil,
            queue: .main
        ) { _ in
            copyDiagnosticInfo()
        }
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
                selectedMatchIndex: outputFindSelection
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
            }
        }
        .padding()
    }
    
    private var portsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Ports")
                    .font(.headline)
                Spacer()
                Text(isFilteringResults ? "\(filteredPorts.count) of \(allPorts.count) port results" : "\(allPorts.count) port result\(allPorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            
            resultsFilterBar

            if allPorts.isEmpty {
                emptyResultsView("Run a scan to populate port results.")
            } else if filteredPorts.isEmpty {
                emptyResultsView("No ports match the current filter.")
            } else {
                Table(filteredPorts) {
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
            }
            
            resultsFilterBar

            if allServicePorts.isEmpty {
                emptyResultsView("Run a service detection scan to populate service results.")
            } else if filteredServicePorts.isEmpty {
                emptyResultsView("No services match the current filter.")
            } else {
                Table(filteredServicePorts) {
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
            }
        }
        .padding()
    }
    
    private var detailsView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Scan Details", systemImage: "info.circle")
                .font(.title2.bold())
            
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
                    Text("Hosts")
                        .foregroundStyle(.secondary)
                    Text("\(hosts.count)")
                }
                GridRow {
                    Text("Ports")
                        .foregroundStyle(.secondary)
                    Text("\(allPorts.count)")
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
            
            if let selectedHost {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    Text("Selected Host")
                        .font(.headline)
                    Text(selectedHost.displayName)
                        .font(.system(.body, design: .monospaced))
                    Text("\(selectedHost.openPortCount) open port\(selectedHost.openPortCount == 1 ? "" : "s")")
                        .foregroundStyle(.secondary)
                }
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
                            .position(point)
                        }
                    }
                }
                .frame(minHeight: 430)

                if let selectedHost {
                    GroupBox("Selected Host") {
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

                Button(role: .destructive) {
                    deleteSelectedSavedScan()
                } label: {
                    Image(systemName: "trash")
                }
                .help("Remove Selected Scan")
                .disabled(scanHistory.selectedSavedScanID == nil)
            }
            if scanHistory.savedScans.isEmpty {
                emptyResultsView("Completed scans and opened XML files will appear here for quick reload during this app session.")
            } else {
                savedScansFilterBar

                if filteredSavedScans.isEmpty {
                    emptyResultsView("No saved scans match the current filter.")
                } else {
                    Table(filteredSavedScans, selection: $scanHistory.selectedSavedScanID) {
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
                        TableColumn("XML") { scan in
                            Text(scan.xmlPath)
                                .font(.system(.body, design: .monospaced))
                        }
                    }
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
                        TextField("-sV -T4", text: $newProfileArguments)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                    }

                    GridRow {
                        Text("Advanced")
                            .foregroundStyle(.secondary)
                        profileAdvancedOptionsRow
                    }

                    GridRow {
                        Text("Description")
                            .foregroundStyle(.secondary)
                        TextField("Describe when to use this profile", text: $newProfileDescription)
                            .textFieldStyle(.roundedBorder)
                    }
                }

                HStack {
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
            
            Table(profiles, selection: $selectedProfileID) {
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
            
            Text("Duplicate a built-in profile, edit it here, then click Update Selected Profile before using it.")
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

    private func progressPercentText(from line: String) -> String? {
        guard let aboutRange = line.range(of: "About", options: [.caseInsensitive]),
              let percentRange = line[aboutRange.upperBound...].range(of: "%") else {
            return nil
        }

        let candidate = line[aboutRange.upperBound..<percentRange.lowerBound]
        let allowed = CharacterSet(charactersIn: "0123456789.")
        let percentText = String(candidate.unicodeScalars.filter { allowed.contains($0) })
        return percentText.isEmpty ? nil : percentText
    }

    private func overallProgressPercent(from line: String, phasePercent: Double) -> (percent: Double, overallMessage: String, phaseMessage: String)? {
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

    private func progressFloorPercent(from line: String) -> Double? {
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

    private func updateScanProgress(from text: String) {
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

    private func updateEstimatedCompletionFromPercent(_ percent: Double) {
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

    private func estimatedScanDurationSeconds() -> Double {
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

    private func updateScanElapsedTime() {
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

    private func runScan() {
        let targetList = splitTargets(target)
        let trimmedTarget = targetList.joined(separator: " ")
        guard !targetList.isEmpty else {
            output += "\nNo target specified."
            status = "Idle"
            return
        }

        let xmlURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("NmapGUI-\(UUID().uuidString).xml")
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
        lastCommand = commandPreview
        lastXMLPath = xmlURL.path
        hosts = []
        selectedHostID = nil
        output = "Running \(commandPreview)...\nXML output: \(xmlURL.path)\n\n"

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
        output += "Using nmap: \(binary)\n"
        output += "Using NMAPDIR: \(dataDirectory)\n"
        output += "Privilege mode: normal user\n\n"

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
                output += text
                updateScanProgress(from: text)
            }
        }

        process.terminationHandler = { finishedProcess in
            pipe.fileHandleForReading.readabilityHandler = nil
            let parsedHosts = parseNmapXML(at: xmlURL)

            DispatchQueue.main.async {
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
            .appendingPathComponent("NmapGUI-\(UUID().uuidString)-privileged.log")
        let statusURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("NmapGUI-\(UUID().uuidString)-privileged.status")
        let doneURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("NmapGUI-\(UUID().uuidString)-privileged.done")
        let childPIDURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("NmapGUI-\(UUID().uuidString)-privileged.childpid")

        do {
            let privilegedBinary = try PrivilegedNmapRunner.bundledNmapPath()
            let privilegedDataDirectory = PrivilegedNmapRunner.nmapDataDirectory(for: privilegedBinary)
            output += "Using nmap: \(privilegedBinary)\n"
            output += "Using NMAPDIR: \(privilegedDataDirectory)\n"
            output += "Privilege mode: administrator\n"
        } catch {
            output += "Using nmap: unavailable before administrator launch (\(error.localizedDescription))\n"
            output += "Privilege mode: administrator\n"
        }
        output += "Administrator authorization requested. Running nmap as root...\n"
        output += "Privileged output log: \(logURL.path)\n"
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
            output += "Privileged nmap PID: \(pid)\n\n"
            scanPhaseProgressText = "Phase: privileged scan running"

            var lastOffset: UInt64 = 0

            while !FileManager.default.fileExists(atPath: doneURL.path) && PrivilegedNmapRunner.isRunning(pid: pid) {
                let newTextAndOffset = readNewText(from: logURL, startingAt: lastOffset)
                lastOffset = newTextAndOffset.offset

                if !newTextAndOffset.text.isEmpty {
                    output += newTextAndOffset.text
                    updateScanProgress(from: newTextAndOffset.text)
                }

                try await Task.sleep(nanoseconds: 750_000_000)
            }

            let finalTextAndOffset = readNewText(from: logURL, startingAt: lastOffset)
            lastOffset = finalTextAndOffset.offset

            if !finalTextAndOffset.text.isEmpty {
                output += finalTextAndOffset.text
                updateScanProgress(from: finalTextAndOffset.text)
            }

            let parsedHosts = parseNmapXML(at: xmlURL)
            let realExitStatus = readExitStatus(from: statusURL) ?? 1
            let succeeded = realExitStatus == 0 && FileManager.default.fileExists(atPath: xmlURL.path)

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
        guard let profile = selectedCustomProfileForEditing else {
            return
        }

        loadProfileIntoEditor(profile)
    }
    
    private func loadProfileIntoEditor(_ profile: ScanProfile) {
        newProfileName = profile.name
        newProfileArguments = profile.arguments
        newProfileDescription = profile.description
    }
    
    private func profileArgumentsArray() -> [String] {
        shellSplit(newProfileArguments)
    }

    private func profileHasArgument(_ argument: String) -> Bool {
        profileArgumentsArray().contains(argument)
    }

    private func appendProfileArgumentIfMissing(_ argument: String) {
        var argumentsArray = profileArgumentsArray()

        guard !argumentsArray.contains(argument) else {
            return
        }

        argumentsArray.append(argument)
        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    private func removeProfileArgument(_ argument: String) {
        let argumentsArray = profileArgumentsArray().filter { $0 != argument }
        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    private func profileTimingValue() -> String {
        profileArgumentsArray().first {
            $0.range(of: #"^-T[0-5]$"#, options: .regularExpression) != nil
        } ?? ""
    }

    private func setProfileTimingValue(_ value: String) {
        var argumentsArray = profileArgumentsArray().filter {
            $0.range(of: #"^-T[0-5]$"#, options: .regularExpression) == nil
        }

        if !value.isEmpty {
            argumentsArray.append(value)
        }

        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    private func clearProfileEditor() {
        selectedProfileID = nil
        newProfileName = ""
        newProfileArguments = "-sV"
        newProfileDescription = "Custom scan profile."
    }
    
    private static func loadSavedCustomProfiles() -> [ScanProfile]? {
        guard let data = UserDefaults.standard.data(forKey: customProfilesDefaultsKey) else {
            return nil
        }

        return try? JSONDecoder().decode([ScanProfile].self, from: data)
    }
    
    private func saveCustomProfiles() {
        let customProfiles = profiles.filter { !$0.isBuiltIn }

        guard let data = try? JSONEncoder().encode(customProfiles) else {
            return
        }

        UserDefaults.standard.set(data, forKey: Self.customProfilesDefaultsKey)
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
            "NmapGUI Diagnostic Info",
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
            .appendingPathComponent("NmapGUI", isDirectory: true)
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
            "  Command: \(baselineScan.command)",
            "  XML: \(baselineScan.xmlPath)",
            "  Hosts: \(baselineScan.hostCount)",
            "  Ports: \(baselineScan.portCount)",
            "",
            "Comparison Scan:",
            "  \(comparisonLabel)",
            "  Command: \(comparisonScan.command)",
            "  XML: \(comparisonScan.xmlPath)",
            "  Hosts: \(comparisonScan.hostCount)",
            "  Ports: \(comparisonScan.portCount)",
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

    private func reloadSavedScan(id savedScanID: SavedScan.ID) {
        guard let savedScan = scanHistory.savedScans.first(where: { $0.id == savedScanID }) else {
            return
        }

        scanHistory.selectedSavedScanID = savedScanID

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

    private func deleteSelectedSavedScan() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        scanHistory.removeSavedScan(id: selectedSavedScanID, deleteFile: true)
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
    
    private func nmapDataDirectory(for binaryPath: String) -> String {
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

    private func nmapBinaryPath() -> String? {
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
    
    private func shellSplit(_ string: String) -> [String] {
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

