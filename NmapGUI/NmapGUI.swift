import SwiftUI
import Foundation
import AppKit
import UniformTypeIdentifiers
 
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

struct ContentView: View {
    @EnvironmentObject private var scanHistory: ScanHistoryStore
    private static let customProfilesDefaultsKey = "NmapGUI.CustomProfiles"
    private static let builtInProfiles: [ScanProfile] = [
        ScanProfile(
            name: "Quick Scan",
            arguments: "-T4 -F",
            description: "Fast scan of common ports."
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
    @State private var target = "scanme.nmap.org"
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
    @State private var isOutputFindVisible = false
    @State private var outputFindText = ""
    @State private var outputFindSelection = 0
    @FocusState private var isOutputFindFocused: Bool
    
    @State private var runningProcess: Process?
    @State private var scanStartedAt: Date?
    @State private var lastCommand = ""
    @State private var lastXMLPath = ""
    
    @State private var hosts: [ScannedHost] = []
    @State private var selectedHostID: ScannedHost.ID?
    
    init() {
        let defaultProfile = ScanProfile(
            name: "Service Detection",
            arguments: "-sV",
            description: "Detect service and version information."
        )
        _selectedProfile = State(initialValue: defaultProfile)

        if let savedCustomProfiles = Self.loadSavedCustomProfiles(), !savedCustomProfiles.isEmpty {
            _profiles = State(initialValue: Self.builtInProfiles + savedCustomProfiles)
        }
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
            }

            Section("Later") {
                Label("Topology", systemImage: "point.3.connected.trianglepath.dotted")
                    .tag("Topology")
                Label("Profiles", systemImage: "slider.horizontal.3")
                    .tag("Profiles")
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
                    .onChange(of: selectedProfile) { newProfile in
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
            
            placeholderView(
                title: "Topology",
                systemImage: "point.3.connected.trianglepath.dotted",
                message: "Later milestone: draw native macOS topology from traceroute/XML data."
            )
            .tabItem { Label("Topology", systemImage: "point.3.connected.trianglepath.dotted") }
            .tag("Topology")
            
            profilesView
                .tabItem { Label("Profiles", systemImage: "slider.horizontal.3") }
                .tag("Profiles")
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
                        .onChange(of: outputFindText) { _ in
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
                Text("\(hosts.count) host\(hosts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            
            if hosts.isEmpty {
                emptyResultsView("Run a scan to populate discovered hosts.")
            } else {
                Table(hosts, selection: $selectedHostID) {
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
                Text("\(allPorts.count) port result\(allPorts.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            
            if allPorts.isEmpty {
                emptyResultsView("Run a scan to populate port results.")
            } else {
                Table(allPorts) {
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
                Text("\(allPorts.filter { !$0.serviceName.isEmpty }.count) service result\(allPorts.filter { !$0.serviceName.isEmpty }.count == 1 ? "" : "s")")
                    .foregroundStyle(.secondary)
            }
            
            if allPorts.isEmpty {
                emptyResultsView("Run a service detection scan to populate service results.")
            } else {
                Table(allPorts.filter { !$0.serviceName.isEmpty || !$0.serviceSummary.isEmpty }) {
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
                Table(scanHistory.savedScans, selection: $scanHistory.selectedSavedScanID) {
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
            .onChange(of: selectedProfileID) { _ in
                loadSelectedProfileForEditingIfNeeded()
            }
            
            Text("Duplicate a built-in profile, edit it here, then click Update Selected Profile before using it.")
                .foregroundStyle(.secondary)
        }
        .padding()
    }
    
    private var footer: some View {
        HStack {
            Circle()
                .fill(isRunning ? .orange : .green)
                .frame(width: 8, height: 8)
            
            Text(status)
                .foregroundStyle(.secondary)
            
            Spacer()
            
            if let started = scanStartedAt, isRunning {
                Text("Started \(started.formatted(date: .omitted, time: .standard))")
                    .foregroundStyle(.secondary)
            }
            
            if let exitStatus {
                Text("Exit \(exitStatus)")
                    .foregroundColor(exitStatus == 0 ? .secondary : .red)
            }
        }
        .font(.callout)
        .padding(.horizontal)
        .padding(.vertical, 8)
    }
    
    private var commandPreview: String {
        let trimmedArgs = arguments.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines)
        
        if trimmedArgs.isEmpty {
            return "nmap \(trimmedTarget)"
        } else {
            return "nmap \(trimmedArgs) \(trimmedTarget)"
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
    
    private func runScan() {
        let trimmedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines)
        let xmlURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("NmapGUI-\(UUID().uuidString).xml")
        var args = shellSplit(arguments)
        args.append(contentsOf: ["-oX", xmlURL.path, trimmedTarget])

        isRunning = true
        exitStatus = nil
        status = "Running"
        scanStartedAt = Date()
        lastCommand = commandPreview
        lastXMLPath = xmlURL.path
        hosts = []
        selectedHostID = nil
        output = "Running \(commandPreview)...\nXML output: \(xmlURL.path)\n\n"

        let process = Process()
        let pipe = Pipe()

        process.standardOutput = pipe
        process.standardError = pipe

        guard let binary = nmapBinaryPath() else {
            output += "Failed to run nmap: bundled Resources/nmap and /usr/local/bin/nmap were not found."
            status = "Failed"
            isRunning = false
            scanStartedAt = nil
            return
        }

        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = args

        var env = ProcessInfo.processInfo.environment
        if let resources = Bundle.main.resourceURL?.path {
            env["NMAPDIR"] = resources
        }
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
            }
        }

        process.terminationHandler = { finishedProcess in
            pipe.fileHandleForReading.readabilityHandler = nil
            let parsedHosts = parseNmapXML(at: xmlURL)

            DispatchQueue.main.async {
                exitStatus = finishedProcess.terminationStatus
                output += "\nExit status: \(finishedProcess.terminationStatus)"
                status = finishedProcess.terminationStatus == 0 ? "Completed" : "Exited with errors"
                hosts = parsedHosts
                selectedHostID = parsedHosts.first?.id
                if finishedProcess.terminationStatus == 0 {
                    addSavedScan(title: trimmedTarget, command: lastCommand, xmlPath: xmlURL.path, parsedHosts: parsedHosts)
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
            output += "Expected bundled Resources/nmap or /usr/local/bin/nmap."
            status = "Failed"
            isRunning = false
            runningProcess = nil
            scanStartedAt = nil
        }
    }
    
    private func stopScan() {
        guard let process = runningProcess else {
            return
        }
        
        process.terminate()
        status = "Stopping"
        output += "\n\nStopping scan...\n"
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
        outputFindText = ""
        outputFindSelection = 0
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

    private func reloadSelectedSavedScan() {
        guard let selectedSavedScanID = scanHistory.selectedSavedScanID else {
            return
        }

        reloadSavedScan(id: selectedSavedScanID)
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
    
    private func nmapBinaryPath() -> String? {
        if let bundled = Bundle.main.resourceURL?.appendingPathComponent("nmap").path,
           FileManager.default.isExecutableFile(atPath: bundled) {
            return bundled
        }
        
        let fallback = "/usr/local/bin/nmap"
        if FileManager.default.isExecutableFile(atPath: fallback) {
            return fallback
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

