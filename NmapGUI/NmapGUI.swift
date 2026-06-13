import SwiftUI
import Foundation

@main
struct NmapGUIApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 980, minHeight: 680)
        }
        .commands {
            CommandGroup(replacing: .newItem) { }
        }
    }
}

struct ScanProfile: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let arguments: String
    let description: String
}

struct ContentView: View {
    private let profiles: [ScanProfile] = [
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

    @State private var selectedProfile: ScanProfile
    @State private var target = "scanme.nmap.org"
    @State private var arguments = "-sV"
    @State private var output = "Ready. Choose a profile, enter a target, then run a scan."
    @State private var status = "Idle"
    @State private var exitStatus: Int32?
    @State private var isRunning = false
    @State private var selectedTab = "Output"

    @State private var runningProcess: Process?
    @State private var scanStartedAt: Date?
    @State private var lastCommand = ""

    init() {
        let defaultProfile = ScanProfile(
            name: "Service Detection",
            arguments: "-sV",
            description: "Detect service and version information."
        )
        _selectedProfile = State(initialValue: defaultProfile)
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

            Section("Later") {
                Label("Saved Scans", systemImage: "archivebox")
                    .tag("Saved Scans")
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

            placeholderView(
                title: "Hosts",
                systemImage: "desktopcomputer",
                message: "Next milestone: run Nmap with XML output and parse discovered hosts into this table."
            )
            .tabItem { Label("Hosts", systemImage: "desktopcomputer") }
            .tag("Hosts")

            placeholderView(
                title: "Ports",
                systemImage: "list.bullet.rectangle",
                message: "Next milestone: parse open, closed, and filtered ports from Nmap XML."
            )
            .tabItem { Label("Ports", systemImage: "list.bullet.rectangle") }
            .tag("Ports")

            placeholderView(
                title: "Services",
                systemImage: "network",
                message: "Next milestone: parse service names, versions, products, CPEs, and scripts."
            )
            .tabItem { Label("Services", systemImage: "network") }
            .tag("Services")

            detailsView
                .tabItem { Label("Details", systemImage: "info.circle") }
                .tag("Details")

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

            TextEditor(text: $output)
                .font(.system(.body, design: .monospaced))
                .border(.separator)
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

            Spacer()
        }
        .padding()
    }

    private var profilesView: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Built-in Profiles")
                .font(.title2.bold())

            Table(profiles) {
                TableColumn("Name") { profile in
                    Text(profile.name)
                }
                TableColumn("Arguments") { profile in
                    Text(profile.arguments.isEmpty ? "default" : profile.arguments)
                        .font(.system(.body, design: .monospaced))
                }
                TableColumn("Description") { profile in
                    Text(profile.description)
                }
            }

            Text("Custom editable profiles will be added after XML parsing and saved scans.")
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
                    .foregroundStyle(exitStatus == 0 ? .secondary : .red)
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

    private func runScan() {
        let trimmedTarget = target.trimmingCharacters(in: .whitespacesAndNewlines)
        let args = shellSplit(arguments) + [trimmedTarget]

        isRunning = true
        exitStatus = nil
        status = "Running"
        scanStartedAt = Date()
        lastCommand = commandPreview
        output = "Running \(commandPreview)...\n\n"

        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let pipe = Pipe()

            process.standardOutput = pipe
            process.standardError = pipe

            guard let binary = nmapBinaryPath() else {
                DispatchQueue.main.async {
                    output += "Failed to run nmap: bundled Resources/nmap and /usr/local/bin/nmap were not found."
                    status = "Failed"
                    isRunning = false
                    scanStartedAt = nil
                }
                return
            }

            process.executableURL = URL(fileURLWithPath: binary)
            process.arguments = args

            var env = ProcessInfo.processInfo.environment
            if let resources = Bundle.main.resourceURL?.path {
                env["NMAPDIR"] = resources
            }
            process.environment = env

            DispatchQueue.main.async {
                runningProcess = process
            }

            do {
                try process.run()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                let text = String(data: data, encoding: .utf8) ?? ""

                DispatchQueue.main.async {
                    output += text
                    output += "\nExit status: \(process.terminationStatus)"
                    exitStatus = process.terminationStatus
                    status = process.terminationStatus == 0 ? "Completed" : "Exited with errors"
                    isRunning = false
                    runningProcess = nil
                    scanStartedAt = nil
                }
            } catch {
                DispatchQueue.main.async {
                    output += "Failed to run nmap: \(error.localizedDescription)\n"
                    output += "Expected bundled Resources/nmap or /usr/local/bin/nmap."
                    status = "Failed"
                    isRunning = false
                    runningProcess = nil
                    scanStartedAt = nil
                }
            }
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

    private func copyOutput() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }
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
