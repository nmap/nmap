import SwiftUI

@main
struct NmapGUIApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 760, minHeight: 520)
        }
    }
}

struct ContentView: View {
    @State private var target = "scanme.nmap.org"
    @State private var arguments = "-sV"
    @State private var output = "Ready. Build the Nmap CLI target first, then run a scan."
    @State private var isRunning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Nmap for macOS")
                .font(.largeTitle.bold())

            HStack {
                TextField("Target", text: $target)
                    .textFieldStyle(.roundedBorder)
                TextField("Arguments", text: $arguments)
                    .textFieldStyle(.roundedBorder)
                Button(isRunning ? "Running..." : "Scan") {
                    runScan()
                }
                .disabled(isRunning || target.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            TextEditor(text: $output)
                .font(.system(.body, design: .monospaced))
                .border(.separator)
        }
        .padding()
    }

    private func runScan() {
        isRunning = true
        output = "Running nmap \(arguments) \(target)...\n"

        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process()
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            let localBinary = Bundle.main.resourceURL?.appendingPathComponent("nmap").path
            let fallbackBinary = "/usr/local/bin/nmap"
            process.executableURL = URL(fileURLWithPath: FileManager.default.fileExists(atPath: localBinary ?? "") ? localBinary! : fallbackBinary)
            process.arguments = shellSplit(arguments) + [target]

            var env = ProcessInfo.processInfo.environment

            if let resources = Bundle.main.resourceURL?.path {

                env["NMAPDIR"] = resources

            }

            process.environment = env
            
            do {
                try process.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let text = String(data: data, encoding: .utf8) ?? ""
                DispatchQueue.main.async {
                    output += text
                    output += "\nExit status: \(process.terminationStatus)"
                    isRunning = false
                }
            } catch {
                DispatchQueue.main.async {
                    output += "Failed to run nmap: \(error.localizedDescription)\n"
                    output += "Expected bundled Resources/nmap or /usr/local/bin/nmap."
                    isRunning = false
                }
            }
        }
    }
}

private func shellSplit(_ string: String) -> [String] {
    // Minimal whitespace splitter for the first scaffold. Replace with a real parser
    // before accepting arbitrary quoted command lines in production.
    string.split(separator: " ").map(String.init)
}
