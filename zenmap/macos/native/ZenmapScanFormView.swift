import Foundation
import SwiftUI

extension ContentView {
    var header: some View {
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
}
