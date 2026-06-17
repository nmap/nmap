import Foundation
import SwiftUI

extension ContentView {
    var profileValidationWarningsView: some View {
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

    var profileAdvancedOptionsRow: some View {
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

    var profileNSEScriptRow: some View {
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

    func nseScriptDetailsView(_ details: NSEScriptDetails) -> some View {
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

    var profileNSEScriptArgsRow: some View {
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
}
