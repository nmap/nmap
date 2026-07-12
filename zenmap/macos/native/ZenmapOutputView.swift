import Foundation
import SwiftUI

extension ContentView {
    var outputView: some View {
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
}
