import Foundation
import SwiftUI

extension ContentView {
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

    func installDiagnosticInfoObserverIfNeeded() {
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

    func loadNSEScriptDatabaseIfNeeded() {
        guard nseScriptEntries.isEmpty else {
            return
        }

        nseScriptEntries = parseBundledNSEScriptDatabase()
    }
}
