import Foundation
import Combine

final class ScanHistoryStore: ObservableObject {
    private static let savedScansDefaultsKey = "Zenmap.SavedScans"

    @Published var savedScans: [SavedScan] = [] {
        didSet {
            saveSavedScans()
        }
    }
    @Published var selectedSavedScanID: SavedScan.ID?
    @Published var selectedSavedScanIDs: Set<SavedScan.ID> = []

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
        selectedSavedScanIDs.removeAll()
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
