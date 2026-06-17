import AppKit
import Foundation
import UniformTypeIdentifiers

extension ContentView {
    var filteredProfiles: [ScanProfile] {
        let query = normalizedProfileFilterText

        guard !query.isEmpty else {
            return profiles
        }

        return profiles.filter { profileMatchesFilter($0, query: query) }
    }

    var normalizedProfileFilterText: String {
        profileFilterText
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    var isFilteringProfiles: Bool {
        !normalizedProfileFilterText.isEmpty
    }

    func profileMatchesFilter(_ profile: ScanProfile, query: String) -> Bool {
        let profileType = profile.isBuiltIn ? "built-in builtin default" : "custom user"

        return [
            profile.name,
            profile.arguments,
            profile.description,
            profileType
        ]
        .joined(separator: " ")
        .lowercased()
        .contains(query)
    }
    
    var customProfiles: [ScanProfile] {
        profiles.filter { !$0.isBuiltIn }
    }
    
    var selectedProfileForActions: ScanProfile? {
        guard let selectedProfileID else {
            return nil
        }

        return profiles.first { $0.id == selectedProfileID }
    }
    
    var selectedCustomProfileForEditing: ScanProfile? {
        guard let profile = selectedProfileForActions,
              !profile.isBuiltIn else {
            return nil
        }

        return profile
    }
    static func loadSavedCustomProfiles() -> [ScanProfile]? {
        guard let data = UserDefaults.standard.data(forKey: customProfilesDefaultsKey) else {
            return nil
        }

        return try? JSONDecoder.profileDecoder.decode([ScanProfile].self, from: data)
    }
    func exportCustomProfiles() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        panel.nameFieldStringValue = "nmap-custom-profiles.json"

        guard panel.runModal() == .OK,
              let url = panel.url else {
            return
        }

        do {
            let data = try JSONEncoder.profileEncoder.encode(customProfiles)
            try data.write(to: url, options: .atomic)
            nseScriptHelperMessage = "Exported \(customProfiles.count) custom profile(s)."
        } catch {
            nseScriptHelperMessage = "Failed to export custom profiles: \(error.localizedDescription)"
        }
    }
    func importCustomProfiles() {
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
            let importedProfiles = try JSONDecoder.profileDecoder.decode([ScanProfile].self, from: data)
                .map { profile in
                    ScanProfile(
                        id: profile.id,
                        name: profile.name,
                        arguments: profile.arguments,
                        description: profile.description,
                        isBuiltIn: false
                    )
                }
                .filter { !$0.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

            guard !importedProfiles.isEmpty else {
                nseScriptHelperMessage = "No custom profiles found in selected JSON file."
                return
            }

            mergeImportedCustomProfiles(importedProfiles)

            if let lastImportedProfile = importedProfiles.last,
               let importedProfile = profiles.first(where: { $0.name == lastImportedProfile.name && !$0.isBuiltIn }) {
                selectedProfileID = importedProfile.id
                loadProfileIntoEditor(importedProfile)
            }

            nseScriptHelperMessage = "Imported \(importedProfiles.count) custom profile(s) and loaded the latest import."
        } catch {
            nseScriptHelperMessage = "Failed to import custom profiles: \(error.localizedDescription)"
        }
    }
    func saveCustomProfiles() {
        let customProfiles = profiles.filter { !$0.isBuiltIn }

        guard let data = try? JSONEncoder.profileEncoder.encode(customProfiles) else {
            return
        }

        UserDefaults.standard.set(data, forKey: Self.customProfilesDefaultsKey)
    }
}
