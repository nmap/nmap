import Foundation

extension ContentView {
    func useProfile(_ profile: ScanProfile) {
        selectedProfile = profile
        arguments = profile.arguments
        selectedProfileID = profile.id
        selectedTab = "Output"
    }
    
    func addCustomProfile() {
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
    
    func updateSelectedCustomProfile() {
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
    
    func duplicateProfile(_ profile: ScanProfile) {
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
    
    func deleteProfile(_ profile: ScanProfile) {
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
    
    func loadSelectedProfileForEditingIfNeeded() {
        guard let profile = selectedProfileForActions else {
            return
        }

        loadProfileIntoEditor(profile)
    }
    
    func loadProfileIntoEditor(_ profile: ScanProfile) {
        newProfileName = profile.name
        newProfileArguments = profile.arguments
        newProfileDescription = profile.description
        nseScriptHelperMessage = ""
        nseScriptArgsText = profileScriptArgsValue(from: shellSplit(profile.arguments))
    }
    
    func clearProfileEditor() {
        selectedProfileID = nil
        newProfileName = ""
        newProfileArguments = "-sV"
        newProfileDescription = "Custom scan profile."
        nseScriptHelperMessage = ""
        nseScriptArgsText = ""
    }
    
    
    func mergeImportedCustomProfiles(_ importedProfiles: [ScanProfile]) {
        let builtIns = profiles.filter { $0.isBuiltIn }
        var mergedCustomProfiles = customProfiles

        for importedProfile in importedProfiles {
            mergedCustomProfiles.removeAll { $0.name == importedProfile.name }
            mergedCustomProfiles.append(importedProfile)
        }

        mergedCustomProfiles.sort {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }

        profiles = builtIns + mergedCustomProfiles
        saveCustomProfiles()
    }
}
