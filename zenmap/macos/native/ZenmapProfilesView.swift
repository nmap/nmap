import Foundation
import SwiftUI

extension ContentView {
    var profilesView: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Profiles")
                        .font(.title2.bold())
                    Text("Choose a profile to load its arguments into the scan form, or create a custom one.")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    exportCustomProfiles()
                } label: {
                    Label("Export Custom Profiles", systemImage: "square.and.arrow.up")
                }
                .disabled(customProfiles.isEmpty)

                Button {
                    importCustomProfiles()
                } label: {
                    Label("Import Custom Profiles", systemImage: "square.and.arrow.down")
                }

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
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("-sV -T4", text: $newProfileArguments)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))

                            profileValidationWarningsView
                        }
                    }

                    GridRow {
                        Text("Advanced")
                            .foregroundStyle(.secondary)
                        profileAdvancedOptionsRow
                    }

                    GridRow {
                        Text("Scripts")
                            .foregroundStyle(.secondary)
                        profileNSEScriptRow
                    }

                    GridRow {
                        Text("Script Args")
                            .foregroundStyle(.secondary)
                        profileNSEScriptArgsRow
                    }

                    GridRow {
                        Text("Description")
                            .foregroundStyle(.secondary)
                        TextField("Describe when to use this profile", text: $newProfileDescription)
                            .textFieldStyle(.roundedBorder)
                    }
                }

                HStack {
                    Button {
                        copyProfileArguments()
                    } label: {
                        Label("Copy Arguments", systemImage: "doc.on.doc")
                    }
                    .disabled(newProfileArguments.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

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
            
            HStack(spacing: 8) {
                Label("Search Profiles", systemImage: "magnifyingglass")
                    .foregroundStyle(.secondary)

                TextField("Name, arguments, description, built-in, custom", text: $profileFilterText)
                    .textFieldStyle(.roundedBorder)

                if isFilteringProfiles {
                    Button("Clear") {
                        profileFilterText = ""
                    }
                }
            }

            Table(filteredProfiles, selection: $selectedProfileID) {
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
            .onChange(of: selectedProfileID) { _, _ in
                loadSelectedProfileForEditingIfNeeded()
            }
            
            Text("Selecting a profile loads it into the editor. Built-in profiles are view-only here; duplicate one to edit and save your own version.")
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}
