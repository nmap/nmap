import Foundation

extension ContentView {
    struct NSEScriptEntry: Identifiable, Hashable {
        let name: String
        let categories: [String]

        var id: String { name }
    }

    struct NSEScriptDetails {
        let name: String
        let categories: [String]
        let path: String
        let description: String
    }

    var nseScriptCategories: [String] {
        let parsedCategories = Set(nseScriptEntries.flatMap { $0.categories })
        let fallbackCategories = Set(["default", "safe", "vuln", "auth", "discovery", "version", "all"])
        return Array(parsedCategories.union(fallbackCategories)).sorted()
    }

    var filteredNSEScriptEntries: [NSEScriptEntry] {
        let entries = nseScriptEntries.filter { $0.categories.contains(selectedNSEScriptCategory) }
        return entries.isEmpty ? nseScriptEntries : entries
    }

    var selectedNSEScriptDetails: NSEScriptDetails? {
        guard !selectedNSEScriptName.isEmpty else {
            return nil
        }

        return loadNSEScriptDetails(named: selectedNSEScriptName)
    }

    func parseBundledNSEScriptDatabase() -> [NSEScriptEntry] {
        let candidateURLs = [
            Bundle.main.resourceURL?.appendingPathComponent("share/nmap/scripts/script.db"),
            Bundle.main.resourceURL?.appendingPathComponent("scripts/script.db"),
            Bundle.main.resourceURL?.appendingPathComponent("script.db")
        ].compactMap { $0 }

        guard let scriptDatabaseURL = candidateURLs.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
              let databaseText = try? String(contentsOf: scriptDatabaseURL, encoding: .utf8) else {
            return []
        }

        let entryPattern = #"Entry\s*\{\s*filename\s*=\s*"([^"]+)"\s*,\s*categories\s*=\s*\{([^}]*)\}"#
        guard let entryRegex = try? NSRegularExpression(pattern: entryPattern) else {
            return []
        }

        let nsDatabaseText = databaseText as NSString
        let matches = entryRegex.matches(
            in: databaseText,
            range: NSRange(location: 0, length: nsDatabaseText.length)
        )

        return matches.compactMap { match in
            guard match.numberOfRanges >= 3 else {
                return nil
            }

            let filename = nsDatabaseText.substring(with: match.range(at: 1))
            let categoriesText = nsDatabaseText.substring(with: match.range(at: 2))
            let name = filename.replacingOccurrences(of: ".nse", with: "")
            let categories = categoriesText
                .components(separatedBy: ",")
                .map {
                    $0
                        .replacingOccurrences(of: "\"", with: "")
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                }
                .filter { !$0.isEmpty }

            return NSEScriptEntry(name: name, categories: categories)
        }
        .sorted { $0.name < $1.name }
    }

    func loadNSEScriptDetails(named scriptName: String) -> NSEScriptDetails? {
        let candidateURLs = nseScriptFileCandidateURLs(named: scriptName)
        let categories = nseScriptEntries.first(where: { $0.name == scriptName })?.categories ?? []

        guard let scriptURL = candidateURLs.first(where: { FileManager.default.fileExists(atPath: $0.path) }) else {
            return NSEScriptDetails(
                name: scriptName,
                categories: categories,
                path: "Bundled NSE script file not found.",
                description: ""
            )
        }

        let scriptText = (try? String(contentsOf: scriptURL, encoding: .utf8)) ?? ""

        return NSEScriptDetails(
            name: scriptName,
            categories: categories,
            path: scriptURL.path,
            description: nseScriptDescription(from: scriptText)
        )
    }

    func nseScriptFileCandidateURLs(named scriptName: String) -> [URL] {
        let filename = scriptName.hasSuffix(".nse") ? scriptName : "\(scriptName).nse"
        var urls: [URL] = []

        if let resourceURL = Bundle.main.resourceURL {
            urls.append(resourceURL.appendingPathComponent("share/nmap/scripts/\(filename)"))
            urls.append(resourceURL.appendingPathComponent("scripts/\(filename)"))
            urls.append(resourceURL.appendingPathComponent(filename))
        }

        if let nmapPath = nmapBinaryPath() {
            urls.append(URL(fileURLWithPath: nmapDataDirectory(for: nmapPath)).appendingPathComponent("scripts/\(filename)"))
        }

        urls.append(URL(fileURLWithPath: "/Applications/nmap.app/Contents/Resources/share/nmap/scripts/\(filename)"))
        urls.append(URL(fileURLWithPath: "/usr/local/share/nmap/scripts/\(filename)"))
        urls.append(URL(fileURLWithPath: "/opt/homebrew/share/nmap/scripts/\(filename)"))

        return urls
    }

    func nseScriptDescription(from scriptText: String) -> String {
        if let bracketDescription = firstMatch(
            in: scriptText,
            pattern: #"description\s*=\s*\[\[(.*?)\]\]"#,
            options: [.dotMatchesLineSeparators]
        ) {
            return cleanNSEScriptDescription(bracketDescription)
        }

        if let quotedDescription = firstMatch(
            in: scriptText,
            pattern: #"description\s*=\s*"([^"]*)""#
        ) {
            return cleanNSEScriptDescription(quotedDescription)
        }

        return ""
    }

    func firstMatch(in text: String, pattern: String, options: NSRegularExpression.Options = []) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: options) else {
            return nil
        }

        let nsText = text as NSString
        guard let match = regex.firstMatch(in: text, range: NSRange(location: 0, length: nsText.length)),
              match.numberOfRanges > 1 else {
            return nil
        }

        return nsText.substring(with: match.range(at: 1))
    }

    func cleanNSEScriptDescription(_ description: String) -> String {
        description
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }
}
