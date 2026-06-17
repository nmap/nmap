import Foundation

extension ContentView {
    func profileValidationWarnings() -> [String] {
        let argumentsArray = profileArgumentsArray()
        let argumentsSet = Set(argumentsArray)
        let joinedArguments = argumentsArray.joined(separator: " ").lowercased()
        var warnings: [String] = []

        if newProfileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            warnings.append("Profile name is empty.")
        }

        if joinedArguments.contains("--script default or safe") {
            warnings.append("Use --script default,safe instead of '--script default or safe'.")
        }

        if profileHasScriptArgs(argumentsArray), !profileEnablesScripts(argumentsArray) {
            warnings.append("--script-args is set, but no --script, -sC, or -A option enables NSE scripts.")
        }

        if profileScriptExpressions().contains("all") {
            warnings.append("--script all can be very slow and noisy. Use it only when intentional.")
        }

        if argumentsSet.contains("-sU") {
            warnings.append("UDP scans can be slow and may require administrator privileges.")
        }

        if argumentsSet.contains("-sS") {
            warnings.append("SYN scans usually require administrator privileges on macOS.")
        }

        if argumentsSet.contains("-A") {
            warnings.append("-A enables OS detection, version detection, scripts, and traceroute.")
        }

        return warnings
    }

    func profileHasScriptArgs(_ argumentsArray: [String]) -> Bool {
        argumentsArray.contains("--script-args") ||
        argumentsArray.contains { $0.hasPrefix("--script-args=") }
    }

    func profileEnablesScripts(_ argumentsArray: [String]) -> Bool {
        argumentsArray.contains("-sC") ||
        argumentsArray.contains("-A") ||
        argumentsArray.contains("--script") ||
        argumentsArray.contains { $0.hasPrefix("--script=") }
    }

    func profileArgumentsArray() -> [String] {
        shellSplit(newProfileArguments)
    }

    func profileHasArgument(_ argument: String) -> Bool {
        profileArgumentsArray().contains(argument)
    }

    func appendProfileArgumentIfMissing(_ argument: String) {
        var argumentsArray = profileArgumentsArray()

        guard !argumentsArray.contains(argument) else {
            return
        }

        argumentsArray.append(argument)
        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    func removeProfileArgument(_ argument: String) {
        let argumentsArray = profileArgumentsArray().filter { $0 != argument }
        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    func profileTimingValue() -> String {
        profileArgumentsArray().first {
            $0.range(of: #"^-T[0-5]$"#, options: .regularExpression) != nil
        } ?? ""
    }

    func setProfileTimingValue(_ value: String) {
        var argumentsArray = profileArgumentsArray().filter {
            $0.range(of: #"^-T[0-5]$"#, options: .regularExpression) == nil
        }

        if !value.isEmpty {
            argumentsArray.append(value)
        }

        newProfileArguments = argumentsArray.joined(separator: " ")
    }

    func appendProfileScriptExpression(_ expression: String) {
        let trimmedExpression = expression.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedExpression.isEmpty else {
            return
        }

        var scriptExpressions = profileScriptExpressions()
        let expressionsToAdd = splitProfileScriptExpression(trimmedExpression)
        let existingExpressions = Set(scriptExpressions)
        let newExpressions = expressionsToAdd.filter { !existingExpressions.contains($0) }

        guard !newExpressions.isEmpty else {
            nseScriptHelperMessage = "Already added --script \(trimmedExpression) to Arguments."
            return
        }

        scriptExpressions.append(contentsOf: newExpressions)
        setProfileScriptExpressions(scriptExpressions)
        nseScriptHelperMessage = "Added --script \(newExpressions.joined(separator: ",")) to Arguments. Use Add/Update to save the profile."
    }

    func profileScriptExpressions() -> [String] {
        var expressions: [String] = []
        let argumentsArray = profileArgumentsArray()
        var index = 0

        while index < argumentsArray.count {
            let argument = argumentsArray[index]

            if argument == "--script", index + 1 < argumentsArray.count {
                expressions.append(contentsOf: splitProfileScriptExpression(argumentsArray[index + 1]))
                index += 2
                continue
            }

            if argument.hasPrefix("--script=") {
                let value = String(argument.dropFirst("--script=".count))
                expressions.append(contentsOf: splitProfileScriptExpression(value))
            }

            index += 1
        }

        var seen = Set<String>()
        return expressions.filter { expression in
            guard !seen.contains(expression) else {
                return false
            }

            seen.insert(expression)
            return true
        }
    }

    func splitProfileScriptExpression(_ expression: String) -> [String] {
        expression
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    func removeProfileScriptExpression(_ expression: String) {
        let updatedExpressions = profileScriptExpressions().filter { $0 != expression }
        setProfileScriptExpressions(updatedExpressions)
        nseScriptHelperMessage = "Removed --script \(expression) from Arguments."
    }

    func setProfileScriptExpressions(_ expressions: [String]) {
        let argumentsArray = profileArgumentsArray()
        var updatedArguments: [String] = []
        var index = 0

        while index < argumentsArray.count {
            let argument = argumentsArray[index]

            if argument == "--script" {
                index += 2
                continue
            }

            if argument.hasPrefix("--script=") {
                index += 1
                continue
            }

            updatedArguments.append(argument)
            index += 1
        }

        if !expressions.isEmpty {
            updatedArguments.append("--script")
            updatedArguments.append(expressions.joined(separator: ","))
        }

        newProfileArguments = updatedArguments.joined(separator: " ")
    }

    func normalizedProfileScriptArgs(_ value: String) -> String {
        value
            .split { character in
                character == "," || character.isWhitespace
            }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .joined(separator: ",")
    }

    func isLikelyOrphanScriptArg(_ argument: String) -> Bool {
        !argument.hasPrefix("-") && argument.contains("=")
    }

    func profileScriptArgsValue() -> String {
        profileScriptArgsValue(from: profileArgumentsArray())
    }

    func profileScriptArgsValue(from argumentsArray: [String]) -> String {
        var index = 0

        while index < argumentsArray.count {
            let argument = argumentsArray[index]

            if argument == "--script-args", index + 1 < argumentsArray.count {
                var values = [argumentsArray[index + 1]]
                var valueIndex = index + 2

                while valueIndex < argumentsArray.count,
                      isLikelyOrphanScriptArg(argumentsArray[valueIndex]) {
                    values.append(argumentsArray[valueIndex])
                    valueIndex += 1
                }

                return normalizedProfileScriptArgs(values.joined(separator: ","))
            }

            if argument.hasPrefix("--script-args=") {
                return normalizedProfileScriptArgs(String(argument.dropFirst("--script-args=".count)))
            }

            index += 1
        }

        return ""
    }

    func setProfileScriptArgs(_ value: String) {
        let trimmedValue = normalizedProfileScriptArgs(value)
        guard !trimmedValue.isEmpty else {
            clearProfileScriptArgs()
            return
        }

        let argumentsArray = profileArgumentsArray()
        var updatedArguments: [String] = []
        var index = 0

        while index < argumentsArray.count {
            let argument = argumentsArray[index]

            if argument == "--script-args" {
                index += 2

                while index < argumentsArray.count,
                      isLikelyOrphanScriptArg(argumentsArray[index]) {
                    index += 1
                }

                continue
            }

            if argument.hasPrefix("--script-args=") {
                index += 1
                continue
            }

            updatedArguments.append(argument)
            index += 1
        }

        updatedArguments.append("--script-args")
        updatedArguments.append(trimmedValue)
        newProfileArguments = updatedArguments.joined(separator: " ")
        nseScriptArgsText = trimmedValue
        nseScriptHelperMessage = "Applied --script-args \(trimmedValue) to Arguments. Use Add/Update to save the profile."
    }

    func clearProfileScriptArgs() {
        let argumentsArray = profileArgumentsArray()
        var updatedArguments: [String] = []
        var index = 0

        while index < argumentsArray.count {
            let argument = argumentsArray[index]

            if argument == "--script-args" {
                index += 2

                while index < argumentsArray.count,
                      isLikelyOrphanScriptArg(argumentsArray[index]) {
                    index += 1
                }

                continue
            }

            if argument.hasPrefix("--script-args=") {
                index += 1
                continue
            }

            updatedArguments.append(argument)
            index += 1
        }

        newProfileArguments = updatedArguments.joined(separator: " ")
        nseScriptArgsText = ""
        nseScriptHelperMessage = "Cleared --script-args from Arguments."
    }
}
