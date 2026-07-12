/*
 * Escaping helpers for commands that must pass through both AppleScript and
 * the shell before they reach nmap.
 */
import Foundation

extension String {
    var shellEscaped: String {
        "'" + self.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    var appleScriptEscaped: String {
        self
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
