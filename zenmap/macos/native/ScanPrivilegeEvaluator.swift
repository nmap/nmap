/*
 * Determines whether a requested nmap scan can run as the GUI user or needs
 * administrator privileges.
 */
import Foundation

enum ScanPrivilegeRequirement: Equatable {
    case normalUser
    case administrator(reason: String)
}

struct ScanPrivilegeEvaluator {
    static func requirement(for arguments: [String]) -> ScanPrivilegeRequirement {
        // These options require privileges on macOS because they use raw sockets,
        // packet capture, traceroute behavior, or scan types unavailable to an
        // unprivileged process.
        let rootRequiredFlags: Set<String> = [
            "-sS",          // SYN scan
            "-sU",          // UDP scan
            "-O",           // OS detection
            "-A",           // Aggressive scan includes OS detection/traceroute behavior
            "--traceroute",

            "-sA",          // ACK scan
            "-sW",          // Window scan
            "-sM",          // Maimon scan
            "-sN",          // Null scan
            "-sF",          // FIN scan
            "-sX",          // Xmas scan
            "-sY",          // SCTP INIT scan
            "-sZ"           // SCTP COOKIE-ECHO scan
        ]

        for arg in arguments {
            if rootRequiredFlags.contains(arg) {
                return .administrator(reason: "\(arg) requires administrator privileges.")
            }
        }

        return .normalUser
    }
}
