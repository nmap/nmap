//
//  PrivilegedNmapRunner.swift
//  NmapMac
//
//  Created by st0rmshadow on 6/15/26.
//
import Foundation
import Darwin

struct PrivilegedNmapRunner {
    enum PrivilegedRunnerError: Error, LocalizedError {
        case nmapNotFound
        case executionFailed(String)
        case invalidPID(String)

        var errorDescription: String? {
            switch self {
            case .nmapNotFound:
                return "The bundled nmap executable could not be found."
            case .executionFailed(let message):
                return message
            case .invalidPID(let value):
                return "Privileged nmap returned an invalid process id: \(value)"
            }
        }
    }

    static func bundledNmapPath() throws -> String {
        let candidates = [
            Bundle.main.resourceURL?.appendingPathComponent("bin/nmap").path,
            Bundle.main.resourceURL?.appendingPathComponent("nmap").path,
            Bundle.main.path(forResource: "nmap", ofType: nil),
            Bundle.main.path(forResource: "nmap", ofType: nil, inDirectory: "bin"),
            Bundle.main.path(forResource: "nmap", ofType: nil, inDirectory: "nmap/bin"),
            "/Applications/nmap.app/Contents/Resources/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/homebrew/bin/nmap"
        ].compactMap { $0 }

        for path in candidates {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }

        throw PrivilegedRunnerError.nmapNotFound
    }

    static func nmapDataDirectory(for nmapPath: String) -> String {
        let nmapURL = URL(fileURLWithPath: nmapPath)
        var candidates: [String] = []

        candidates.append(
            nmapURL
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("share/nmap")
                .path
        )

        if let resourcePath = Bundle.main.resourceURL?.appendingPathComponent("share/nmap").path {
            candidates.append(resourcePath)
        }

        if let resourcePath = Bundle.main.resourceURL?.path {
            candidates.append(resourcePath)
        }

        candidates.append("/Applications/nmap.app/Contents/Resources/share/nmap")
        candidates.append("/usr/local/share/nmap")
        candidates.append("/opt/homebrew/share/nmap")

        for path in candidates {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
               isDirectory.boolValue {
                return path
            }
        }

        return Bundle.main.resourceURL?.path ?? ""
    }

    static func start(arguments: [String], logPath: String, statusPath: String, donePath: String, childPIDPath: String) async throws -> Int32 {
        let nmapPath = try bundledNmapPath()

        let commandParts = ([nmapPath] + arguments).map { $0.shellEscaped }
        let command = commandParts.joined(separator: " ")
        let escapedLogPath = logPath.shellEscaped
        let escapedStatusPath = statusPath.shellEscaped
        let escapedDonePath = donePath.shellEscaped
        let escapedChildPIDPath = childPIDPath.shellEscaped
        let resourcesPath = nmapDataDirectory(for: nmapPath)
        let escapedResourcesPath = resourcesPath.shellEscaped

        /*
         Start a small root wrapper instead of nmap directly.

         Why:
         - AppleScript returns immediately with the wrapper PID.
         - The wrapper writes the real nmap exit code to statusPath.
         - The wrapper touches donePath when nmap is truly finished.
         - Stop can kill the wrapper, whose trap kills the nmap child.
         */
        let wrapper = """
        rm -f \(escapedStatusPath) \(escapedDonePath) \(escapedChildPIDPath); \
        NMAPDIR=\(escapedResourcesPath); export NMAPDIR; \
        trap 'kill "$child" 2>/dev/null; sleep 1; kill -9 "$child" 2>/dev/null; echo 130 > \(escapedStatusPath); touch \(escapedDonePath); exit 130' TERM INT; \
        \(command) > \(escapedLogPath) 2>&1 & \
        child=$!; \
        echo "$child" > \(escapedChildPIDPath); \
        wait "$child"; \
        code=$?; \
        echo "$code" > \(escapedStatusPath); \
        touch \(escapedDonePath); \
        exit "$code"
        """

        let shellCommand = "sh -c \(wrapper.shellEscaped) > /dev/null 2>&1 & echo $!"
        let appleScript = """
        do shell script "\(shellCommand.appleScriptEscaped)" with administrator privileges
        """

        let output = try await runAppleScript(appleScript)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let pid = Int32(output) else {
            throw PrivilegedRunnerError.invalidPID(output)
        }

        return pid
    }

    static func stop(pid: Int32, childPIDPath: String? = nil) async throws {
        var commands = [String]()

        if let childPIDPath,
           let childPIDText = try? String(contentsOfFile: childPIDPath, encoding: .utf8),
           let childPID = Int32(childPIDText.trimmingCharacters(in: .whitespacesAndNewlines)) {
            commands.append("kill \(childPID) 2>/dev/null || true")
            commands.append("sleep 1")
            commands.append("kill -9 \(childPID) 2>/dev/null || true")
        }

        commands.append("kill \(pid) 2>/dev/null || true")
        commands.append("sleep 1")
        commands.append("kill -9 \(pid) 2>/dev/null || true")

        let shellCommand = commands.joined(separator: "; ")
        let appleScript = """
        do shell script "\(shellCommand.appleScriptEscaped)" with administrator privileges
        """
        _ = try await runAppleScript(appleScript)
    }

    static func isRunning(pid: Int32) -> Bool {
        errno = 0
        let result = kill(pid, 0)

        if result == 0 {
            return true
        }

        /*
         If the process is owned by root, a normal GUI process may get EPERM.
         EPERM still means the PID exists, so the privileged scan is still running.
         ESRCH means the PID does not exist.
         */
        return errno == EPERM
    }

    private static func runAppleScript(_ source: String) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", source]

            let stdout = Pipe()
            let stderr = Pipe()

            process.standardOutput = stdout
            process.standardError = stderr

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
                return
            }

            process.terminationHandler = { process in
                let outData = stdout.fileHandleForReading.readDataToEndOfFile()
                let errData = stderr.fileHandleForReading.readDataToEndOfFile()

                let output = String(data: outData, encoding: .utf8) ?? ""
                let errorOutput = String(data: errData, encoding: .utf8) ?? ""

                if process.terminationStatus == 0 {
                    continuation.resume(returning: output)
                } else {
                    let message = errorOutput.isEmpty ? output : errorOutput
                    continuation.resume(
                        throwing: PrivilegedRunnerError.executionFailed(message)
                    )
                }
            }
        }
    }
}
