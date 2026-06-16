//
//  ShellEscaping.swift
//  NmapMac
//
//  Created by st0rmshadow on 6/15/26.
//

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
