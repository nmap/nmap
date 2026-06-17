import AppKit
import Foundation
import SwiftUI

extension ContentView {
    struct FindableOutputTextView: NSViewRepresentable {
        @Binding var text: String
        var findText: String
        var selectedMatchIndex: Int
        var autoScrollEnabled: Bool

        func makeCoordinator() -> Coordinator {
            Coordinator(self)
        }

        func makeNSView(context: Context) -> NSScrollView {
            let scrollView = NSScrollView()
            scrollView.hasVerticalScroller = true
            scrollView.hasHorizontalScroller = true
            scrollView.autohidesScrollers = false
            scrollView.borderType = .noBorder

            let textView = NSTextView()
            textView.isEditable = true
            textView.isSelectable = true
            textView.isRichText = false
            textView.usesFontPanel = false
            textView.allowsUndo = true
            textView.drawsBackground = true
            textView.backgroundColor = NSColor.textBackgroundColor
            textView.textColor = NSColor.textColor
            textView.insertionPointColor = NSColor.textColor
            textView.font = NSFont.monospacedSystemFont(
                ofSize: NSFont.systemFontSize,
                weight: .regular
            )
            textView.minSize = NSSize(width: 0, height: 0)
            textView.maxSize = NSSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            )
            textView.isHorizontallyResizable = true
            textView.isVerticallyResizable = true
            textView.autoresizingMask = [.width]
            textView.textContainer?.containerSize = NSSize(
                width: CGFloat.greatestFiniteMagnitude,
                height: CGFloat.greatestFiniteMagnitude
            )
            textView.textContainer?.widthTracksTextView = false
            textView.delegate = context.coordinator

            scrollView.documentView = textView
            context.coordinator.textView = textView
            return scrollView
        }

        func updateNSView(_ scrollView: NSScrollView, context: Context) {
            guard let textView = scrollView.documentView as? NSTextView else {
                return
            }

            context.coordinator.parent = self

            if textView.string != text {
                textView.string = text

                if autoScrollEnabled {
                    scrollOutputToBottom(scrollView, textView: textView)

                    DispatchQueue.main.async {
                        scrollOutputToBottom(scrollView, textView: textView)
                    }
                }
            }

            context.coordinator.applyFindHighlight()
        }

        func scrollOutputToBottom(_ scrollView: NSScrollView, textView: NSTextView) {
            guard let textContainer = textView.textContainer else {
                return
            }

            textView.layoutManager?.ensureLayout(for: textContainer)

            let endRange = NSRange(location: max(textView.string.count - 1, 0), length: 1)
            textView.scrollRangeToVisible(endRange)

            let documentHeight = textView.bounds.height
            let visibleHeight = scrollView.contentView.bounds.height
            let y = max(0, documentHeight - visibleHeight)
            scrollView.contentView.scroll(to: NSPoint(x: 0, y: y))
            scrollView.reflectScrolledClipView(scrollView.contentView)
        }

        final class Coordinator: NSObject, NSTextViewDelegate {
            var parent: FindableOutputTextView
            weak var textView: NSTextView?

            init(_ parent: FindableOutputTextView) {
                self.parent = parent
            }

            func textDidChange(_ notification: Notification) {
                guard let textView else {
                    return
                }

                parent.text = textView.string
            }

            func applyFindHighlight() {
                guard let textView else {
                    return
                }

                let text = textView.string as NSString
                let fullRange = NSRange(location: 0, length: text.length)
                textView.textStorage?.removeAttribute(.backgroundColor, range: fullRange)
                textView.textStorage?.addAttribute(.foregroundColor, value: NSColor.textColor, range: fullRange)

                if let font = textView.font {
                    textView.textStorage?.addAttribute(.font, value: font, range: fullRange)
                }
                
                let query = parent.findText.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !query.isEmpty else {
                    return
                }

                var searchRange = NSRange(location: 0, length: text.length)
                var matches: [NSRange] = []

                while searchRange.location < text.length {
                    let foundRange = text.range(
                        of: query,
                        options: [.caseInsensitive],
                        range: searchRange
                    )

                    if foundRange.location == NSNotFound {
                        break
                    }

                    matches.append(foundRange)

                    let nextLocation = foundRange.location + max(foundRange.length, 1)
                    searchRange = NSRange(
                        location: nextLocation,
                        length: text.length - nextLocation
                    )
                }

                guard !matches.isEmpty else {
                    return
                }

                let normalMatchBackground = NSColor.systemYellow.withAlphaComponent(0.90)
                let normalMatchForeground = NSColor.black
                let selectedMatchBackground = NSColor.systemOrange.withAlphaComponent(0.95)
                let selectedMatchForeground = NSColor.black

                for match in matches {
                    textView.textStorage?.addAttribute(
                        .backgroundColor,
                        value: normalMatchBackground,
                        range: match
                    )
                    textView.textStorage?.addAttribute(
                        .foregroundColor,
                        value: normalMatchForeground,
                        range: match
                    )
                }

                let selectedIndex = min(max(parent.selectedMatchIndex, 0), matches.count - 1)
                let selectedRange = matches[selectedIndex]

                textView.textStorage?.addAttribute(
                    .backgroundColor,
                    value: selectedMatchBackground,
                    range: selectedRange
                )
                textView.textStorage?.addAttribute(
                    .foregroundColor,
                    value: selectedMatchForeground,
                    range: selectedRange
                )
                textView.scrollRangeToVisible(selectedRange)
            }
        }
    }

    var outputFindMatchCount: Int {
        let query = outputFindText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else {
            return 0
        }

        return output.lowercased().components(separatedBy: query.lowercased()).count - 1
    }

    var outputFindSummary: String {
        let count = outputFindMatchCount
        guard count > 0 else {
            return outputFindText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "" : "No matches"
        }

        let displayIndex = min(outputFindSelection + 1, count)
        return "\(displayIndex) of \(count)"
    }

    func forceOutputScrollToBottom(_ scrollView: NSScrollView, textView: NSTextView) {
        textView.layoutManager?.ensureLayout(for: textView.textContainer!)

        let endRange = NSRange(location: max(textView.string.count - 1, 0), length: 1)
        textView.scrollRangeToVisible(endRange)

        let documentHeight = textView.bounds.height
        let visibleHeight = scrollView.contentView.bounds.height
        let y = max(0, documentHeight - visibleHeight)
        scrollView.contentView.scroll(to: NSPoint(x: 0, y: y))
        scrollView.reflectScrolledClipView(scrollView.contentView)
    }

    func moveToNextOutputMatch() {
        let count = outputFindMatchCount
        guard count > 0 else {
            return
        }

        outputFindSelection = (outputFindSelection + 1) % count
    }

    func moveToPreviousOutputMatch() {
        let count = outputFindMatchCount
        guard count > 0 else {
            return
        }

        outputFindSelection = (outputFindSelection - 1 + count) % count
    }
}
