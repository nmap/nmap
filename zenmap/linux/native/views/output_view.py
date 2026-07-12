"""Scrollable monospace output view for live nmap stdout."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk


class OutputView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self._text_view = Gtk.TextView()
        self._text_view.set_editable(False)
        self._text_view.set_monospace(True)
        self._text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self._text_buffer = self._text_view.get_buffer()
        scrolled.set_child(self._text_view)

        self.append(scrolled)

    def set_text(self, text: str) -> None:
        self._text_buffer.set_text(text)

    def append_text(self, text: str) -> None:
        end_iter = self._text_buffer.get_end_iter()
        self._text_buffer.insert(end_iter, text)
        mark = self._text_buffer.create_mark(None, end_iter, False)
        self._text_view.scroll_to_mark(mark, 0.0, False, 0.0, 1.0)

    def clear(self) -> None:
        self._text_buffer.set_text("")
