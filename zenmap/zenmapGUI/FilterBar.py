import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GObject

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higlabels import HintWindow


class FilterBar(HIGHBox):
    """This is the bar that appears while the host filter is active. It allows
    entering a string that restricts the set of visible hosts."""

    __gsignals__ = {
        "changed": (GObject.SignalFlags.RUN_FIRST, GObject.TYPE_NONE, ())
    }

    def __init__(self):
        HIGHBox.__init__(self)
        self.information_label = Gtk.Label()
        self.entry = Gtk.Entry()

        self.pack_start(self.information_label, False, True, 0)
        self.information_label.show()

        label = Gtk.Label.new(_("Host Filter:"))
        self.pack_start(label, False, True, 0)
        label.show()

        self.pack_start(self.entry, True, True, 0)
        self.entry.show()

        help_button = Gtk.Button()
        icon = Gtk.Image()
        icon.set_from_stock(Gtk.STOCK_INFO, Gtk.IconSize.BUTTON)
        help_button.add(icon)
        help_button.connect("clicked", self._help_button_clicked)
        self.pack_start(help_button, False, True, 0)
        help_button.show_all()

        self.entry.connect("changed", lambda x: self.emit("changed"))

    def grab_focus(self):
        self.entry.grab_focus()

    def get_filter_string(self):
        return self.entry.get_text()

    def set_filter_string(self, filter_string):
        return self.entry.set_text(filter_string)

    def set_information_text(self, text):
        self.information_label.set_text(text)

    def _help_button_clicked(self, button):
        hint_window = HintWindow(HELP_TEXT)
        hint_window.show_all()

HELP_TEXT = _("""\
Entering the text into the search performs a <b>keyword search</b> - the \
search string is matched against every aspect of the host.

To refine the search, you can use <b>operators</b> to search only \
specific fields within a host. Most operators have a short form, listed. \

<b>target: (t:)</b> - User-supplied target, or a rDNS result.
<b>os:</b> - All OS-related fields.
<b>open: (op:)</b> - Open ports discovered in a scan.
<b>closed: (cp:)</b> - Closed ports discovered in a scan.
<b>filtered: (fp:)</b> - Filtered ports discovered in scan.
<b>unfiltered: (ufp:)</b> - Unfiltered ports found in a scan (using, for \
example, an ACK scan).
<b>open|filtered: (ofp:)</b> - Ports in the \"open|filtered\" state.
<b>closed|filtered: (cfp:)</b> - Ports in the \"closed|filtered\" state.
<b>service: (s:)</b> - All service-related fields.
<b>inroute: (ir:)</b> - Matches a router in the scan's traceroute output.
""")
