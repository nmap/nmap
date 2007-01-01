
/***************************************************************************
 * nmapfe.c -- Handles widget placement for drawing the main NmapFE GUI    *
 * interface.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2006 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 with the clarifications and exceptions described  *
 * below.  This guarantees your right to use, modify, and redistribute     *
 * this software under certain conditions.  If you wish to embed Nmap      *
 * technology into proprietary software, we sell alternative licenses      *
 * (contact sales@insecure.com).  Dozens of software vendors already       *
 * license Nmap technology such as host discovery, port scanning, OS       *
 * detection, and version detection.                                       *
 *                                                                         *
 * Note that the GPL places important restrictions on "derived works", yet *
 * it does not provide a detailed definition of that term.  To avoid       *
 * misunderstandings, we consider an application to constitute a           *
 * "derivative work" for the purpose of this license if it does any of the *
 * following:                                                              *
 * o Integrates source code from Nmap                                      *
 * o Reads or includes Nmap copyrighted data files, such as                *
 *   nmap-os-fingerprints or nmap-service-probes.                          *
 * o Executes Nmap and parses the results (as opposed to typical shell or  *
 *   execution-menu apps, which simply display raw Nmap output and so are  *
 *   not derivative works.)                                                * 
 * o Integrates/includes/aggregates Nmap into a proprietary executable     *
 *   installer, such as those produced by InstallShield.                   *
 * o Links to a library or executes a program that does any of the above   *
 *                                                                         *
 * The term "Nmap" should be taken to also include any portions or derived *
 * works of Nmap.  This list is not exclusive, but is just meant to        *
 * clarify our interpretation of derived works with some common examples.  *
 * These restrictions only apply when you actually redistribute Nmap.  For *
 * example, nothing stops you from writing and selling a proprietary       *
 * front-end to Nmap.  Just distribute it by itself, and point people to   *
 * http://insecure.org/nmap/ to download Nmap.                             *
 *                                                                         *
 * We don't consider these to be added restrictions on top of the GPL, but *
 * just a clarification of how we interpret "derived works" as it applies  *
 * to our GPL-licensed Nmap product.  This is similar to the way Linus     *
 * Torvalds has announced his interpretation of how "derived works"        *
 * applies to Linux kernel modules.  Our interpretation refers only to     *
 * Nmap - we don't speak for any other GPL products.                       *
 *                                                                         *
 * If you have any questions about the GPL licensing restrictions on using *
 * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
 * we also offer alternative license to integrate Nmap into proprietary    *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates as well as helping to     *
 * fund the continued development of Nmap technology.  Please email        *
 * sales@insecure.com for further information.                             *
 *                                                                         *
 * As a special exception to the GPL terms, Insecure.Com LLC grants        *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included Copying.OpenSSL file, and distribute linked      *
 * combinations including the two. You must obey the GNU GPL in all        *
 * respects for all of the code used other than OpenSSL.  If you modify    *
 * this file, you may extend this exception to your version of the file,   *
 * but you are not obligated to do so.                                     *
 *                                                                         *
 * If you received these files with a written license agreement or         *
 * contract stating terms other than the terms above, then that            *
 * alternative license agreement takes precedence over these comments.     *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes (none     *
 * have been found so far).                                                *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to fyodor@insecure.org for possible incorporation into the main         *
 * distribution.  By sending these changes to Fyodor or one the            *
 * Insecure.Org development mailing lists, it is assumed that you are      *
 * offering Fyodor and Insecure.Com LLC the unlimited, non-exclusive right *
 * to reuse, modify, and relicense the code.  Nmap will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).  We also occasionally relicense the    *
 * code to third parties as discussed above.  If you wish to specify       *
 * special license conditions of your contributions, just say so when you  *
 * send them.                                                              *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
 * General Public License for more details at                              *
 * http://www.gnu.org/copyleft/gpl.html , or in the COPYING file included  *
 * with Nmap.                                                              *
 *                                                                         *
 ***************************************************************************/

/* $Id$ */


/* Original Author: Zach
 * Mail: key@aye.net
 * IRC: EFNet as zach` or key in #bastards or #neatoelito
 * AIM (Aol): GoldMatrix
 *
 * Change the source as you wish, but leave these comments..
 *
 * Long live Aol and pr: Phreak. <grins>
 */

#if MISSING_GTK
#error "Your system does not appear to have GTK (www.gtk.org) installed.  Thus the Nmap X Front End will not compile.  You should still be able to use Nmap the normal way (via text console).  GUIs are for wimps anyway :)"
#else



#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>

#include <nbase.h>

#include "nmapfe.h"
#include "nmapfe_sig.h"

/* Keep this global */
struct NmapFEoptions opt;

void openLog(char *);
void saveLog(char *);
static void LogOpen_callback    (void);
static void LogSave_callback    (void);
static void LogAppend_callback  (void);
static void Help_callback       (void);
static void Version_callback    (void);
static void About_callback      (void);
static void Quit_callback       (void);
static void Colourize_callback  (GtkAction *action, GtkRadioAction *current);

void scanType_cb                (GtkComboBox *widget, gpointer data);

static GtkWidget *main_win;

static GtkActionEntry menu_entries[] = {
    { "FileMenu",   NULL, "_File" }, /* File menu */
    { "LogOpen",    NULL, "_Open Log",  NULL, "Open log file", LogOpen_callback },
    { "LogSave",    NULL, "_Save Log",  NULL, "Save log file", LogSave_callback },
    { "Quit",       NULL, "_Quit",      NULL, "Quit the program", Quit_callback },
    { "ViewMenu",   NULL, "_View" }, /* View menu */
    { "HelpMenu",   NULL, "_Help" }, /* Help menu */
    { "Help",       NULL, "_Help",              NULL, NULL, Help_callback },
    { "Version",    NULL, "_Nmap version",      NULL, NULL, Version_callback },
    { "About",      NULL, "_About NMapFE...",   NULL, NULL, About_callback }
};
static GtkToggleActionEntry menu_entries_toggle[] = {
    { "LogAppend",  NULL,   "Append log",       NULL, NULL, LogAppend_callback }
};
static GtkRadioActionEntry menu_entries_radio[] = {
    { "View_RGB",   NULL,   "Coloured",         NULL, NULL, 1},
    { "View_BW",    NULL,   "Black & White",    NULL, NULL, 2}
};

static const char *menu_description =
    "<ui>"
    "   <menubar name='MainMenu'>"
    "       <menu action='FileMenu'>"
    "           <menuitem action='LogOpen' />"
    "           <menuitem action='LogSave' />"
    "           <separator/>"
    "           <menuitem action='Quit' />"
    "       </menu>"
    "       <menu action='ViewMenu'>"
    "           <menuitem action='View_RGB' />"
    "           <menuitem action='View_BW' />"
    "           <separator/>"
    "           <menuitem action='LogAppend' />"
    "       </menu>"
    "       <menu action='HelpMenu'>"
    "           <menuitem action='Help' />"
    "           <menuitem action='Version' />"
    "           <separator/>"
    "           <menuitem action='About' />"
    "       </menu>"
    "   </menubar>"
    "</ui>";

static Entry scanentries[] = {
    { "SYN Stealth Scan",       SYN_SCAN,       TRUE },
    { "Connect Scan",           CONNECT_SCAN,   FALSE },
    { "ACK Stealth Scan",       ACK_SCAN,       TRUE },
    { "FIN|ACK Stealth Scan",   MAIMON_SCAN,    TRUE },
    { "FIN Stealth Scan",       FIN_SCAN,       TRUE },
    { "NULL Stealth Scan",      NULL_SCAN,      TRUE },
    { "XMas Tree Stealth Scan", XMAS_SCAN,      TRUE },
    { "TCP Window Scan",        WIN_SCAN,       TRUE },
    { "UDP Port Scan",          UDP_SCAN,       TRUE },
    { "IP Protocol Scan",       PROT_SCAN,      TRUE },
    { "Ping Sweep",             PING_SCAN,      FALSE },
    { "Host List",              LIST_SCAN,      FALSE },
    { "FTP Bounce Attack",      BOUNCE_SCAN,    FALSE },
    { "Idle Scan",              IDLE_SCAN,      TRUE },
    { NULL,                     0,              FALSE }
};


static gchar *throttleEntries[] = {
    "Paranoid Throttling",
    "Sneaky Throttling",
    "Polite Throttling",
    "Normal Throttling",
    "Aggressive Throttling",
    "Insane Throttling",
    NULL
};

static gchar *resolveEntries[] = {
    "Always",
    "When Required",
    "Never",
    NULL
};

static gchar *protportEntries[] = {
    "Default",
    "All",
    "Most Important [fast]",
    "Range Given Below",
    NULL
};

static gchar *outputFormatEntries[] = {
    "Normal",
    "grep-able",
    "XML",
    "All",
#if GTK_CHECK_VERSION(2,6,0)
    "<separator>",
#endif
    "ScriptKiddie"
};

static void 
LogOpen_callback (void) {
    static char filename[FILENAME_MAX+1] = "";
    gtk_widget_show(create_fileSelection("Open Log", filename, openLog, NULL));
}
static void
LogSave_callback (void) {
    static char filename[FILENAME_MAX+1] = "";
    gtk_widget_show(create_fileSelection("Save Log", filename, saveLog, NULL));
}
static void
Quit_callback (void) {
    stop_scan();
    gtk_main_quit();
}
static void 
Colourize_callback (GtkAction *action, GtkRadioAction *current) {
    opt.viewValue = gtk_radio_action_get_current_value(current);
}
static void 
LogAppend_callback (void) {
    opt.appendLog = !opt.appendLog;
}
static void
Version_callback (void) {
    execute("nmap -V");
}
static void
Help_callback (void) {
    gtk_widget_show(create_helpDialog());
}
static void
About_callback (void) {
#if GTK_CHECK_VERSION(2,6,0)
    static const gchar *authors[] = 
    {
        "Nmap is written by Fyodor <fyodor(a)insecure.org>",
        "with the help of many-many others."
        "\n",
        "NmapFE originally written by Zach Smith <key(a)aye.net>",
        "GUI rework by:",
        "   Peter Marschall <peter(a)adpm.de>",
        "Ported to GTK2 by:",
        "   Mike Basinger <dbasinge(a)speakeasy.net>",
        "   Meethune Bhowmick <meethune(a)oss-institute.org>",
        NULL
    };
    gtk_show_about_dialog ( GTK_WINDOW(main_win),
            "authors",      authors,
            "comments",     "Frontend for Nmap security scanner",
            "name",         "Nmap & NmapFE",
            "version",      VERSION,
            "website",      "http://www.insecure.org/nmap",
            NULL);
#else
  GtkWidget *aboutDialog;
  GtkWidget *vbox;
  GtkWidget *notebook;
  GtkWidget *text;
  GtkWidget *label;

  aboutDialog = gtk_dialog_new_with_buttons("About NmapFE & Nmap",
					   NULL,
					   GTK_DIALOG_MODAL,
					   GTK_STOCK_OK,
					   GTK_RESPONSE_NONE,
					   NULL);
					   
  g_signal_connect_swapped (aboutDialog,
			   "response", 
			   G_CALLBACK (gtk_widget_destroy),
			   aboutDialog);

  gtk_widget_set_usize(aboutDialog, 200, 200);
  gtk_window_position(GTK_WINDOW(aboutDialog), GTK_WIN_POS_CENTER);

  vbox = GTK_DIALOG(aboutDialog)->vbox;

  notebook = gtk_notebook_new();
  gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);

  label = gtk_label_new("NmapFE");
  text = gtk_label_new("Author: Zach Smith\n"
		       "EMail: key@aye.net\n"
		       "http://a.linuxbox.com\n"
		       "Written in: C/GTK\n"
		       "\n"
		       "GUI rewritten by:\n"
		       "Author: Peter Marschall\n"
                       "EMail: peter@adpm.de");

  gtk_widget_show(label);
  gtk_widget_show(text);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), text, label);

  label = gtk_label_new("Nmap");
  text = gtk_label_new("Author: Fyodor\n"
		       "EMail: fyodor@insecure.org\n"
		       "http://www.insecure.org/nmap\n"
		       "Written in: C++");

  gtk_widget_show(label);
  gtk_widget_show(text);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), text, label);

  gtk_widget_show_all(aboutDialog);

#endif
    
}
#if GTK_CHECK_VERSION(2,6,0)
/* FIXME: This needs to be rewritten because it's an ugly hack :(
 * See below for comment...
 */
static gboolean
is_separator (GtkTreeModel *model,
              GtkTreeIter  *iter,
              gpointer      data)
{
    GtkTreePath *path;
    gboolean     result;

    path = gtk_tree_model_get_path (model, iter);
    /* FIXME: Here we should see whether the contents of the row
     * equals "<separator>. But it works for now... :)
     */
    result = gtk_tree_path_get_indices (path)[0] == SEPARATOR;
    gtk_tree_path_free (path);

    return result;
}
#endif
static GtkTreeModel *
create_dropdown_store(Entry *data, gboolean is_root)
{
    GtkTreeIter     iter;
    GtkTreeStore    *store;
    gint i;
    
    store = gtk_tree_store_new (1, G_TYPE_STRING);

    for (i = 0; data[i].scan; i++) {
        if (is_root || (data[i].rootonly == is_root)) {
            gtk_tree_store_append(store, &iter, NULL);
            gtk_tree_store_set(store, &iter, 0, data[i].scan, -1);
        }
    }
    return GTK_TREE_MODEL (store);
}
        
GtkWidget* create_main_win()
{
  GtkWidget *main_vbox;
  GtkWidget *menubar;
GtkWidget *hbox;
GtkWidget *vbox;
GtkWidget *label;
GtkWidget *button;
GtkWidget *notebook;
GtkWidget *nblabel;
GtkWidget *nbpage;
GtkWidget *frame;
GtkWidget *table;
GtkAdjustment *adjust;

  GtkAccelGroup *accel_group;
  GtkActionGroup *action_group;
  GtkUIManager *ui_manager;

  GError *error;

  /* initialize our options */
  opt.viewValue = 1;
  opt.appendLog = FALSE;
  opt.scanValue = SYN_SCAN;
  opt.throttleValue = NORMAL_THROTTLE;
  opt.resolveValue = DEFAULT_RESOLVE;
  opt.protportValue = DEFAULT_PROTPORT;
  opt.outputFormatValue = NORMAL_OUTPUT;

#ifdef WIN32
  opt.isr00t = 1;
  /* for nmap version */
#include "nmap_winconfig.h"
#define VERSION NMAP_VERSION
#else
  opt.isr00t = !geteuid();
#endif

/* main (toplevel) window */
  main_win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(main_win), "Nmap Front End v" VERSION);
  gtk_window_set_position (GTK_WINDOW (main_win), GTK_WIN_POS_CENTER);
  g_signal_connect (GTK_OBJECT (main_win), "delete_event",
		     GTK_SIGNAL_FUNC(Quit_callback), NULL);
  
/* vertical box for menu bar, input, output and status fields */
  main_vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add (GTK_CONTAINER (main_win), main_vbox);
  gtk_widget_show (main_vbox);

  action_group = gtk_action_group_new ("MenuActions");
  gtk_action_group_add_actions (action_group, menu_entries, 
          G_N_ELEMENTS (menu_entries), main_win);
  gtk_action_group_add_radio_actions (action_group, menu_entries_radio, 
          G_N_ELEMENTS (menu_entries_radio), 0, 
          G_CALLBACK(Colourize_callback), main_win);
  
  gtk_action_group_add_toggle_actions (action_group, menu_entries_toggle, 
          G_N_ELEMENTS (menu_entries_toggle), main_win);

  ui_manager = gtk_ui_manager_new ();
  gtk_ui_manager_insert_action_group (ui_manager, action_group, 0);

  error = NULL;
  if (!gtk_ui_manager_add_ui_from_string (ui_manager, menu_description, -1, &error)) {
      g_message ("building menus failed: %s", error->message);
      g_error_free (error);
      exit (EXIT_FAILURE);
  }

  /* main menu */
  menubar = gtk_ui_manager_get_widget (ui_manager, "/MainMenu");
  gtk_box_pack_start (GTK_BOX (main_vbox), menubar, 
          FALSE, TRUE, 0);
  gtk_widget_show (menubar);
  /*  Install the accelerator table in the main window  */
  accel_group = gtk_ui_manager_get_accel_group (ui_manager);
  gtk_window_add_accel_group (GTK_WINDOW (main_win), accel_group);

/* upper hbox for horizontal alignment */
  hbox = gtk_hbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
  gtk_box_pack_start(GTK_BOX(main_vbox), hbox, FALSE, FALSE, 10);

/* Target(s) entry field and label */
  label = gtk_label_new("Target(s):");
  gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  opt.targetHost = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.targetHost), 256);
  GTK_WIDGET_SET_FLAGS(opt.targetHost, GTK_CAN_DEFAULT);
  gtk_widget_grab_focus(opt.targetHost);
  gtk_entry_set_text(GTK_ENTRY(opt.targetHost), "127.0.0.1");
  g_signal_connect(GTK_OBJECT(opt.targetHost), "changed",
                     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_box_pack_start(GTK_BOX(hbox), opt.targetHost, TRUE, TRUE, 0);
  gtk_widget_show(opt.targetHost);

/* Exit button (rightmost in hbox) */
  button = gtk_button_new_with_label("Exit");
  /*gtk_object_set(GTK_OBJECT(button), "width", 48, NULL);*/
  g_signal_connect(GTK_OBJECT(button), "clicked",
                     GTK_SIGNAL_FUNC(Quit_callback), NULL);
  gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
  gtk_widget_show(button);

/* Scan button (2nd right in hbox) */
  opt.scanButton = gtk_toggle_button_new_with_label("Scan");
  /*gtk_object_set(GTK_OBJECT(opt.scanButton), "width", 72, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.scanButton), "toggled",
                     GTK_SIGNAL_FUNC(scanButton_toggled_cb), NULL);
  gtk_box_pack_end(GTK_BOX(hbox), opt.scanButton, FALSE, FALSE, 0);
  gtk_widget_show(opt.scanButton);

  gtk_widget_show(hbox);


/* notebook in vbox below hbox */
  notebook = gtk_notebook_new();
  gtk_container_set_border_width(GTK_CONTAINER(notebook), 5);

/* Scan page (first in notebook) */
  nblabel = gtk_label_new("Scan");
  /* nbpage = gtk_vbox_new(FALSE, 5); */
  nbpage = gtk_table_new(5, 3, TRUE);
  gtk_table_set_col_spacings(GTK_TABLE(nbpage), 5);
  gtk_table_set_row_spacings(GTK_TABLE(nbpage), 5);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);

  frame = gtk_frame_new("Scan Type");
  /* gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0); */
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 2, 0, 3);

  table = gtk_table_new(2, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_table_set_row_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  /* Create "Scan Type" combobox */
  {
      GtkCellRenderer *renderer;
      GtkTreeModel    *model;
      model = create_dropdown_store (scanentries, 
              opt.isr00t ? TRUE : FALSE);
      opt.scanType = gtk_combo_box_new_with_model (model);
      g_object_unref (model);

      opt.scanValue = opt.isr00t ? SYN_SCAN : CONNECT_SCAN;

      gtk_table_attach_defaults (GTK_TABLE(table), opt.scanType, 0, 4, 0, 1);
      gtk_widget_show (opt.scanType);

      renderer = gtk_cell_renderer_text_new ();
      gtk_cell_layout_pack_start (
              GTK_CELL_LAYOUT (opt.scanType), renderer, TRUE);
      gtk_cell_layout_set_attributes (
              GTK_CELL_LAYOUT (opt.scanType), renderer,
              "text", 0,
              NULL);
      g_object_unref(renderer);

      g_signal_connect(G_OBJECT(opt.scanType), "changed",
              G_CALLBACK (scanType_cb), scanentries);
      
  }
  
  opt.scanRelayLabel = gtk_label_new("Relay Host:");
  gtk_label_set_justify(GTK_LABEL(opt.scanRelayLabel), GTK_JUSTIFY_LEFT);
  if ((opt.scanValue != BOUNCE_SCAN) && (opt.scanValue != IDLE_SCAN))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelayLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanRelayLabel, 0, 1, 1, 2);
  gtk_widget_show(opt.scanRelayLabel);

  opt.scanRelay = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.scanRelay), 256);
  /*gtk_object_set(GTK_OBJECT(opt.scanRelay), "width", 150, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.scanRelay), "changed",
                     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.scanValue != BOUNCE_SCAN) && (opt.scanValue != IDLE_SCAN))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelay), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanRelay, 1, 4, 1, 2);
  gtk_widget_show(opt.scanRelay);

  gtk_widget_show(table);
  gtk_widget_show(frame);


  /* Scanned ports frame */
  {
    gint i;
    opt.protportFrame = gtk_frame_new("Scanned Ports");
    gtk_table_attach_defaults(GTK_TABLE(nbpage), opt.protportFrame, 2, 3, 0, 3);

    table = gtk_table_new(2, 2, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(table), 5);
    gtk_table_set_col_spacings(GTK_TABLE(table), 5);
    gtk_table_set_row_spacings(GTK_TABLE(table), 5);
    gtk_container_add(GTK_CONTAINER(opt.protportFrame), table);

    opt.protportType = gtk_combo_box_new_text();
    
    for(i = 0; protportEntries[i]; i++) {
        gtk_combo_box_append_text(GTK_COMBO_BOX(opt.protportType), protportEntries[i]);
    }

    g_signal_connect(G_OBJECT(opt.protportType), "changed",
            G_CALLBACK (protportType_cb), NULL);
    
    gtk_table_attach_defaults(GTK_TABLE(table), opt.protportType, 0, 2, 0, 1);

    opt.protportLabel = gtk_label_new("Range:");
    gtk_label_set_justify(GTK_LABEL(opt.protportLabel), GTK_JUSTIFY_LEFT);
    if (opt.protportValue != GIVEN_PROTPORT)
        gtk_widget_set_sensitive(GTK_WIDGET(opt.protportLabel), FALSE);
    gtk_table_attach_defaults(GTK_TABLE(table), opt.protportLabel, 0, 1, 1, 2);
    gtk_widget_show(opt.protportLabel);
    
    opt.protportRange = gtk_entry_new();
    gtk_entry_set_max_length(GTK_ENTRY(opt.protportRange), 256);
    /*gtk_object_set(GTK_OBJECT(opt.protportRange), "width", 100, NULL);*/
    g_signal_connect(GTK_OBJECT(opt.protportRange), "changed",
            GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
    if (opt.protportValue != GIVEN_PROTPORT)
        gtk_widget_set_sensitive(GTK_WIDGET(opt.protportRange), FALSE);
    gtk_table_attach_defaults(GTK_TABLE(table), opt.protportRange, 1, 2, 1, 2);

    gtk_widget_show_all(opt.protportFrame);
  }


  frame = gtk_frame_new("Scan Extensions");
  /* gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0); */
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 2, 3, 5);

  table = gtk_table_new(1, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_table_set_row_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.RPCInfo = gtk_check_button_new_with_label("RPC Scan");
  g_signal_connect(GTK_OBJECT(opt.RPCInfo), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.RPCInfo, 0, 1, 0, 1);
  gtk_widget_show(opt.RPCInfo);

  opt.OSInfo = gtk_check_button_new_with_label("OS Detection");
  g_signal_connect(GTK_OBJECT(opt.OSInfo), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (opt.isr00t)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(opt.OSInfo), TRUE);
  else
    gtk_widget_set_sensitive(GTK_WIDGET(opt.OSInfo), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.OSInfo, 2, 3, 0, 1);
  gtk_widget_show(opt.OSInfo);


  opt.VersionInfo = gtk_check_button_new_with_label("Version Probe");
  g_signal_connect(GTK_OBJECT(opt.VersionInfo), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(opt.VersionInfo), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.VersionInfo, 3, 4, 0, 1);
  gtk_widget_show(opt.VersionInfo);

  gtk_widget_show(table);
  gtk_widget_show(frame);


  gtk_widget_show(nblabel);
  gtk_widget_show(nbpage);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), GTK_WIDGET(nbpage), GTK_WIDGET(nblabel));


/* Discover/Ping page (second in notebook) */
  nblabel = gtk_label_new("Discover");
  nbpage = gtk_table_new(4, 4, FALSE);
  /* nbpage = gtk_vbox_new(FALSE, 5); */
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);

  opt.dontPing = gtk_check_button_new_with_label("Don't Ping");
  g_signal_connect(GTK_OBJECT(opt.dontPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.dontPing);
  gtk_table_attach_defaults(GTK_TABLE(nbpage), opt.dontPing, 0, 1, 0, 1);
  /* gtk_box_pack_start(GTK_BOX(nbpage), opt.dontPing, FALSE, FALSE, 0); */
  gtk_widget_show(opt.dontPing);

  
  frame = gtk_frame_new("Ping Types");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 3, 1, 4);
  /* gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0); */

  table = gtk_table_new(3, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.icmpechoPing = gtk_check_button_new_with_label("ICMP Echo");
  g_signal_connect(GTK_OBJECT(opt.icmpechoPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmpechoPing);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmpechoPing, 0, 1, 0, 1);
  if (opt.isr00t)
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(opt.icmpechoPing), TRUE);
  else
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpechoPing), FALSE);
  gtk_widget_show(opt.icmpechoPing);


  opt.icmptimePing = gtk_check_button_new_with_label("ICMP Timestamp");
  g_signal_connect(GTK_OBJECT(opt.icmptimePing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmptimePing);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmptimePing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmptimePing, 0, 1, 1, 2);
  gtk_widget_show(opt.icmptimePing);


  opt.icmpmaskPing = gtk_check_button_new_with_label("ICMP Netmask");
  g_signal_connect(GTK_OBJECT(opt.icmpmaskPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmpmaskPing);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpmaskPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmpmaskPing, 0, 1, 2, 3);
  gtk_widget_show(opt.icmpmaskPing);


  opt.tcpPing = gtk_check_button_new_with_label("TCP ACK Ping");
  g_signal_connect(GTK_OBJECT(opt.tcpPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.tcpPing);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPing, 1, 2, 0, 1);
  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(opt.tcpPing), TRUE);
  gtk_widget_show(opt.tcpPing);

  opt.tcpPingLabel = gtk_label_new("Port(s):");
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPingLabel, 2, 3, 0, 1);
  gtk_widget_show(opt.tcpPingLabel);
  
  opt.tcpPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.tcpPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.tcpPingPorts), "width", 100, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.tcpPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPingPorts, 3, 4, 0, 1);
  gtk_widget_show(opt.tcpPingPorts);


  opt.synPing = gtk_check_button_new_with_label("TCP SYN Ping");
  g_signal_connect(GTK_OBJECT(opt.synPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.synPing);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPing, 1, 2, 1, 2);
  gtk_widget_show(opt.synPing);

  opt.synPingLabel = gtk_label_new("Port(s):");
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.synPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPingLabel, 2, 3, 1, 2);
  gtk_widget_show(opt.synPingLabel);
  
  opt.synPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.synPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.synPingPorts), "width", 100, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.synPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t)  || (! GTK_TOGGLE_BUTTON(opt.synPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingPorts), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPingPorts, 3, 4, 1, 2);
  gtk_widget_show(opt.synPingPorts);


  opt.udpPing = gtk_check_button_new_with_label("UDP Ping");
  g_signal_connect(GTK_OBJECT(opt.udpPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.udpPing);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.udpPing, 1, 2, 2, 3);
  gtk_widget_show(opt.udpPing);

  opt.udpPingLabel = gtk_label_new("Port(s):");
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.udpPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.udpPingLabel, 2, 3, 2, 3);
  gtk_widget_show(opt.udpPingLabel);
  
  opt.udpPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.udpPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.udpPingPorts), "width", 100, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.udpPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.udpPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingPorts), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.udpPingPorts, 3, 4, 2, 3);
  gtk_widget_show(opt.udpPingPorts);

  gtk_widget_show(table);
  gtk_widget_show(frame);

  gtk_widget_show(nblabel);
  gtk_widget_show(nbpage);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), GTK_WIDGET(nbpage), GTK_WIDGET(nblabel));


/* Timings page (3rd in notebook) */
  nblabel = gtk_label_new("Timing");
  nbpage = gtk_hbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);


  /* Throttling & Timeouts combobox */
  {
    gint i;
    
    frame = gtk_frame_new("Throttling & Timeouts");
    gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0);

    table = gtk_table_new(5, 6, FALSE);
    gtk_container_set_border_width(GTK_CONTAINER(table), 5);
    gtk_table_set_col_spacing(GTK_TABLE(table), 1, 15);
    gtk_container_add(GTK_CONTAINER(frame), table);

    opt.throttleType = gtk_combo_box_new_text ();

    for (i = 0; throttleEntries[i]; i++) {
        gtk_combo_box_append_text(GTK_COMBO_BOX(opt.throttleType), throttleEntries[i]);
    }

    g_signal_connect(G_OBJECT(opt.throttleType), "changed",
            G_CALLBACK (throttleType_cb), NULL);

    gtk_table_attach_defaults(GTK_TABLE(table), opt.throttleType, 0, 2, 0, 1);
    gtk_widget_show(opt.throttleType);
  }


  opt.ipv4Ttl = gtk_check_button_new_with_label("IPv4 TTL");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.ipv4Ttl), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.ipv4Ttl, 0, 1, 2, 3);
  gtk_widget_show(opt.ipv4Ttl);

  adjust = (GtkAdjustment *) gtk_adjustment_new(127.0, 0.0, 255.0, 1.0, 10.0, 10.0);
  opt.ipv4TtlValue = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.ipv4TtlValue), TRUE);
  g_signal_connect(GTK_OBJECT(opt.ipv4Ttl), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.ipv4TtlValue);
  /*  gtk_object_set(GTK_OBJECT(opt.ipv4TtlValue), "width", 55, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.ipv4TtlValue), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.ipv4Ttl)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.ipv4TtlValue), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.ipv4TtlValue, 1, 2, 2, 3);
  gtk_widget_show(opt.ipv4TtlValue);


  opt.minPar = gtk_check_button_new_with_label("Min. Parallel");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minPar), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minPar, 0, 1, 3, 4);
  gtk_widget_show(opt.minPar);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 150.0, 1.0, 10.0, 10.0);
  opt.minParSocks = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.minParSocks), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.minParSocks), "width", 55, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.minPar), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.minParSocks);
  g_signal_connect(GTK_OBJECT(opt.minParSocks), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.minPar)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minParSocks), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minParSocks, 1, 2, 3, 4);
  gtk_widget_show(opt.minParSocks);


  opt.maxPar = gtk_check_button_new_with_label("Max. Parallel");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxPar), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxPar, 0, 1, 4, 5);
  gtk_widget_show(opt.maxPar);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 1500.0, 1.0, 10.0, 10.0);
  opt.maxParSocks = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.maxParSocks), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.maxParSocks), "width", 55, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.maxPar), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.maxParSocks);
  g_signal_connect(GTK_OBJECT(opt.maxParSocks), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.maxPar)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxParSocks), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxParSocks, 1, 2, 4, 5);
  gtk_widget_show(opt.maxParSocks);


  opt.startRtt = gtk_check_button_new_with_label("Initial RTT");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.startRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.startRtt, 2, 3, 0, 1);
  gtk_widget_show(opt.startRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 0.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.startRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  /*  gtk_object_set(GTK_OBJECT(opt.startRttTime), "width", 75, NULL);*/
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.startRttTime), TRUE);
  g_signal_connect(GTK_OBJECT(opt.startRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.startRttTime);
  g_signal_connect(GTK_OBJECT(opt.startRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.startRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.startRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.startRttTime, 3, 4, 0, 1);
  gtk_widget_show(opt.startRttTime);

  label = gtk_label_new("ms");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 0, 1);
  gtk_widget_show(label);


  opt.minRtt = gtk_check_button_new_with_label("Min. RTT");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minRtt, 2, 3, 1, 2);
  gtk_widget_show(opt.minRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 1.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.minRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.minRttTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.minRttTime), "width", 75, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.minRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.minRttTime);
  g_signal_connect(GTK_OBJECT(opt.minRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.minRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minRttTime, 3, 4, 1, 2);
  gtk_widget_show(opt.minRttTime);

  label = gtk_label_new("ms");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 1, 2);
  gtk_widget_show(label);


  opt.maxRtt = gtk_check_button_new_with_label("Max. RTT");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxRtt, 2, 3, 2, 3);
  gtk_widget_show(opt.maxRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 6.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.maxRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.maxRttTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.maxRttTime), "width", 75, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.maxRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.maxRttTime);
  g_signal_connect(GTK_OBJECT(opt.maxRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.maxRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxRttTime, 3, 4, 2, 3);
  gtk_widget_show(opt.maxRttTime);

  label = gtk_label_new("ms");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 2, 3);
  gtk_widget_show(label);


  opt.hostTimeout = gtk_check_button_new_with_label("Host Timeout");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.hostTimeout), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.hostTimeout, 2, 3, 3, 4);
  gtk_widget_show(opt.hostTimeout);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 201.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.hostTimeoutTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.hostTimeoutTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.hostTimeoutTime), "width", 75, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.hostTimeout), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.hostTimeoutTime);
  g_signal_connect(GTK_OBJECT(opt.hostTimeoutTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.hostTimeout)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.hostTimeoutTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.hostTimeoutTime, 3, 4, 3, 4);
  gtk_widget_show(opt.hostTimeoutTime);

  label = gtk_label_new("ms");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 3, 4);
  gtk_widget_show(label);


  opt.scanDelay = gtk_check_button_new_with_label("Scan Delay");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanDelay), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanDelay, 2, 3, 4, 5);
  gtk_widget_show(opt.scanDelay);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 1.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.scanDelayTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.scanDelayTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.scanDelayTime), "width", 75, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.scanDelay), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.scanDelayTime);
  g_signal_connect(GTK_OBJECT(opt.scanDelayTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((!opt.isr00t) || (! GTK_TOGGLE_BUTTON(opt.scanDelay)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanDelayTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanDelayTime, 3, 4, 4, 5);
  gtk_widget_show(opt.scanDelayTime);

  label = gtk_label_new("ms");
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 4, 5);
  gtk_widget_show(label);


  gtk_widget_show(table);
  gtk_widget_show(frame);

  gtk_widget_show(nblabel);
  gtk_widget_show(nbpage);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), GTK_WIDGET(nbpage), GTK_WIDGET(nblabel));


/* Files page (4th in notebook) */
  nblabel = gtk_label_new("Files");
  nbpage = gtk_hbox_new(TRUE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);
  /* gtk_table_set_col_spacings(GTK_TABLE(nbpage), 5); */

  frame = gtk_frame_new("Input File");
  gtk_box_pack_start(GTK_BOX(nbpage), frame, TRUE, TRUE, 0);

  table = gtk_table_new(5, 5, TRUE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacing(GTK_TABLE(table), 1, 15);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.useInputFile = gtk_check_button_new_with_label("Input File");
  g_signal_connect(GTK_OBJECT(opt.useInputFile), "released",
		     GTK_SIGNAL_FUNC(validate_file_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useInputFile, 0, 2, 0, 1);
  gtk_widget_show(opt.useInputFile);

  opt.inputFilename = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.inputFilename), 256);
  /*  gtk_object_set(GTK_OBJECT(opt.inputFilename), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.inputFilename), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.inputFilename),
                           GTK_TOGGLE_BUTTON(opt.useInputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.inputFilename, 0, 4, 2, 3);
  gtk_widget_show(opt.inputFilename);

  opt.inputBrowse = gtk_button_new_with_label("Browse");
  g_signal_connect(GTK_OBJECT(opt.inputBrowse), "pressed",
		     GTK_SIGNAL_FUNC(browseButton_pressed_cb), opt.inputFilename);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.inputBrowse),
                           GTK_TOGGLE_BUTTON(opt.useInputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.inputBrowse, 4, 5, 2, 3);
  gtk_widget_show(opt.inputBrowse);

  gtk_widget_show(table);
  gtk_widget_show(frame);


  frame = gtk_frame_new("Output File");
  gtk_box_pack_end(GTK_BOX(nbpage), frame, TRUE, TRUE, 0);

  table = gtk_table_new(5, 5, TRUE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacing(GTK_TABLE(table), 1, 15);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.useOutputFile = gtk_check_button_new_with_label("Output File");
  g_signal_connect(GTK_OBJECT(opt.useOutputFile), "released",
		     GTK_SIGNAL_FUNC(validate_file_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useOutputFile, 0, 2, 0, 1);
  gtk_widget_show(opt.useOutputFile);

  opt.outputFilename = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.outputFilename), 256);
  /*gtk_object_set(GTK_OBJECT(opt.outputFilename), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.outputFilename), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFilename),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFilename, 0, 4, 2, 3);
  gtk_widget_show(opt.outputFilename);

  opt.outputBrowse = gtk_button_new_with_label("Browse");
  g_signal_connect(GTK_OBJECT(opt.outputBrowse), "pressed",
		     GTK_SIGNAL_FUNC(browseButton_pressed_cb), opt.outputFilename);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputBrowse),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputBrowse, 4, 5, 2, 3);
  gtk_widget_show(opt.outputBrowse);


  {
    GtkTreeIter     iter;
    GtkListStore    *store;
    GtkCellRenderer *renderer;
    gint            i;

  opt.outputFormatLabel = gtk_label_new("Output Format:");
  gtk_label_set_justify(GTK_LABEL(opt.outputFormatLabel), GTK_JUSTIFY_LEFT);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFormatLabel, 0, 2, 3, 4);
  gtk_widget_show(opt.outputFormatLabel);

  store = gtk_list_store_new (1, G_TYPE_STRING);

  for (i = 0; i < G_N_ELEMENTS(outputFormatEntries); i++ ) {
    gtk_list_store_append(store, &iter);
    gtk_list_store_set(store, &iter, 
            0, outputFormatEntries[i], 
            -1);
  }
                
  opt.outputFormatType = gtk_combo_box_new_with_model(GTK_TREE_MODEL(store));

  g_object_unref(store);

#if GTK_CHECK_VERSION(2,6,0)
  gtk_combo_box_set_row_separator_func (GTK_COMBO_BOX (opt.outputFormatType),
          is_separator, NULL, NULL);
#endif

  renderer = gtk_cell_renderer_text_new ();
  gtk_cell_layout_pack_start (
          GTK_CELL_LAYOUT (opt.outputFormatType), renderer, TRUE);
  gtk_cell_layout_set_attributes (
          GTK_CELL_LAYOUT (opt.outputFormatType), renderer,
          "text", 0,
          NULL);
  g_object_unref(renderer);
  
  g_signal_connect(G_OBJECT(opt.outputFormatType), "changed",
          G_CALLBACK (outputFormatType_cb), NULL);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFormatType),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFormatType, 2, 4, 3, 4);
  gtk_widget_show(opt.outputFormatType);
  }

  opt.outputAppend = gtk_check_button_new_with_label("Append to File");
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputAppend, 0, 3, 4, 5);
  gtk_widget_show(opt.outputAppend);



  gtk_widget_show(table);
  gtk_widget_show(frame);


  gtk_widget_show(nblabel);
  gtk_widget_show(nbpage);

  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), GTK_WIDGET(nbpage), GTK_WIDGET(nblabel));


/* Option page (5th in notebook) */
  nblabel = gtk_label_new("Options");
  nbpage = gtk_table_new(2, 3, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);
  gtk_table_set_col_spacings(GTK_TABLE(nbpage), 5);

  /* Reverse DNS Resolution frame */
  {
    gint i;

    frame = gtk_frame_new("Reverse DNS Resolution");
    gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 1, 0, 1);

    vbox = gtk_vbox_new(FALSE, 5);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
    gtk_container_add(GTK_CONTAINER(frame), vbox);

    opt.resolveType = gtk_combo_box_new_text();

    for (i = 0; resolveEntries[i]; i++) {
      gtk_combo_box_append_text(GTK_COMBO_BOX(opt.resolveType), resolveEntries[i]);
    }

    g_signal_connect(G_OBJECT(opt.resolveType), "changed",
            G_CALLBACK (resolveType_cb), NULL);

    gtk_box_pack_start(GTK_BOX(vbox), opt.resolveType, TRUE, FALSE, 0);
    gtk_widget_show_all(frame);
  }

  /* Verbosity & Debugging frame */
  frame = gtk_frame_new("Verbosity & Debugging Levels");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 1, 1, 2);

  table = gtk_table_new(2, 2, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.verbose = gtk_check_button_new_with_label("Verbosity");
  gtk_table_attach_defaults(GTK_TABLE(table), opt.verbose, 0, 1, 0, 1);
  gtk_widget_show(opt.verbose);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 2.0, 1.0, 10.0, 10.0);
  opt.verboseValue = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.verboseValue), TRUE);
  g_signal_connect(GTK_OBJECT(opt.verbose), "released",
		   GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.verboseValue);
  g_signal_connect(GTK_OBJECT(opt.verboseValue), "changed",
		   GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.verbose)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.verboseValue), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.verboseValue, 1, 2, 0, 1);
  gtk_widget_show(opt.verboseValue);

  opt.debug = gtk_check_button_new_with_label("Debugging");
  gtk_table_attach_defaults(GTK_TABLE(table), opt.debug, 0, 1, 1, 2);
  gtk_widget_show(opt.debug);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 9.0, 1.0, 10.0, 10.0);
  opt.debugValue = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.debugValue), TRUE);
  g_signal_connect(GTK_OBJECT(opt.debug), "released",
		   GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.debugValue);
  g_signal_connect(GTK_OBJECT(opt.debugValue), "changed",
		   GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.debug)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.debugValue), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.debugValue, 1, 2, 1, 2);
  gtk_widget_show(opt.debugValue);

  gtk_widget_show(table);
  gtk_widget_show(frame);


  frame = gtk_frame_new("Source");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 1, 2, 0, 2);

  table = gtk_table_new(4, 2, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  /* gtk_table_set_col_spacings(GTK_TABLE(table), 5); */
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.useSourceDevice = gtk_check_button_new_with_label("Device");
  g_signal_connect(GTK_OBJECT(opt.useSourceDevice), "toggled",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourceDevice), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourceDevice, 0, 1, 0, 1);
  gtk_widget_show(opt.useSourceDevice);

  opt.SourceDevice = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourceDevice), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourceDevice), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.useSourceDevice), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourceDevice);
  g_signal_connect(GTK_OBJECT(opt.SourceDevice), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourceDevice)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourceDevice), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourceDevice, 1, 2, 0, 1);
  gtk_widget_show(opt.SourceDevice);


  opt.useSourcePort = gtk_check_button_new_with_label("Port");
  g_signal_connect(GTK_OBJECT(opt.useSourcePort), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourcePort), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourcePort, 0, 1, 1, 2);
  gtk_widget_show(opt.useSourcePort);

  opt.SourcePort = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourcePort), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourcePort), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.useSourcePort), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourcePort);
  g_signal_connect(GTK_OBJECT(opt.SourcePort), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourcePort)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourcePort), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourcePort, 1, 2, 1, 2);
  gtk_widget_show(opt.SourcePort);


  opt.useSourceIP = gtk_check_button_new_with_label("IP");
  g_signal_connect(GTK_OBJECT(opt.useSourceIP), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourceIP), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourceIP, 0, 1, 2, 3);
  gtk_widget_show(opt.useSourceIP);

  opt.SourceIP = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourceIP), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourceIP), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.useSourceIP), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourceIP);
  g_signal_connect(GTK_OBJECT(opt.SourceIP), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourceIP)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourceIP), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourceIP, 1, 2, 2, 3);
  gtk_widget_show(opt.SourceIP);


  opt.useDecoy = gtk_check_button_new_with_label("Decoy");
  g_signal_connect(GTK_OBJECT(opt.useDecoy), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useDecoy), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useDecoy, 0, 1, 3, 4);
  gtk_widget_show(opt.useDecoy);

  opt.Decoy = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.Decoy), 256);
  /*gtk_object_set(GTK_OBJECT(opt.Decoy), "width", 110, NULL);*/
  g_signal_connect(GTK_OBJECT(opt.useDecoy), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.Decoy);
  g_signal_connect(GTK_OBJECT(opt.Decoy), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useDecoy)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.Decoy), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.Decoy, 1, 2, 3, 4);
  gtk_widget_show(opt.Decoy);


  gtk_widget_show(table);
  gtk_widget_show(frame);


  frame = gtk_frame_new("Misc. Options");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 2, 3, 0, 2);

  vbox = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
  gtk_container_add(GTK_CONTAINER(frame), vbox);

  opt.useFragments = gtk_check_button_new_with_label("Fragmentation");
  g_signal_connect(GTK_OBJECT(opt.useFragments), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useFragments), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useFragments, FALSE, TRUE, 0);
  gtk_widget_show(opt.useFragments);


  opt.useIPv6 = gtk_check_button_new_with_label("IPv6");
  g_signal_connect(GTK_OBJECT(opt.useIPv6), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useIPv6), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useIPv6, FALSE, TRUE, 0);
  gtk_widget_show(opt.useIPv6);


  opt.useOrderedPorts = gtk_check_button_new_with_label("Ordered Ports");
  g_signal_connect(GTK_OBJECT(opt.useOrderedPorts), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (!opt.isr00t)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useOrderedPorts), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useOrderedPorts, FALSE, TRUE, 0);
  gtk_widget_show(opt.useOrderedPorts);

  opt.randomizeHosts = gtk_check_button_new_with_label("Randomize Host Order");
  g_signal_connect(GTK_OBJECT(opt.randomizeHosts), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_box_pack_start(GTK_BOX(vbox), opt.randomizeHosts, FALSE, TRUE, 0);
  gtk_widget_show(opt.randomizeHosts);

  gtk_widget_show(vbox);
  gtk_widget_show(frame);


  gtk_widget_show(nblabel);
  gtk_widget_show(nbpage);
  
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), GTK_WIDGET(nbpage), GTK_WIDGET(nblabel));
  
  gtk_box_pack_start(GTK_BOX(main_vbox), notebook, FALSE, TRUE, 5);
  gtk_widget_show(notebook);


 /* output box (variable; below notebook) */
   hbox = gtk_hbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX(main_vbox), hbox, TRUE, TRUE, 5);

 /* text widget with scroll bar */
   {
       GtkWidget *sw;
       GtkWidget *view;

       sw = gtk_scrolled_window_new(NULL, NULL);
       gtk_box_pack_start(GTK_BOX(main_vbox), sw, TRUE, TRUE, 5);

       view = gtk_text_view_new();
       opt.buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));

       /* Create tag definitions for text coloring */
       gtk_text_buffer_create_tag(opt.buffer, "normal",
               "family", "monospace", NULL);
       gtk_text_buffer_create_tag(opt.buffer, "bold",
               "family", "monospace", 
               "weight", PANGO_WEIGHT_BOLD, NULL);
       gtk_text_buffer_create_tag(opt.buffer, "red",
               "family", "monospace", 
               "weight", PANGO_WEIGHT_BOLD,
               "foreground", "red", NULL);
       gtk_text_buffer_create_tag(opt.buffer, "blue",
               "family", "monospace", 
               "weight", PANGO_WEIGHT_BOLD,
               "foreground", "blue", NULL);
       gtk_text_buffer_create_tag(opt.buffer, "green",
               "family", "monospace", 
               "weight", PANGO_WEIGHT_BOLD,
               "foreground", "green", NULL);

       gtk_container_add(GTK_CONTAINER(sw), view);
       gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD);
       gtk_widget_set_size_request(view, 500, 248);
       gtk_widget_show(view);
       gtk_widget_realize(view);
        
       gtk_widget_show(sw);
   }


/* status hbox at bottom */
  hbox = gtk_hbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(hbox), 5);
  gtk_box_pack_end(GTK_BOX(main_vbox), hbox, FALSE, FALSE, 5);

/* label and line in status box */
  label = gtk_label_new("Command:");
  gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);
  gtk_widget_show(label);

  opt.commandEntry = gtk_entry_new();
  gtk_editable_set_editable(GTK_EDITABLE(opt.commandEntry), FALSE);
  gtk_box_pack_start(GTK_BOX(hbox), opt.commandEntry, TRUE, TRUE, 0);
  gtk_widget_show(opt.commandEntry);

  gtk_widget_show(hbox);

  gtk_widget_show(main_vbox);

  /* Set default values here because now we can be sure that all the
   * widgets have been created.
   */
  /* First Notebook - Scan */
  gtk_combo_box_set_active(GTK_COMBO_BOX (opt.scanType), 0);
  gtk_combo_box_set_active(GTK_COMBO_BOX (opt.protportType), opt.protportValue);
  /* Third Notebook - Timing */
  gtk_combo_box_set_active(GTK_COMBO_BOX (opt.throttleType), opt.throttleValue);
  /* Fourth Notebook - Files */
  gtk_combo_box_set_active(GTK_COMBO_BOX (opt.outputFormatType), opt.outputFormatValue);
  /* Fifth Notebook - Options */
  gtk_combo_box_set_active(GTK_COMBO_BOX (opt.resolveType), opt.resolveValue);

  display_nmap_command();

  return main_win;
}

GtkWidget* create_fileSelection(const char *title, char *filename, void (*action)(), GtkEntry *entry)
{
GtkWidget *selector = gtk_file_selection_new((title) ? title : "Select File");

  if (filename) {
    if (*filename)
      gtk_file_selection_set_filename(GTK_FILE_SELECTION(selector), filename);
    g_object_set_data(G_OBJECT(selector), "NmapFE_filename", filename);
}
  if (action)
    g_object_set_data(G_OBJECT(selector), "NmapFE_action", action);
  if (entry)
    g_object_set_data(G_OBJECT(selector), "NmapFE_entry", entry);

  g_signal_connect_swapped(GTK_OBJECT(GTK_FILE_SELECTION(selector)->ok_button),
                            "clicked", GTK_SIGNAL_FUNC(okButton_clicked_cb),
                            (gpointer) selector);

  g_signal_connect_swapped(GTK_OBJECT(GTK_FILE_SELECTION(selector)->ok_button),
                            "clicked", GTK_SIGNAL_FUNC(gtk_widget_destroy),
                            (gpointer) selector);

  g_signal_connect_swapped(GTK_OBJECT(GTK_FILE_SELECTION(selector)->cancel_button),
                            "clicked", GTK_SIGNAL_FUNC(gtk_widget_destroy),
                            (gpointer) selector);

  return(selector);
}


GtkWidget* create_helpDialog()
{
GtkWidget *helpDialog;
GtkWidget *vbox;
GtkWidget *notebook;
GtkWidget *text;
GtkWidget *label;

 helpDialog = gtk_dialog_new_with_buttons("Help With NmapFE",
					  NULL,
					  GTK_DIALOG_MODAL,
					  GTK_STOCK_OK,
					  GTK_RESPONSE_NONE,
					  NULL);
 

 g_signal_connect_swapped (helpDialog,
			   "response", 
			   G_CALLBACK (gtk_widget_destroy),
			   helpDialog);

  gtk_widget_set_size_request(helpDialog, 400, 300);
  gtk_window_set_position(GTK_WINDOW(helpDialog), GTK_WIN_POS_CENTER);

  vbox = GTK_DIALOG(helpDialog)->vbox;

  notebook = gtk_notebook_new();
  gtk_widget_show(notebook);
  gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);

  label = gtk_label_new("Scanning");
  text = gtk_label_new("Starting a scan:\n"
		       "1) Put the host(s) name(s) of which to scan in the \"Targets\" text box.\n"
		       "2) Pick the scan options you would like\n"
		       "3) Pick the view you want from the 'View' menu option.\n"
		       "4) Click the 'Scan' button\n"
		       "\n"
		       "Stopping a Scan:\n"
		       "After clicking 'Scan', the button will remain depressed. \n"
		       "If you would like to stop the scan, simply click that button again.\n"
		       "The button will pop up, and the scan will be stopped.\n");
  gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);

  gtk_widget_show(label);
  gtk_widget_show(text);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), text, label);

  label = gtk_label_new("Logging");
  text = gtk_label_new("To log a scan in human-readable form:\n"
		       "1) After finishing a scan, click 'Save Log' from the 'File' menu.\n"
		       "\n"
		       "To re-open a human-readable log:\n"
		       "1) Click 'Open Log' from the 'File' menu.\n"
		       "2) If you have color coding enabled, the log will be opened in \n"
		       "color. If not, it will be opened in plain text.");
  gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);

  gtk_widget_show(label);
  gtk_widget_show(text);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), text, label);

  label = gtk_label_new("Colors");
  text = gtk_label_new("Bold Red - Services that would allow execution of commands\n"
		       "and/or logging directly into the system. Telnet, FTP, rsh, ssh,\n"
		       "etc... are covered by this. Not *every* single service is covered,\n"
		       "the code base would be huge if they were.\n"
		       "\n"
		       "Bold Blue - Mail services. IMAP, SMTP, POP3, etc... \n"
		       "Once again, not all are covered, just the common ones.\n"
		       "\n"
		       "Bold Black - Services users could get information from.\n"
		       "finger, http, X11, etc...\n"
		       "\n"
		       "Regular Black - Services I had nothing better to do with :)");
                      /* 
                       "\n"
		       "\n"
		       "If you have ideas on how to color code more, please let me know:\n"
		       "key@aye.net");
                      */
  gtk_label_set_justify(GTK_LABEL(text), GTK_JUSTIFY_LEFT);

  gtk_widget_show(label);
  gtk_widget_show(text);
  gtk_notebook_append_page(GTK_NOTEBOOK(notebook), text, label);

  gtk_widget_show(notebook);

  return(helpDialog);
}


#endif /* MISSING_GTK */
