
/***************************************************************************
 * nmapfe.c -- Handles widget placement for drawing the main NmapFE GUI    *
 * interface.                                                              *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2004 Insecure.Com LLC. Nmap       *
 * is also a registered trademark of Insecure.Com LLC.  This program is    *
 * free software; you may redistribute and/or modify it under the          *
 * terms of the GNU General Public License as published by the Free        *
 * Software Foundation; Version 2.  This guarantees your right to use,     *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we may be  *
 * willing to sell alternative licenses (contact sales@insecure.com).      *
 * Many security scanner vendors already license Nmap technology such as  *
 * our remote OS fingerprinting database and code, service/version         *
 * detection system, and port scanning code.                               *
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
 * http://www.insecure.org/nmap/ to download Nmap.                         *
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
 * applications and appliances.  These contracts have been sold to many    *
 * security vendors, and generally include a perpetual license as well as  *
 * providing for priority support and updates as well as helping to fund   *
 * the continued development of Nmap technology.  Please email             *
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


static GtkItemFactoryEntry mainMenuEntries[] = {
  { "/_File",             NULL, NULL,         FILE_MENU,        "<Branch>" },
  { "/File/Open Log",     NULL, mainMenu_fcb, FILEOPEN_MENU,    NULL },
  { "/File/Save Log",     NULL, mainMenu_fcb, FILESAVE_MENU,    NULL },
  { "/File/-",            NULL, NULL,         SEP_MENU,         "<Separator>" },
  { "/File/Quit",         NULL, mainMenu_fcb, FILEQUIT_MENU,    NULL },
  { "/_View",             NULL, NULL,         VIEW_MENU,        "<Branch>" },
  { "/View/Black&White",  NULL, mainMenu_fcb, VIEWMONO_MENU,    "<RadioItem>" },
  { "/View/Coloured",     NULL, mainMenu_fcb, VIEWCOLOR_MENU,   "/View/Black&White" },
  { "/View/-",            NULL, NULL,         SEP_MENU,         "<Separator>" },
  { "/View/Append Log",   NULL, mainMenu_fcb, VIEWAPPEND_MENU,  "<CheckItem>" },
  { "/_Help",             NULL, NULL,         HELP_MENU,        "<LastBranch>" },
  { "/Help/Help",         NULL, mainMenu_fcb, HELPHELP_MENU,    NULL },
  { "/Help/Nmap Version", NULL, mainMenu_fcb, HELPVERSION_MENU, NULL },
  { "/Help/-",            NULL, NULL,         SEP_MENU,         "<Separator>" },
  { "/Help/About ...",    NULL, mainMenu_fcb, HELPABOUT_MENU,   NULL },
  { NULL, NULL, NULL, NO_MENU, NULL }
};


static GtkItemFactoryEntry userScanEntries[] = {
  { "/Connect Scan",           NULL, scanType_changed_fcb, CONNECT_SCAN, NULL },
  { "/Ping Sweep",             NULL, scanType_changed_fcb, PING_SCAN,    NULL },
  { "/Host List",              NULL, scanType_changed_fcb, LIST_SCAN,    NULL },
  { "/FTP Bounce Attack",      NULL, scanType_changed_fcb, BOUNCE_SCAN,  NULL },
  { NULL, NULL, NULL, NO_SCAN, NULL }
};

static GtkItemFactoryEntry rootScanEntries[] = {
  { "/Connect Scan",           NULL, scanType_changed_fcb, CONNECT_SCAN, NULL },
  { "/SYN Stealth Scan",       NULL, scanType_changed_fcb, SYN_SCAN,     NULL },
  { "/ACK Stealth Scan",       NULL, scanType_changed_fcb, ACK_SCAN,     NULL },
  { "/FIN|ACK Stealth Scan",   NULL, scanType_changed_fcb, MAIMON_SCAN,  NULL },
  { "/FIN Stealth Scan",       NULL, scanType_changed_fcb, FIN_SCAN,     NULL },
  { "/NULL Stealth Scan",      NULL, scanType_changed_fcb, NULL_SCAN,    NULL },
  { "/XMas Tree Stealth Scan", NULL, scanType_changed_fcb, XMAS_SCAN,    NULL },
  { "/TCP Window Scan",        NULL, scanType_changed_fcb, WIN_SCAN,     NULL },
  { "/UDP Port Scan",          NULL, scanType_changed_fcb, UDP_SCAN,     NULL },
  { "/IP Protocol Scan",       NULL, scanType_changed_fcb, PROT_SCAN,    NULL },
  { "/Ping Sweep",             NULL, scanType_changed_fcb, PING_SCAN,    NULL },
  { "/Host List",              NULL, scanType_changed_fcb, LIST_SCAN,    NULL },
  { "/FTP Bounce Attack",      NULL, scanType_changed_fcb, BOUNCE_SCAN,  NULL },
  { "/Idle Scan",              NULL, scanType_changed_fcb, IDLE_SCAN,    NULL },
  { NULL, NULL, NULL, NO_SCAN, NULL }
};


static GtkItemFactoryEntry throttleEntries[] = {
  { "/Paranoid Throttling",  NULL, throttleType_changed_fcb, PARANOID_THROTTLE,  NULL },
  { "/Sneaky Throttling",    NULL, throttleType_changed_fcb, SNEAKY_THROTTLE,    NULL },
  { "/Polite Throttling",    NULL, throttleType_changed_fcb, POLITE_THROTTLE,    NULL },
  { "/Normal Throttling",    NULL, throttleType_changed_fcb, NORMAL_THROTTLE,    NULL },
  { "/Agressive Throttling", NULL, throttleType_changed_fcb, AGRESSIVE_THROTTLE, NULL },
  { "/Insane Throttling",    NULL, throttleType_changed_fcb, INSANE_THROTTLE,    NULL },
  { NULL, NULL, NULL, NO_THROTTLE, NULL }
};


static GtkItemFactoryEntry resolveEntries[] = {
  { "/Always",        NULL, resolveType_changed_fcb, ALWAYS_RESOLVE,  NULL },
  { "/When Required", NULL, resolveType_changed_fcb, DEFAULT_RESOLVE, NULL },
  { "/Never",         NULL, resolveType_changed_fcb, NEVER_RESOLVE,   NULL },
  { NULL, NULL, NULL, NO_RESOLVE, NULL }
};


static GtkItemFactoryEntry protportEntries[] = {
  { "/Default",         NULL, protportType_changed_fcb, DEFAULT_PROTPORT,   NULL },
  { "/All",         NULL, protportType_changed_fcb, ALL_PROTPORT,   NULL },
  { "/Most Important [fast]", NULL, protportType_changed_fcb, FAST_PROTPORT,  NULL },
  { "/Range Given Below",     NULL, protportType_changed_fcb, GIVEN_PROTPORT, NULL },
  { NULL, NULL, NULL, NO_PROTPORT, NULL }
};


static GtkItemFactoryEntry verboseEntries[] = {
  { "/Quiet",         NULL, verboseType_changed_fcb, QUIET_VERBOSE, NULL },
  { "/Verbose",       NULL, verboseType_changed_fcb, V1_VERBOSE,    NULL },
  { "/Very Verbose",  NULL, verboseType_changed_fcb, V2_VERBOSE,    NULL },
  { "/Debug",         NULL, verboseType_changed_fcb, D1_VERBOSE,    NULL },
  { "/Verbose Debug", NULL, verboseType_changed_fcb, D2_VERBOSE,    NULL },
  { NULL, NULL, NULL, NO_VERBOSE, NULL }
};


static GtkItemFactoryEntry outputFormatEntries[] = {
  { "/Normal",       NULL, outputFormatType_changed_fcb, NORMAL_OUTPUT, NULL },
  { "/grep-able",    NULL, outputFormatType_changed_fcb, GREP_OUTPUT,   NULL },
  { "/XML",          NULL, outputFormatType_changed_fcb, XML_OUTPUT,    NULL },
  { "/All",          NULL, outputFormatType_changed_fcb, ALL_OUTPUT,    NULL },
  { "/-",            NULL, NULL,                         NO_OUTPUT,     "<Separator>" },
  { "/ScriptKiddie", NULL, outputFormatType_changed_fcb, SKIDS_OUTPUT,  NULL },
  { NULL, NULL, NULL, NO_OUTPUT, NULL }
};



/* Returns a menubar widget made from the above menu */
static GtkWidget *new_factory_menu(GtkWidget  *window, GtkType menuType,
                                   const gchar *name, GtkItemFactoryEntry *entries,
                                   guint *variable)
{
GtkItemFactory *item_factory;
GtkAccelGroup *accel_group = NULL;
GtkItemFactoryEntry *end = entries;

  while ((end != NULL) && (end->path != NULL))
    end++;

  /* Make an accelerator group (shortcut keys) */
  if (window)
    accel_group = gtk_accel_group_new ();

  /* Make an ItemFactory (that makes a menubar) */
  item_factory = gtk_item_factory_new (menuType, name, accel_group);

  /* This function generates the menu items. Pass the item factory,
     the number of items in the array, the array itself, and any
     callback data for the the menu items. */
  gtk_item_factory_create_items(item_factory, end-entries, entries, variable);

  /* Attach the new accelerator group to the window. */
  if (window)
    gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);

  /* Finally, return the actual menu bar created by the item factory. */
  return(gtk_item_factory_get_widget(item_factory, name));
}


GtkWidget* create_main_win()
{
  GtkWidget *main_win;
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

  /* initialize our options */
  opt.viewValue = 1;
  opt.appendLog = FALSE;
  opt.uid = 0;
  opt.scanValue = SYN_SCAN;
  opt.throttleValue = NORMAL_THROTTLE;
  opt.resolveValue = DEFAULT_RESOLVE;
  opt.protportValue = DEFAULT_PROTPORT;
  opt.verboseValue = QUIET_VERBOSE;
  opt.outputFormatValue = NORMAL_OUTPUT;

#ifdef WIN32
  opt.uid = 0;
  /* for nmap version */
#include "nmap_winconfig.h"
#define VERSION NMAP_VERSION
#else
  opt.uid = getuid();
#endif


/* main (toplevel) window */
  main_win = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(main_win), "Nmap Front End v" VERSION);
  gtk_window_position (GTK_WINDOW (main_win), GTK_WIN_POS_CENTER);
  gtk_signal_connect (GTK_OBJECT (main_win), "delete_event",
		     GTK_SIGNAL_FUNC(exitNmapFE_cb), NULL);
  
  
/* vertical box for menu bar, input, output and status fields */
  main_vbox = gtk_vbox_new(FALSE, 0);
  gtk_container_add (GTK_CONTAINER (main_win), main_vbox);
  gtk_widget_show (main_vbox);


  /* main menu */
  menubar = new_factory_menu(main_win, GTK_TYPE_MENU_BAR, "<mainMenu>",
                             mainMenuEntries, NULL);
  gtk_box_pack_start (GTK_BOX (main_vbox), menubar, FALSE, TRUE, 0);
  if (opt.uid == 0) {
  GtkWidget *w = gtk_item_factory_get_widget_by_action(gtk_item_factory_from_widget(menubar),
                                                       VIEWCOLOR_MENU);
    gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(w), TRUE);
  }
  gtk_widget_show (menubar);

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
  gtk_widget_grab_default(opt.targetHost);
  gtk_entry_set_text(GTK_ENTRY(opt.targetHost), "127.0.0.1");
  gtk_signal_connect(GTK_OBJECT(opt.targetHost), "changed",
                     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_box_pack_start(GTK_BOX(hbox), opt.targetHost, TRUE, TRUE, 0);
  gtk_widget_show(opt.targetHost);

/* Exit button (rightmost in hbox) */
  button = gtk_button_new_with_label("Exit");
  /*gtk_object_set(GTK_OBJECT(button), "width", 48, NULL);*/
  gtk_signal_connect(GTK_OBJECT(button), "clicked",
                     GTK_SIGNAL_FUNC(exitNmapFE_cb), NULL);
  gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
  gtk_widget_show(button);

/* Scan button (2nd right in hbox) */
  opt.scanButton = gtk_toggle_button_new_with_label("Scan");
  /*gtk_object_set(GTK_OBJECT(opt.scanButton), "width", 72, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.scanButton), "toggled",
                     GTK_SIGNAL_FUNC(scanButton_toggled_cb), NULL);
  gtk_box_pack_end(GTK_BOX(hbox), opt.scanButton, FALSE, FALSE, 0);
  gtk_widget_show(opt.scanButton);

  gtk_widget_show(hbox);


/* notebook in vbox below hbox */
  notebook = gtk_notebook_new();
  gtk_container_set_border_width(GTK_CONTAINER(notebook), 5);

/* Scan page (first in notebook) */
  nblabel = gtk_label_new("Scan");
  // nbpage = gtk_vbox_new(FALSE, 5);
  nbpage = gtk_table_new(5, 3, TRUE);
  gtk_table_set_col_spacings(GTK_TABLE(nbpage), 5);
  gtk_table_set_row_spacings(GTK_TABLE(nbpage), 5);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);

  frame = gtk_frame_new("Scan Type");
  // gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 2, 0, 3);

  table = gtk_table_new(2, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_table_set_row_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.scanType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<scanMenu>",
                                  (opt.uid == 0) ? rootScanEntries : userScanEntries,
                                   &opt.scanValue);
  opt.scanValue = (opt.uid == 0) ? SYN_SCAN : CONNECT_SCAN;
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.scanType),
                              opt.scanValue - SCAN_OFFSET);
  
  /*gtk_object_set(GTK_OBJECT(opt.scanType), "height", 26, NULL);*/
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanType, 0, 4, 0, 1);
  gtk_widget_show(opt.scanType);

  opt.scanRelayLabel = gtk_label_new("Relay Host:");
  gtk_label_set_justify(GTK_LABEL(opt.scanRelayLabel), GTK_JUSTIFY_LEFT);
  if ((opt.scanValue != BOUNCE_SCAN) && (opt.scanValue != IDLE_SCAN))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelayLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanRelayLabel, 0, 1, 1, 2);
  gtk_widget_show(opt.scanRelayLabel);

  opt.scanRelay = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.scanRelay), 256);
  /*gtk_object_set(GTK_OBJECT(opt.scanRelay), "width", 150, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.scanRelay), "changed",
                     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.scanValue != BOUNCE_SCAN) && (opt.scanValue != IDLE_SCAN))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanRelay), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanRelay, 1, 4, 1, 2);
  gtk_widget_show(opt.scanRelay);

  gtk_widget_show(table);
  gtk_widget_show(frame);


  opt.protportFrame = gtk_frame_new("Scanned Ports");
  // gtk_box_pack_start(GTK_BOX(nbpage), opt.protportFrame, FALSE, FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(nbpage), opt.protportFrame, 2, 3, 0, 3);

  table = gtk_table_new(2, 2, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_table_set_row_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(opt.protportFrame), table);

  opt.protportType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<protportMenu>",
                                      protportEntries, &opt.protportValue);
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.protportType),
                              opt.protportValue - PROTPORT_OFFSET);
  /*  gtk_object_set(GTK_OBJECT(opt.protportType), "height", 26, NULL);*/
  gtk_table_attach_defaults(GTK_TABLE(table), opt.protportType, 0, 2, 0, 1);
  gtk_widget_show(opt.protportType);

  opt.protportLabel = gtk_label_new("Range:");
  gtk_label_set_justify(GTK_LABEL(opt.protportLabel), GTK_JUSTIFY_LEFT);
  if (opt.protportValue != GIVEN_PROTPORT)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.protportLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.protportLabel, 0, 1, 1, 2);
  gtk_widget_show(opt.protportLabel);

  opt.protportRange = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.protportRange), 256);
  /*gtk_object_set(GTK_OBJECT(opt.protportRange), "width", 100, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.protportRange), "changed",
                     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (opt.protportValue != GIVEN_PROTPORT)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.protportRange), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.protportRange, 1, 2, 1, 2);
  gtk_widget_show(opt.protportRange);

  gtk_widget_show(table);
  gtk_widget_show(opt.protportFrame);


  frame = gtk_frame_new("Scan Extensions");
  // gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0);
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 2, 3, 5);

  table = gtk_table_new(1, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_table_set_row_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.RPCInfo = gtk_check_button_new_with_label("RPC Scan");
  gtk_signal_connect(GTK_OBJECT(opt.RPCInfo), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.RPCInfo, 0, 1, 0, 1);
  gtk_widget_show(opt.RPCInfo);

  opt.OSInfo = gtk_check_button_new_with_label("OS Detection");
  gtk_signal_connect(GTK_OBJECT(opt.OSInfo), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (opt.uid == 0)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.OSInfo), TRUE);
  else
    gtk_widget_set_sensitive(GTK_WIDGET(opt.OSInfo), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.OSInfo, 2, 3, 0, 1);
  gtk_widget_show(opt.OSInfo);


  opt.VersionInfo = gtk_check_button_new_with_label("Version Probe");
  gtk_signal_connect(GTK_OBJECT(opt.VersionInfo), "released",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.VersionInfo), FALSE);
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
  // nbpage = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(nbpage), 5);

  opt.dontPing = gtk_check_button_new_with_label("Don't Ping");
  gtk_signal_connect(GTK_OBJECT(opt.dontPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.dontPing);
  gtk_table_attach_defaults(GTK_TABLE(nbpage), opt.dontPing, 0, 1, 0, 1);
  // gtk_box_pack_start(GTK_BOX(nbpage), opt.dontPing, FALSE, FALSE, 0);
  gtk_widget_show(opt.dontPing);

  
  frame = gtk_frame_new("Ping Types");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 3, 1, 4);
  // gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0);

  table = gtk_table_new(3, 4, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.icmpechoPing = gtk_check_button_new_with_label("ICMP Echo");
  gtk_signal_connect(GTK_OBJECT(opt.icmpechoPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmpechoPing);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmpechoPing, 0, 1, 0, 1);
  if (opt.uid == 0)
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.icmpechoPing), TRUE);
  else
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpechoPing), FALSE);
  gtk_widget_show(opt.icmpechoPing);


  opt.icmptimePing = gtk_check_button_new_with_label("ICMP Timestamp");
  gtk_signal_connect(GTK_OBJECT(opt.icmptimePing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmptimePing);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmptimePing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmptimePing, 0, 1, 1, 2);
  gtk_widget_show(opt.icmptimePing);


  opt.icmpmaskPing = gtk_check_button_new_with_label("ICMP Netmask");
  gtk_signal_connect(GTK_OBJECT(opt.icmpmaskPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.icmpmaskPing);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.icmpmaskPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.icmpmaskPing, 0, 1, 2, 3);
  gtk_widget_show(opt.icmpmaskPing);


  opt.tcpPing = gtk_check_button_new_with_label("TCP ACK Ping");
  gtk_signal_connect(GTK_OBJECT(opt.tcpPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.tcpPing);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPing, 1, 2, 0, 1);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(opt.tcpPing), TRUE);
  gtk_widget_show(opt.tcpPing);

  opt.tcpPingLabel = gtk_label_new("Port(s):");
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPingLabel, 2, 3, 0, 1);
  gtk_widget_show(opt.tcpPingLabel);
  
  opt.tcpPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.tcpPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.tcpPingPorts), "width", 100, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.tcpPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.tcpPingPorts, 3, 4, 0, 1);
  gtk_widget_show(opt.tcpPingPorts);


  opt.synPing = gtk_check_button_new_with_label("TCP SYN Ping");
  gtk_signal_connect(GTK_OBJECT(opt.synPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.synPing);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPing, 1, 2, 1, 2);
  gtk_widget_show(opt.synPing);

  opt.synPingLabel = gtk_label_new("Port(s):");
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.synPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPingLabel, 2, 3, 1, 2);
  gtk_widget_show(opt.synPingLabel);
  
  opt.synPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.synPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.synPingPorts), "width", 100, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.synPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0)  || (! GTK_TOGGLE_BUTTON(opt.synPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.synPingPorts), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.synPingPorts, 3, 4, 1, 2);
  gtk_widget_show(opt.synPingPorts);


  opt.udpPing = gtk_check_button_new_with_label("UDP Ping");
  gtk_signal_connect(GTK_OBJECT(opt.udpPing), "released",
		     GTK_SIGNAL_FUNC(pingButton_toggled_cb), opt.udpPing);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPing), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.udpPing, 1, 2, 2, 3);
  gtk_widget_show(opt.udpPing);

  opt.udpPingLabel = gtk_label_new("Port(s):");
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.udpPing)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.udpPingLabel), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.udpPingLabel, 2, 3, 2, 3);
  gtk_widget_show(opt.udpPingLabel);
  
  opt.udpPingPorts = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.udpPingPorts), 256);
  /*gtk_object_set(GTK_OBJECT(opt.udpPingPorts), "width", 100, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.udpPingPorts), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.udpPing)->active))
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


  frame = gtk_frame_new("Throttling & Timeouts");
  gtk_box_pack_start(GTK_BOX(nbpage), frame, FALSE, FALSE, 0);

  table = gtk_table_new(5, 6, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacing(GTK_TABLE(table), 1, 15);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.throttleType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<throttleMenu>",
                                      throttleEntries, &opt.throttleValue);
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.throttleType),
                              opt.throttleValue - THROTTLE_OFFSET);
  /*gtk_object_set(GTK_OBJECT(opt.throttleType), "height", 24, NULL);*/
  gtk_table_attach_defaults(GTK_TABLE(table), opt.throttleType, 0, 2, 0, 1);
  gtk_widget_show(opt.throttleType);


  opt.ipv4Ttl = gtk_check_button_new_with_label("IPv4 TTL");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.ipv4Ttl), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.ipv4Ttl, 0, 1, 2, 3);
  gtk_widget_show(opt.ipv4Ttl);

  adjust = (GtkAdjustment *) gtk_adjustment_new(127.0, 0.0, 255.0, 1.0, 10.0, 10.0);
  opt.ipv4TtlValue = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.ipv4TtlValue), TRUE);
  gtk_signal_connect(GTK_OBJECT(opt.ipv4Ttl), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.ipv4TtlValue);
  /*  gtk_object_set(GTK_OBJECT(opt.ipv4TtlValue), "width", 55, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.ipv4TtlValue), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.ipv4Ttl)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.ipv4TtlValue), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.ipv4TtlValue, 1, 2, 2, 3);
  gtk_widget_show(opt.ipv4TtlValue);


  opt.minPar = gtk_check_button_new_with_label("Min. Parallel");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minPar), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minPar, 0, 1, 3, 4);
  gtk_widget_show(opt.minPar);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 150.0, 1.0, 10.0, 10.0);
  opt.minParSocks = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.minParSocks), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.minParSocks), "width", 55, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.minPar), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.minParSocks);
  gtk_signal_connect(GTK_OBJECT(opt.minParSocks), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.minPar)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minParSocks), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minParSocks, 1, 2, 3, 4);
  gtk_widget_show(opt.minParSocks);


  opt.maxPar = gtk_check_button_new_with_label("Max. Parallel");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxPar), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxPar, 0, 1, 4, 5);
  gtk_widget_show(opt.maxPar);

  adjust = (GtkAdjustment *) gtk_adjustment_new(1.0, 1.0, 1500.0, 1.0, 10.0, 10.0);
  opt.maxParSocks = gtk_spin_button_new(adjust, 1.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.maxParSocks), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.maxParSocks), "width", 55, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.maxPar), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.maxParSocks);
  gtk_signal_connect(GTK_OBJECT(opt.maxParSocks), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.maxPar)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxParSocks), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxParSocks, 1, 2, 4, 5);
  gtk_widget_show(opt.maxParSocks);


  opt.startRtt = gtk_check_button_new_with_label("Initial RTT");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.startRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.startRtt, 2, 3, 0, 1);
  gtk_widget_show(opt.startRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 0.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.startRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  /*  gtk_object_set(GTK_OBJECT(opt.startRttTime), "width", 75, NULL);*/
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.startRttTime), TRUE);
  gtk_signal_connect(GTK_OBJECT(opt.startRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.startRttTime);
  gtk_signal_connect(GTK_OBJECT(opt.startRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.startRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.startRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.startRttTime, 3, 4, 0, 1);
  gtk_widget_show(opt.startRttTime);

  label = gtk_label_new("ms");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 0, 1);
  gtk_widget_show(label);


  opt.minRtt = gtk_check_button_new_with_label("Min. RTT");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minRtt, 2, 3, 1, 2);
  gtk_widget_show(opt.minRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 1.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.minRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.minRttTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.minRttTime), "width", 75, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.minRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.minRttTime);
  gtk_signal_connect(GTK_OBJECT(opt.minRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.minRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.minRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.minRttTime, 3, 4, 1, 2);
  gtk_widget_show(opt.minRttTime);

  label = gtk_label_new("ms");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 1, 2);
  gtk_widget_show(label);


  opt.maxRtt = gtk_check_button_new_with_label("Max. RTT");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxRtt), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxRtt, 2, 3, 2, 3);
  gtk_widget_show(opt.maxRtt);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 6.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.maxRttTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.maxRttTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.maxRttTime), "width", 75, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.maxRtt), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.maxRttTime);
  gtk_signal_connect(GTK_OBJECT(opt.maxRttTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.maxRtt)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.maxRttTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.maxRttTime, 3, 4, 2, 3);
  gtk_widget_show(opt.maxRttTime);

  label = gtk_label_new("ms");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 2, 3);
  gtk_widget_show(label);


  opt.hostTimeout = gtk_check_button_new_with_label("Host Timeout");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.hostTimeout), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.hostTimeout, 2, 3, 3, 4);
  gtk_widget_show(opt.hostTimeout);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 201.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.hostTimeoutTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.hostTimeoutTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.hostTimeoutTime), "width", 75, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.hostTimeout), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.hostTimeoutTime);
  gtk_signal_connect(GTK_OBJECT(opt.hostTimeoutTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.hostTimeout)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.hostTimeoutTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.hostTimeoutTime, 3, 4, 3, 4);
  gtk_widget_show(opt.hostTimeoutTime);

  label = gtk_label_new("ms");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(label), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), label, 4, 5, 3, 4);
  gtk_widget_show(label);


  opt.scanDelay = gtk_check_button_new_with_label("Scan Delay");
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanDelay), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanDelay, 2, 3, 4, 5);
  gtk_widget_show(opt.scanDelay);

  adjust = (GtkAdjustment *) gtk_adjustment_new(6000.0, 1.0, 9999999.0, 10.0, 100.0, 100.0);
  opt.scanDelayTime = gtk_spin_button_new(adjust, 10.0, 0);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(opt.scanDelayTime), TRUE);
  /*gtk_object_set(GTK_OBJECT(opt.scanDelayTime), "width", 75, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.scanDelay), "released",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.scanDelayTime);
  gtk_signal_connect(GTK_OBJECT(opt.scanDelayTime), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if ((opt.uid != 0) || (! GTK_TOGGLE_BUTTON(opt.scanDelay)->active))
    gtk_widget_set_sensitive(GTK_WIDGET(opt.scanDelayTime), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.scanDelayTime, 3, 4, 4, 5);
  gtk_widget_show(opt.scanDelayTime);

  label = gtk_label_new("ms");
  if (opt.uid != 0)
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
  // gtk_table_set_col_spacings(GTK_TABLE(nbpage), 5);

  frame = gtk_frame_new("Input File");
  gtk_box_pack_start(GTK_BOX(nbpage), frame, TRUE, TRUE, 0);

  table = gtk_table_new(5, 5, TRUE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  gtk_table_set_col_spacing(GTK_TABLE(table), 1, 15);
  gtk_container_add(GTK_CONTAINER(frame), table);


  opt.useInputFile = gtk_check_button_new_with_label("Input File");
  gtk_signal_connect(GTK_OBJECT(opt.useInputFile), "released",
		     GTK_SIGNAL_FUNC(validate_file_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useInputFile, 0, 2, 0, 1);
  gtk_widget_show(opt.useInputFile);

  opt.inputFilename = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.inputFilename), 256);
  /*  gtk_object_set(GTK_OBJECT(opt.inputFilename), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.inputFilename), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.inputFilename),
                           GTK_TOGGLE_BUTTON(opt.useInputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.inputFilename, 0, 4, 2, 3);
  gtk_widget_show(opt.inputFilename);

  opt.inputBrowse = gtk_button_new_with_label("Browse");
  gtk_signal_connect(GTK_OBJECT(opt.inputBrowse), "pressed",
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
  gtk_signal_connect(GTK_OBJECT(opt.useOutputFile), "released",
		     GTK_SIGNAL_FUNC(validate_file_change), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useOutputFile, 0, 2, 0, 1);
  gtk_widget_show(opt.useOutputFile);

  opt.outputFilename = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.outputFilename), 256);
  /*gtk_object_set(GTK_OBJECT(opt.outputFilename), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.outputFilename), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFilename),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFilename, 0, 4, 2, 3);
  gtk_widget_show(opt.outputFilename);

  opt.outputBrowse = gtk_button_new_with_label("Browse");
  gtk_signal_connect(GTK_OBJECT(opt.outputBrowse), "pressed",
		     GTK_SIGNAL_FUNC(browseButton_pressed_cb), opt.outputFilename);
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputBrowse),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputBrowse, 4, 5, 2, 3);
  gtk_widget_show(opt.outputBrowse);


  opt.outputFormatLabel = gtk_label_new("Output Format:");
  gtk_label_set_justify(GTK_LABEL(opt.outputFormatLabel), GTK_JUSTIFY_LEFT);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFormatLabel, 0, 2, 3, 4);
  gtk_widget_show(opt.outputFormatLabel);

  opt.outputFormatType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<outputFormatMenu>",
                                      outputFormatEntries, &opt.outputFormatValue);
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.outputFormatType),
                              opt.outputFormatValue - OUTPUT_OFFSET);
  /*  gtk_object_set(GTK_OBJECT(opt.outputFormatType), "height", 24, NULL);*/
  gtk_widget_set_sensitive(GTK_WIDGET(opt.outputFormatType),
                           GTK_TOGGLE_BUTTON(opt.useOutputFile)->active);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.outputFormatType, 2, 4, 3, 4);
  gtk_widget_show(opt.outputFormatType);


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


  frame = gtk_frame_new("Reverse DNS Resolution");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 1, 0, 1);

  vbox = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
  gtk_container_add(GTK_CONTAINER(frame), vbox);

  opt.resolveType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<resolveMenu>",
                                    resolveEntries, &opt.resolveValue);
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.resolveType),
                              opt.resolveValue - RESOLVE_OFFSET);
  /*gtk_object_set(GTK_OBJECT(opt.resolveType), "height", 24, NULL);*/
  gtk_box_pack_start(GTK_BOX(vbox), opt.resolveType, TRUE, FALSE, 0);
  gtk_widget_show(opt.resolveType);

  gtk_widget_show(vbox);
  gtk_widget_show(frame);


  frame = gtk_frame_new("Verbosity");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 0, 1, 1, 2);

  vbox = gtk_vbox_new(FALSE, 5);
  gtk_container_set_border_width(GTK_CONTAINER(vbox), 5);
  gtk_container_add(GTK_CONTAINER(frame), vbox);

  opt.verboseType = new_factory_menu(NULL, GTK_TYPE_OPTION_MENU, "<verboseMenu>",
                                    verboseEntries, &opt.verboseValue);
  gtk_option_menu_set_history(GTK_OPTION_MENU(opt.verboseType),
                              opt.verboseValue - VERBOSE_OFFSET);
  /*  gtk_object_set(GTK_OBJECT(opt.verboseType), "height", 24, NULL);*/
  gtk_box_pack_start(GTK_BOX(vbox), opt.verboseType, TRUE, FALSE, 0);
  gtk_widget_show(opt.verboseType);

  gtk_widget_show(vbox);
  gtk_widget_show(frame);


  frame = gtk_frame_new("Source");
  gtk_table_attach_defaults(GTK_TABLE(nbpage), frame, 1, 2, 0, 2);

  table = gtk_table_new(4, 2, FALSE);
  gtk_container_set_border_width(GTK_CONTAINER(table), 5);
  // gtk_table_set_col_spacings(GTK_TABLE(table), 5);
  gtk_container_add(GTK_CONTAINER(frame), table);

  opt.useSourceDevice = gtk_check_button_new_with_label("Device");
  gtk_signal_connect(GTK_OBJECT(opt.useSourceDevice), "toggled",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourceDevice), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourceDevice, 0, 1, 0, 1);
  gtk_widget_show(opt.useSourceDevice);

  opt.SourceDevice = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourceDevice), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourceDevice), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.useSourceDevice), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourceDevice);
  gtk_signal_connect(GTK_OBJECT(opt.SourceDevice), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourceDevice)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourceDevice), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourceDevice, 1, 2, 0, 1);
  gtk_widget_show(opt.SourceDevice);


  opt.useSourcePort = gtk_check_button_new_with_label("Port");
  gtk_signal_connect(GTK_OBJECT(opt.useSourcePort), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourcePort), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourcePort, 0, 1, 1, 2);
  gtk_widget_show(opt.useSourcePort);

  opt.SourcePort = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourcePort), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourcePort), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.useSourcePort), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourcePort);
  gtk_signal_connect(GTK_OBJECT(opt.SourcePort), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourcePort)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourcePort), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourcePort, 1, 2, 1, 2);
  gtk_widget_show(opt.SourcePort);


  opt.useSourceIP = gtk_check_button_new_with_label("IP");
  gtk_signal_connect(GTK_OBJECT(opt.useSourceIP), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useSourceIP), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useSourceIP, 0, 1, 2, 3);
  gtk_widget_show(opt.useSourceIP);

  opt.SourceIP = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.SourceIP), 64);
  /*gtk_object_set(GTK_OBJECT(opt.SourceIP), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.useSourceIP), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.SourceIP);
  gtk_signal_connect(GTK_OBJECT(opt.SourceIP), "changed",
		     GTK_SIGNAL_FUNC(display_nmap_command_cb), NULL);
  if (!GTK_TOGGLE_BUTTON(opt.useSourceIP)->active)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.SourceIP), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.SourceIP, 1, 2, 2, 3);
  gtk_widget_show(opt.SourceIP);


  opt.useDecoy = gtk_check_button_new_with_label("Decoy");
  gtk_signal_connect(GTK_OBJECT(opt.useDecoy), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useDecoy), FALSE);
  gtk_table_attach_defaults(GTK_TABLE(table), opt.useDecoy, 0, 1, 3, 4);
  gtk_widget_show(opt.useDecoy);

  opt.Decoy = gtk_entry_new();
  gtk_entry_set_max_length(GTK_ENTRY(opt.Decoy), 256);
  /*gtk_object_set(GTK_OBJECT(opt.Decoy), "width", 110, NULL);*/
  gtk_signal_connect(GTK_OBJECT(opt.useDecoy), "toggled",
		     GTK_SIGNAL_FUNC(toggle_button_set_sensitive_cb), opt.Decoy);
  gtk_signal_connect(GTK_OBJECT(opt.Decoy), "changed",
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
  gtk_signal_connect(GTK_OBJECT(opt.useFragments), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useFragments), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useFragments, FALSE, TRUE, 0);
  gtk_widget_show(opt.useFragments);


  opt.useIPv6 = gtk_check_button_new_with_label("IPv6");
  gtk_signal_connect(GTK_OBJECT(opt.useIPv6), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useIPv6), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useIPv6, FALSE, TRUE, 0);
  gtk_widget_show(opt.useIPv6);


  opt.useOrderedPorts = gtk_check_button_new_with_label("Ordered Ports");
  gtk_signal_connect(GTK_OBJECT(opt.useOrderedPorts), "released",
			GTK_SIGNAL_FUNC(validate_option_change), NULL);
  if (opt.uid != 0)
    gtk_widget_set_sensitive(GTK_WIDGET(opt.useOrderedPorts), FALSE);
  gtk_box_pack_start(GTK_BOX(vbox), opt.useOrderedPorts, FALSE, TRUE, 0);
  gtk_widget_show(opt.useOrderedPorts);

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
     sw = gtk_scrolled_window_new(NULL, NULL);
     gtk_box_pack_start(GTK_BOX(main_vbox), sw, TRUE, TRUE, 5);

     opt.output = gtk_text_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(sw),opt.output);
    gtk_text_set_word_wrap(GTK_TEXT(opt.output), 1);
    gtk_widget_set_usize(opt.output, 500, 248);
    gtk_widget_show(opt.output);
    gtk_widget_realize(opt.output);
        
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

  display_nmap_command();

  return main_win;
}


GtkWidget* create_aboutDialog()
{
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

  gtk_widget_show(notebook);

  return(aboutDialog);
}


GtkWidget* create_fileSelection(const char *title, char *filename, void (*action)(), GtkEntry *entry)
{
GtkWidget *selector = gtk_file_selection_new((title) ? title : "Select File");

  if (filename) {
    if (*filename)
      gtk_file_selection_set_filename(GTK_FILE_SELECTION(selector), filename);
    gtk_object_set_data(GTK_OBJECT(selector), "NmapFE_filename", filename);
}
  if (action)
    gtk_object_set_data(GTK_OBJECT(selector), "NmapFE_action", action);
  if (entry)
    gtk_object_set_data(GTK_OBJECT(selector), "NmapFE_entry", entry);

  gtk_signal_connect_object(GTK_OBJECT(GTK_FILE_SELECTION(selector)->ok_button),
                            "clicked", GTK_SIGNAL_FUNC(okButton_clicked_cb),
                            (gpointer) selector);

  gtk_signal_connect_object(GTK_OBJECT(GTK_FILE_SELECTION(selector)->ok_button),
                            "clicked", GTK_SIGNAL_FUNC(gtk_widget_destroy),
                            (gpointer) selector);

  gtk_signal_connect_object(GTK_OBJECT(GTK_FILE_SELECTION(selector)->cancel_button),
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

  gtk_widget_set_usize(helpDialog, 400, 300);
  gtk_window_position(GTK_WINDOW(helpDialog), GTK_WIN_POS_CENTER);

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
