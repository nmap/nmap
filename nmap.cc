
/***************************************************************************
 * nmap.cc -- Currently handles some of Nmap's port scanning features as   *
 * well as the command line user interface.  Note that the actual main()   *
 * function is in main.cc                                                  *
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

#include "nmap.h"
#include "osscan.h"
#include "scan_engine.h"
#include "idle_scan.h"
#include "timing.h"
#include "NmapOps.h"

/* global options */
extern char *optarg;
extern int optind;
extern NmapOps o;  /* option structure */

#ifdef __amigaos__
extern void CloseLibs(void);
#endif

/* parse the --scanflags argument.  It can be a number >=0 or a string consisting of TCP flag names like "URGPSHFIN".  Returns -1 if the argument is invalid. */
static int parse_scanflags(char *arg) {
  int flagval = 0;
  char *end = NULL;

  if (isdigit(arg[0])) {
    flagval = strtol(arg, &end, 0);
    if (*end || flagval < 0 || flagval > 255) return -1;
  } else {
    if (strcasestr(arg, "FIN")) {
      flagval |= TH_FIN;
    } 
    if (strcasestr(arg, "SYN")) {
      flagval |= TH_SYN;
    } 
    if (strcasestr(arg, "RST") || strcasestr(arg, "RESET")) {
      flagval |= TH_RST;
    } 
    if (strcasestr(arg, "PSH") || strcasestr(arg, "PUSH")) {
      flagval |= TH_PUSH;
    } 
    if (strcasestr(arg, "ACK")) {
      flagval |= TH_ACK;
    } 
    if (strcasestr(arg, "URG")) {
      flagval |= TH_URG;
    } 
    if (strcasestr(arg, "SYN")) {
      flagval |= TH_SYN;
    }
  }
  return flagval;
}

/* parse a URL stype ftp string of the form user:pass@server:portno */
static int parse_bounce_argument(struct ftpinfo *ftp, char *url) {
  char *p = url,*q, *s;

  if ((q = strrchr(url, '@'))) /*we have username and/or pass */ {
    *(q++) = '\0';
    if ((s = strchr(q, ':')))
      { /* has portno */
	*(s++) = '\0';
	strncpy(ftp->server_name, q, MAXHOSTNAMELEN);
	ftp->port = atoi(s);
      }
    else  strncpy(ftp->server_name, q, MAXHOSTNAMELEN);

    if ((s = strchr(p, ':'))) { /* User AND pass given */
      *(s++) = '\0';
      strncpy(ftp->user, p, 63);
      strncpy(ftp->pass, s, 255);
    }
    else { /* Username ONLY given */
      log_write(LOG_STDOUT, "Assuming %s is a username, and using the default password: %s\n",
	      p, ftp->pass);
      strncpy(ftp->user, p, 63);
    }
  }
  else /* no username or password given */ 
    if ((s = strchr(url, ':'))) { /* portno is given */
      *(s++) = '\0';
      strncpy(ftp->server_name, url, MAXHOSTNAMELEN);
      ftp->port = atoi(s);
    }
    else  /* default case, no username, password, or portnumber */
      strncpy(ftp->server_name, url, MAXHOSTNAMELEN);

  ftp->user[63] = ftp->pass[255] = ftp->server_name[MAXHOSTNAMELEN] = 0;

  return 1;
}

int nmap_main(int argc, char *argv[]) {
  char *p, *q;
  int i, arg;
  unsigned int targetno;
  size_t j, argvlen;
  FILE *inputfd = NULL, *excludefd = NULL;
  char *host_spec = NULL, *exclude_spec = NULL;
  short fastscan=0, randomize=1, resolve_all=0;
  short quashargv = 0;
  int numhosts_scanned = 0;
  char **host_exp_group;
  char *idleProxy = NULL; /* The idle host used to "Proxy" an Idlescan */
  int num_host_exp_groups = 0;
  char *machinefilename = NULL, *kiddiefilename = NULL, 
    *normalfilename = NULL, *xmlfilename = NULL;
  HostGroupState *hstate = NULL;
  int numhosts_up = 0;
  int starttime;
  char *endptr = NULL;
  struct scan_lists *ports = NULL;
  TargetGroup *exclude_group = NULL;
  char myname[MAXHOSTNAMELEN + 1];
#if (defined(IN_ADDR_DEEPSTRUCT) || defined( SOLARIS))
  /* Note that struct in_addr in solaris is 3 levels deep just to store an
   * unsigned int! */
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "",  { { { 0 } } } , 21, 0};
#else
  struct ftpinfo ftp = { FTPUSER, FTPPASS, "", { 0 }, 21, 0};
#endif
  struct hostent *target = NULL;
  char **fakeargv;
  Target *currenths;
  vector<Target *> Targets;
  char *proberr;
#if WIN32
  bool skip_winip_init = false;
#endif
  char emptystring[1];
  int sourceaddrwarning = 0; /* Have we warned them yet about unguessable
				source addresses? */
  unsigned int ideal_scan_group_sz = 0;
  char hostname[MAXHOSTNAMELEN + 1] = "";
  time_t timep;
  char mytime[128];
  struct sockaddr_storage ss;
  size_t sslen;
  int option_index;
  struct option long_options[] =
    {
      {"version", no_argument, 0, 'V'},
      {"verbose", no_argument, 0, 'v'},
      {"datadir", required_argument, 0, 0},
      {"debug", optional_argument, 0, 'd'},
      {"help", no_argument, 0, 'h'},
      {"max_parallelism", required_argument, 0, 'M'},
      {"min_parallelism", required_argument, 0, 0},
      {"timing", required_argument, 0, 'T'},
      {"max_rtt_timeout", required_argument, 0, 0},
      {"min_rtt_timeout", required_argument, 0, 0},
      {"initial_rtt_timeout", required_argument, 0, 0},
      {"excludefile", required_argument, 0, 0},
      {"exclude", required_argument, 0, 0},
      {"max_hostgroup", required_argument, 0, 0},
      {"min_hostgroup", required_argument, 0, 0},
      {"scanflags", required_argument, 0, 0},
      {"host_timeout", required_argument, 0, 0},
      {"scan_delay", required_argument, 0, 0},
      {"max_scan_delay", required_argument, 0, 0},
      {"oA", required_argument, 0, 0},  
      {"oN", required_argument, 0, 0},
      {"oM", required_argument, 0, 0},  
      {"oG", required_argument, 0, 0},  
      {"oS", required_argument, 0, 0},
      {"oH", required_argument, 0, 0},  
      {"oX", required_argument, 0, 0},  
      {"iL", required_argument, 0, 0},  
      {"iR", required_argument, 0, 0},
      {"sI", required_argument, 0, 0},  
      {"source_port", required_argument, 0, 'g'},
      {"randomize_hosts", no_argument, 0, 0},
      {"osscan_limit", no_argument, 0, 0}, /* skip OSScan if no open ports */
      {"osscan_guess", no_argument, 0, 0}, /* More guessing flexability */
      {"packet_trace", no_argument, 0, 0}, /* Display all packets sent/rcv */
      {"version_trace", no_argument, 0, 0}, /* Display -sV related activity */
      {"fuzzy", no_argument, 0, 0}, /* Alias for osscan_guess */
      {"data_length", required_argument, 0, 0},
      {"stylesheet", required_argument, 0, 0},
      {"no-stylesheet", no_argument, 0, 0},
      {"rH", no_argument, 0, 0},
      {"vv", no_argument, 0, 0},
      {"ff", no_argument, 0, 0},
      {"mtu", required_argument, 0, 0},
      {"append_output", no_argument, 0, 0},
      {"noninteractive", no_argument, 0, 0},
      {"ttl", required_argument, 0, 0}, /* Time to live */
#ifdef WIN32
      {"win_list_interfaces", no_argument, 0, 0},
      {"win_norawsock", no_argument, 0, 0}, 
      {"win_forcerawsock", no_argument, 0, 0}, 
      {"win_nopcap", no_argument, 0, 0}, 
      {"win_nt4route", no_argument, 0, 0}, 
      {"win_noiphlpapi", no_argument, 0, 0}, 
      {"win_help", no_argument, 0, 0},
      {"win_trace", no_argument, 0, 0},
      {"win_skip_winip_init", no_argument, 0, 0},
#endif
      {0, 0, 0, 0}
    };

  /* argv faking silliness */
  fakeargv = (char **) safe_malloc(sizeof(char *) * (argc + 1));
  for(i=0; i < argc; i++) {
    fakeargv[i] = strdup(argv[i]);
  }
  fakeargv[argc] = NULL;

  emptystring[0] = '\0'; /* It wouldn't be an emptystring w/o this ;) */

  if (argc < 2 ) printusage(argv[0], -1);
  Targets.reserve(100);

  /* OK, lets parse these args! */
  optind = 1; /* so it can be called multiple times */
  while((arg = getopt_long_only(argc,fakeargv,"6Ab:D:d::e:Ffg:hIi:M:m:NnOo:P:p:qRrS:s:T:Vv", long_options, &option_index)) != EOF) {
    switch(arg) {
    case 0:
      if (strcmp(long_options[option_index].name, "max_rtt_timeout") == 0) {
	o.setMaxRttTimeout(atoi(optarg));
	if (o.maxRttTimeout() < 5) {
	  fatal("max_rtt_timeout is given in milliseconds and must be at least 5");
	}       
        if (o.maxRttTimeout() < 20) {
	  error("WARNING: You specified a round-trip time timeout (%d ms) that is EXTRAORDINARILY SMALL.  Accuracy may suffer.", o.maxRttTimeout());
	}
      } else if (strcmp(long_options[option_index].name, "min_rtt_timeout") == 0) {
	o.setMinRttTimeout(atoi(optarg));
	if (o.minRttTimeout() > 50000) {
	  error("Warning:  min_rtt_timeout is given in milliseconds, your value seems pretty large.");
	}
      } else if (strcmp(long_options[option_index].name, "initial_rtt_timeout") == 0) {
	o.setInitialRttTimeout(atoi(optarg));
	if (o.initialRttTimeout() <= 0) {
	  fatal("initial_rtt_timeout must be greater than 0");
	}
      } else if (strcmp(long_options[option_index].name, "excludefile") == 0) {
        excludefd = fopen(optarg, "r");
        if (!excludefd) {
          fatal("Failed to open exclude file %s for reading", optarg);
        }
      } else if (strcmp(long_options[option_index].name, "exclude") == 0) {
	if (excludefd)
	  fatal("--excludefile and --exclude options are mutually exclusive.");
	exclude_spec = strdup(optarg);
      } else if (strcmp(long_options[option_index].name, "max_hostgroup") == 0) {
	o.setMaxHostGroupSz(atoi(optarg));
      } else if (strcmp(long_options[option_index].name, "min_hostgroup") == 0) {
	o.setMinHostGroupSz(atoi(optarg));
	if (atoi(optarg) > 100)
	  error("Warning: You specified a highly aggressive --min_hostgroup.");
      } else if (strcmp(long_options[option_index].name, "scanflags") == 0) {
	o.scanflags = parse_scanflags(optarg);
	if (o.scanflags < 0) {
	  fatal("--scanflags option must be a number between 0 and 255 (inclusive) or a string like \"URGPSHFIN\".");
	}
      } else if (strcmp(long_options[option_index].name, "min_parallelism") == 0 ) {
	o.min_parallelism = atoi(optarg); 
	if (o.min_parallelism < 1) fatal("Argument to --min_parallelism must be at least 1!");
	if (o.min_parallelism > 100) {
	  error("Warning: Your --min_parallelism option is absurdly high! Don't complain to Fyodor if all hell breaks loose!");
	}
      } else if (strcmp(long_options[option_index].name, "host_timeout") == 0) {
	o.host_timeout = strtoul(optarg, NULL, 10);
	if (o.host_timeout <= 200) {
	  fatal("host_timeout is given in milliseconds and must be greater than 200");
	}
      } else if (strcmp(long_options[option_index].name, "ttl") == 0) {
	o.ttl = atoi(optarg);
	if (o.ttl < 0 || o.ttl > 255) {
	  fatal("ttl option must be a number between 0 and 255 (inclusive)");
	}
      } else if (strcmp(long_options[option_index].name, "datadir") == 0) {
	o.datadir = strdup(optarg);
#ifdef WIN32
      } else if (strcmp(long_options[option_index].name, "win_list_interfaces") == 0 ) { 
	wo.listinterfaces = 1; 
      } else if (strcmp(long_options[option_index].name, "win_norawsock") == 0 ) { 
	wo.norawsock = 1; 
      } else if (strcmp(long_options[option_index].name, "win_forcerawsock") == 0 ) { 
	wo.forcerawsock = 1; 
      } else if (strcmp(long_options[option_index].name, "win_nopcap") == 0 ) { 
	wo.nopcap = 1; 
      } else if (strcmp(long_options[option_index].name, "win_nt4route") == 0 ) { 
	wo.nt4route = 1; 
      } else if (strcmp(long_options[option_index].name, "win_noiphlpapi") == 0 ) { 
	wo.noiphlpapi = 1; 
      } else if (strcmp(long_options[option_index].name, "win_trace") == 0 ) { 
	wo.trace++; 
      } else if (strcmp(long_options[option_index].name, "win_skip_winip_init") == 0 ) { 
	skip_winip_init = true;
      } else if (strcmp(long_options[option_index].name, "win_help") == 0 ) { 
	printf("Windows-specific options:\n\n"); 
	printf(" --win_list_interfaces : list all network interfaces\n"); 
	printf(" --win_norawsock       : disable raw socket support\n"); 
	printf(" --win_forcerawsock    : try raw sockets even on non-W2K systems\n"); 
	printf(" --win_nopcap          : disable winpcap support\n"); 
	printf(" --win_nt4route        : test nt4 route code\n"); 
	printf(" --win_noiphlpapi      : test response to lack of iphlpapi.dll\n"); 
	printf(" --win_trace           : trace through raw IP initialization\n");
	exit(0);
#endif
      } else if (strcmp(long_options[option_index].name, "append_output") == 0) {
	o.append_output = 1;
      } else if (strcmp(long_options[option_index].name, "noninteractive") == 0) {
	/* Do nothing */
      } else if (strcmp(long_options[option_index].name, "scan_delay") == 0) {
	o.scan_delay = atoi(optarg);
	if (o.scan_delay <= 0) {
	  fatal("scan_delay must be greater than 0");
	}
	if (o.scan_delay > o.maxTCPScanDelay()) o.setMaxTCPScanDelay(o.scan_delay);
	if (o.scan_delay > o.maxUDPScanDelay()) o.setMaxUDPScanDelay(o.scan_delay);
	o.max_parallelism = 1;
      } else if (strcmp(long_options[option_index].name, "max_scan_delay") == 0) {
	unsigned int scand = atoi(optarg);
	if (scand < 0) {
	  fatal("max_scan_delay must be greater than 0");
	}
	o.setMaxTCPScanDelay(scand);
	o.setMaxUDPScanDelay(scand);
      } else if (strcmp(long_options[option_index].name, "randomize_hosts") == 0
		 || strcmp(long_options[option_index].name, "rH") == 0) {
	o.randomize_hosts = 1;
	o.ping_group_sz = PING_GROUP_SZ * 4;
      } else if (strcmp(long_options[option_index].name, "osscan_limit")  == 0) {
	o.osscan_limit = 1;
      } else if (strcmp(long_options[option_index].name, "osscan_guess")  == 0
                 || strcmp(long_options[option_index].name, "fuzzy") == 0) {
	o.osscan_guess = 1;
      } else if (strcmp(long_options[option_index].name, "packet_trace") == 0) {
	o.setPacketTrace(true);
      } else if (strcmp(long_options[option_index].name, "version_trace") == 0) {
	o.setVersionTrace(true);
	o.debugging++;
      } else if (strcmp(long_options[option_index].name, "data_length") == 0) {
	o.extra_payload_length = atoi(optarg);
	if (o.extra_payload_length < 0) {
	  fatal("data_length must be greater than 0");
	} else if (o.extra_payload_length > 0) {
	  o.extra_payload = (char *) safe_malloc(o.extra_payload_length);
	  get_random_bytes(o.extra_payload, o.extra_payload_length);
	}
      } else if (strcmp(long_options[option_index].name, "stylesheet") == 0) {
	o.setXSLStyleSheet(optarg);
      } else if (strcmp(long_options[option_index].name, "no-stylesheet") == 0) {
	o.setXSLStyleSheet(NULL);
      } else if (strcmp(long_options[option_index].name, "oN") == 0) {
	normalfilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oG") == 0 ||
		 strcmp(long_options[option_index].name, "oM") == 0) {
	machinefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oS") == 0) {
	kiddiefilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oH") == 0) {
	fatal("HTML output is not yet supported");
      } else if (strcmp(long_options[option_index].name, "oX") == 0) {
	xmlfilename = optarg;
      } else if (strcmp(long_options[option_index].name, "oA") == 0) {
	char buf[MAXPATHLEN];
	snprintf(buf, sizeof(buf), "%s.nmap", optarg);
	normalfilename = strdup(buf);
	snprintf(buf, sizeof(buf), "%s.gnmap", optarg);
	machinefilename = strdup(buf);
	snprintf(buf, sizeof(buf), "%s.xml", optarg);
	xmlfilename = strdup(buf);
      }
      else if (strcmp(long_options[option_index].name, "iL") == 0) {
	if (inputfd) {
	  fatal("Only one input filename allowed");
	}
	if (!strcmp(optarg, "-")) {
	  inputfd = stdin;
	} else {    
	  inputfd = fopen(optarg, "r");
	  if (!inputfd) {
	    fatal("Failed to open input file %s for reading", optarg);
	  }  
	}
      } else if (strcmp(long_options[option_index].name, "iR") == 0) {
	o.generate_random_ips = 1;
	o.max_ips_to_scan = strtoul(optarg, &endptr, 10);
	if (*endptr != '\0') {
	  fatal("ERROR: -iR argument must be the maximum number of random IPs you wish to scan (use 0 for unlimited)");
	}
      } else if (strcmp(long_options[option_index].name, "sI") == 0) {
	o.idlescan = 1;
	idleProxy = optarg;
      } else if (strcmp(long_options[option_index].name, "vv") == 0) {
	/* Compatability hack ... ugly */
	o.verbose += 2;
      } else if (strcmp(long_options[option_index].name, "ff") == 0) {
	o.fragscan += 16; 
      } else if (strcmp(long_options[option_index].name, "mtu") == 0) {
        o.fragscan = atoi(optarg);
        if (o.fragscan <= 0 || o.fragscan % 8 != 0)
            fatal("Data payload MTU must be >0 and multiple of 8");
      } else {
	fatal("Unknown long option (%s) given@#!$#$", long_options[option_index].name);
      }
      break;
    case '6':
#if !HAVE_IPV6
      fatal("I am afraid IPv6 is not available because your host doesn't support it or you chose to compile Nmap w/o IPv6 support.");
#else
      o.setaf(AF_INET6);
#endif /* !HAVE_IPV6 */
      break;
    case 'A':
      o.servicescan = true;
      if (o.isr00t)
	o.osscan++; 
      break;
    case 'b': 
      o.bouncescan++;
      if (parse_bounce_argument(&ftp, optarg) < 0 ) {
	fprintf(stderr, "Your argument to -b is b0rked. Use the normal url style:  user:pass@server:port or just use server and use default anon login\n  Use -h for help\n");
      }
      break;
    case 'D':
      p = optarg;
      do {    
	q = strchr(p, ',');
	if (q) *q = '\0';
	if (!strcasecmp(p, "me")) {
	  if (o.decoyturn != -1) 
	    fatal("Can only use 'ME' as a decoy once.\n");
	  o.decoyturn = o.numdecoys++;
	} else {      
	  if (o.numdecoys >= MAX_DECOYS -1)
	    fatal("You are only allowed %d decoys (if you need more redefine MAX_DECOYS in nmap.h)", MAX_DECOYS);
	  if (resolve(p, &o.decoys[o.numdecoys])) {
	    o.numdecoys++;
	  } else {
	    fatal("Failed to resolve decoy host: %s (must be hostname or IP address", optarg);
	  }
	}
	if (q) {
	  *q = ',';
	  p = q+1;
	}
      } while(q);
      break;
    case 'd': 
      if (optarg)
	o.debugging = o.verbose = atoi(optarg);
      else {
	o.debugging++; o.verbose++;
      }
      break;
    case 'e': 
      strncpy(o.device, optarg,63); o.device[63] = '\0'; break;
    case 'F': fastscan++; break;
    case 'f': o.fragscan += 8; break;
    case 'g': 
      o.magic_port = atoi(optarg);
      o.magic_port_set = 1;
      if (!o.magic_port) fatal("-g needs nonzero argument");
      break;    
    case 'h': printusage(argv[0], 0); break;
    case '?': printusage(argv[0], -1); break;
    case 'I': 
      printf("WARNING: identscan (-I) no longer supported.  Ignoring -I\n");
      break;
      // o.identscan++; break;
    case 'i': 
      if (inputfd) {
	fatal("Only one input filename allowed");
      }
      if (!strcmp(optarg, "-")) {
	inputfd = stdin;
      } else {    
	inputfd = fopen(optarg, "r");
	if (!inputfd) {
	  fatal("Failed to open input file %s for reading", optarg);
	}  
      }
      break;  
    case 'M': 
      o.max_parallelism = atoi(optarg); 
      if (o.max_parallelism < 1) fatal("Argument to -M must be at least 1!");
      if (o.max_parallelism > 900) {
	error("Warning: Your max_parallelism (-M) option is absurdly high! Don't complain to Fyodor if all hell breaks loose!");
      }
      break;
    case 'm': 
      machinefilename = optarg;
      break;
    case 'n': o.noresolve++; break;
    case 'O': 
      o.osscan++; 
      break;
    case 'o':
      normalfilename = optarg;
      break;
    case 'P': 
      if (*optarg == '\0' || *optarg == 'I' || *optarg == 'E')
	o.pingtype |= PINGTYPE_ICMP_PING;
      else if (*optarg == 'M') 
	o.pingtype |= PINGTYPE_ICMP_MASK;
      else if (*optarg == 'P') 
	o.pingtype |= PINGTYPE_ICMP_TS;
      else if (*optarg == '0' || *optarg == 'N' || *optarg == 'D')      
	o.pingtype = PINGTYPE_NONE;
      else if (*optarg == 'R')
	o.pingtype |= PINGTYPE_ARP;
      else if (*optarg == 'S') {
	o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_SYN);
	if (isdigit((int) *(optarg+1)))
	  {
	    o.num_ping_synprobes = numberlist2array(optarg+1, o.ping_synprobes, sizeof(o.ping_synprobes), &proberr);
	    if (o.num_ping_synprobes < 0) {
	      fatal("Bogus argument to -PS: %s", proberr);
	    }
	  }
	if (o.num_ping_synprobes == 0) {
	  o.num_ping_synprobes = 1;
	  o.ping_synprobes[0] = DEFAULT_TCP_PROBE_PORT;
	}
      }
      else if (*optarg == 'T' || *optarg == 'A') {
	o.pingtype |= (PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK);
	if (isdigit((int) *(optarg+1))) {
	  o.num_ping_ackprobes = numberlist2array(optarg+1, o.ping_ackprobes, sizeof(o.ping_ackprobes), &proberr);
	  if (o.num_ping_ackprobes < 0) {
	    fatal("Bogus argument to -PB: %s", proberr);
	  }
	}
	if (o.num_ping_ackprobes == 0) {
	  o.num_ping_ackprobes = 1;
	  o.ping_ackprobes[0] = DEFAULT_TCP_PROBE_PORT;
	}
      }
      else if (*optarg == 'U') {
	o.pingtype |= (PINGTYPE_UDP);
	if (isdigit((int) *(optarg+1))) {
	  o.num_ping_udpprobes = numberlist2array(optarg+1, o.ping_udpprobes, sizeof(o.ping_udpprobes), &proberr);
	  if (o.num_ping_udpprobes < 0) {
	    fatal("Bogus argument to -PU: %s", proberr);
	  }
	}
	if (o.num_ping_udpprobes == 0) {
	  o.num_ping_udpprobes = 1;
	  o.ping_udpprobes[0] = DEFAULT_UDP_PROBE_PORT;
	}
      }
      else if (*optarg == 'B') {
	o.pingtype = (PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_ICMP_PING);
	if (isdigit((int) *(optarg+1))) {
	  o.num_ping_ackprobes = numberlist2array(optarg+1, o.ping_ackprobes, sizeof(o.ping_ackprobes), &proberr);
	  if (o.num_ping_ackprobes < 0) {
	    fatal("Bogus argument to -PB: %s", proberr);
	  }
	}
	if (o.num_ping_ackprobes == 0) {
	  o.num_ping_ackprobes = 1;
	  o.ping_ackprobes[0] = DEFAULT_TCP_PROBE_PORT;
	}
      } else if (*optarg == 'O') {
	fatal("-PO (the letter O)? No such option. Perhaps you meant to disable pings with -P0 (Zero).");
      } else { 
	fatal("Illegal Argument to -P, use -P0, -PI, -PB, -PE, -PM, -PP, -PA, -PU, -PT, or -PT80 (or whatever number you want for the TCP probe destination port)"); 
      }
      break;
    case 'p': 
      if (ports)
	fatal("Only 1 -p option allowed, separate multiple ranges with commas.");
      ports = getpts(optarg);
      if (!ports)
	fatal("Your port specification string is not parseable");
      break;
    case 'q': quashargv++; break;
    case 'R': resolve_all++; break;
    case 'r': 
      randomize = 0;
      break;
    case 'S': 
      if (o.spoofsource)
	fatal("You can only use the source option once!  Use -D <decoy1> -D <decoy2> etc. for decoys\n");
      if (resolve(optarg, &ss, &sslen, o.af()) == 0) {
	fatal("Failed to resolve/decode supposed %s source address %s. Note that if you are using IPv6, the -6 argument must come before -S", (o.af() == AF_INET)? "IPv4" : "IPv6", optarg);
      }
      o.setSourceSockAddr(&ss, sslen);
      o.spoofsource = 1;
      break;
    case 's': 
      if (!*optarg) {
	fprintf(stderr, "An option is required for -s, most common are -sT (tcp scan), -sS (SYN scan), -sF (FIN scan), -sU (UDP scan) and -sP (Ping scan)");
	printusage(argv[0], -1);
      }
      p = optarg;
      while(*p) {
	switch(*p) {
	case 'A': o.ackscan = 1; break;
	case 'B':  fatal("No scan type 'B', did you mean bounce scan (-b)?");
	  break;
	case 'F':  o.finscan = 1; break;
	case 'L':  o.listscan = 1; o.pingtype = PINGTYPE_NONE; break;
	case 'M':  o.maimonscan = 1; break;
	case 'N':  o.nullscan = 1; break;
	case 'O':  o.ipprotscan = 1; break;
	case 'P':  o.pingscan = 1; break;
	case 'R':  o.rpcscan = 1; break;
	case 'S':  o.synscan = 1; break;	  
	case 'W':  o.windowscan = 1; break;
	case 'T':  o.connectscan = 1; break;
	case 'V':  o.servicescan = 1; break;
	case 'U':  
	  o.udpscan++;
	  break;
	case 'X':  o.xmasscan++;break;
	default:  error("Scantype %c not supported\n",*p); printusage(argv[0], -1); break;
	}
	p++;
      }
      break;
    case 'T':
      if (*optarg == '0' || (strcasecmp(optarg, "Paranoid") == 0)) {
	o.timing_level = 0;
	o.max_parallelism = 1;
	o.scan_delay = 300000;
	o.setInitialRttTimeout(300000);
      } else if (*optarg == '1' || (strcasecmp(optarg, "Sneaky") == 0)) {
	o.timing_level = 1;
	o.max_parallelism = 1;
	o.scan_delay = 15000;
	o.setInitialRttTimeout(15000);
      } else if (*optarg == '2' || (strcasecmp(optarg, "Polite") == 0)) {
	o.timing_level = 2;
	o.max_parallelism = 1;
	o.scan_delay = 400;
      } else if (*optarg == '3' || (strcasecmp(optarg, "Normal") == 0)) {
      } else if (*optarg == '4' || (strcasecmp(optarg, "Aggressive") == 0)) {
	o.timing_level = 4;
	o.setMinRttTimeout(100);
	o.setMaxRttTimeout(1250);
	o.setInitialRttTimeout(500);
        o.setMaxTCPScanDelay(10);
      } else if (*optarg == '5' || (strcasecmp(optarg, "Insane") == 0)) {
	o.timing_level = 5;
	o.setMinRttTimeout(50);
	o.setMaxRttTimeout(300);
	o.setInitialRttTimeout(250);
	o.host_timeout = 900000;
        o.setMaxTCPScanDelay(5);
      } else {
	fatal("Unknown timing mode (-T argment).  Use either \"Paranoid\", \"Sneaky\", \"Polite\", \"Normal\", \"Aggressive\", \"Insane\" or a number from 0 (Paranoid) to 5 (Insane)");
      }
      break;
    case 'V': 
      printf("\n%s version %s ( %s )\n", NMAP_NAME, NMAP_VERSION, NMAP_URL); 
      exit(0);
      break;
    case 'v': o.verbose++; break;
    }
  }

#ifdef WIN32
  if (!skip_winip_init)
    winip_postopt_init();
#endif

#if HAVE_SIGNAL
  if (!o.debugging)
    signal(SIGSEGV, sigdie); 
#endif

  if (o.osscan)
    o.reference_FPs = parse_fingerprint_reference_file();

  o.ValidateOptions();

  /* Open the log files, now that we know whether the user wants them appended
     or overwritten */
  if (normalfilename)
    log_open(LOG_NORMAL, o.append_output, normalfilename);
  if (machinefilename)
    log_open(LOG_MACHINE, o.append_output, machinefilename);
  if (kiddiefilename)
    log_open(LOG_SKID, o.append_output, kiddiefilename);
  if (xmlfilename)
    log_open(LOG_XML, o.append_output, xmlfilename);

  if (!o.interactivemode) {
    char tbuf[128];
    struct tm *tm;
    time_t now = time(NULL);
    if (!(tm = localtime(&now))) 
      fatal("Unable to get current localtime()#!#");
    // ISO 8601 date/time -- http://www.cl.cam.ac.uk/~mgk25/iso-time.html 
    if (strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M %Z", tm) <= 0)
      fatal("Unable to properly format time");
    log_write(LOG_STDOUT|LOG_SKID, "\nStarting %s %s ( %s ) at %s\n", NMAP_NAME, NMAP_VERSION, NMAP_URL, tbuf);
    if (o.verbose && tm->tm_mon == 8 && tm->tm_mday == 1) {
      log_write(LOG_STDOUT|LOG_SKID, "Happy %dth Birthday to Nmap, may it live to be %d!\n", tm->tm_year - 97, tm->tm_year + 3 );
    }

  }

  if ((o.pingscan || o.listscan) && fastscan) {
    fatal("The fast scan (-F) is incompatible with ping scan");
  }

  if (fastscan && ports) {
    fatal("You can specify fast scan (-F) or explicitly select individual ports (-p), but not both");
  } else if (fastscan && o.ipprotscan) {
    ports = getfastprots();
  } else if (fastscan) {
    ports = getfastports(o.TCPScan(), o.UDPScan());
  }

  if ((o.pingscan || o.listscan) && ports) {
    fatal("You cannot use -F (fast scan) or -p (explicit port selection) with PING scan or LIST scan");
  }

  if (!ports) {
    if (o.ipprotscan) {
      ports = getdefaultprots();
    } else {
      ports = getdefaultports(o.TCPScan(), o.UDPScan());
    }
  }

  /* By now, we've got our port lists.  Give the user a warning if no 
   * ports are specified for the type of scan being requested.  Other things
   * (such as OS ident scan) might break cause no ports were specified,  but
   * we've given our warning...
   */
  if ((o.TCPScan()) && ports->tcp_count == 0)
    error("WARNING: a TCP scan type was requested, but no tcp ports were specified.  Skipping this scan type.");
  if (o.UDPScan() && ports->udp_count == 0)
    error("WARNING: UDP scan was requested, but no udp ports were specified.  Skipping this scan type.");
  if (o.ipprotscan && ports->prot_count == 0)
    error("WARNING: protocol scan was requested, but no protocols were specified to be scanned.  Skipping this scan type.");

  /* Set up our array of decoys! */
  if (o.decoyturn == -1) {
    o.decoyturn = (o.numdecoys == 0)?  0 : get_random_uint() % o.numdecoys; 
    o.numdecoys++;
    for(i=o.numdecoys-1; i > o.decoyturn; i--)
      o.decoys[i] = o.decoys[i-1];
  }

  /* We need to find what interface to route through if:
   * --None have been specified AND
   * --We are root and doing tcp ping OR
   * --We are doing a raw sock scan and NOT pinging anyone */
  if (o.af() == AF_INET && o.v4sourceip() && !*o.device) {
    if (ipaddr2devname(o.device, o.v4sourceip()) != 0) {
      fatal("Could not figure out what device to send the packet out on with the source address you gave me!  If you are trying to sp00f your scan, this is normal, just give the -e eth0 or -e ppp0 or whatever.  Otherwise you can still use -e, but I find it kindof fishy.");
    }
  }

  if (o.af() == AF_INET && *o.device && !o.v4sourceip()) {
    struct sockaddr_in tmpsock;
    memset(&tmpsock, 0, sizeof(tmpsock));
    if (devname2ipaddr(o.device, &(tmpsock.sin_addr)) == -1) {
      fatal("I cannot figure out what source address to use for device %s, does it even exist?", o.device);
    }
    tmpsock.sin_family = AF_INET;
#if HAVE_SOCKADDR_SA_LEN
    tmpsock.sin_len = sizeof(tmpsock);
#endif
    o.setSourceSockAddr((struct sockaddr_storage *) &tmpsock, sizeof(tmpsock));
  }


  /* If he wants to bounce off of an ftp site, that site better damn well be reachable! */
  if (o.bouncescan) {
    if (!inet_aton(ftp.server_name, &ftp.server)) {
      if ((target = gethostbyname(ftp.server_name)))
	memcpy(&ftp.server, target->h_addr_list[0], 4);
      else {
	fprintf(stderr, "Failed to resolve ftp bounce proxy hostname/IP: %s\n",
		ftp.server_name);
	exit(1);
      } 
    }  else if (o.verbose)
      log_write(LOG_STDOUT, "Resolved ftp bounce attack proxy to %s (%s).\n", 
		ftp.server_name, inet_ntoa(ftp.server)); 
  }
  fflush(stdout);
  fflush(stderr);

  timep = time(NULL);
  
  /* Brief info incase they forget what was scanned */
  Strncpy(mytime, ctime(&timep), sizeof(mytime));
  chomp(mytime);
  char *xslfname = o.XSLStyleSheet();
  char xslline[1024];
  if (xslfname) {
    char *p = xml_convert(xslfname);
    snprintf(xslline, sizeof(xslline), "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\n", p);
    free(p);
  }  else xslline[0] = '\0';
  log_write(LOG_XML, "<?xml version=\"1.0\" ?>\n%s<!-- ", xslline);
  log_write(LOG_NORMAL|LOG_MACHINE, "# ");
  log_write(LOG_NORMAL|LOG_MACHINE|LOG_XML, "%s %s scan initiated %s as: ", NMAP_NAME, NMAP_VERSION, mytime);
  
  for(i=0; i < argc; i++) {
    char *p = xml_convert(fakeargv[i]);
    log_write(LOG_XML,"%s ", p);
    free(p);
    log_write(LOG_NORMAL|LOG_MACHINE,"%s ", fakeargv[i]);
  }
  log_write(LOG_XML, "-->");
  log_write(LOG_NORMAL|LOG_MACHINE|LOG_XML,"\n");  

  log_write(LOG_XML, "<nmaprun scanner=\"nmap\" args=\"");
  for(i=0; i < argc; i++) 
    log_write(LOG_XML, (i == argc-1)? "%s\" " : "%s ", fakeargv[i]);

  log_write(LOG_XML, "start=\"%lu\" startstr=\"%s\" version=\"%s\" xmloutputversion=\"1.01\">\n",
	    (unsigned long) timep, mytime, NMAP_VERSION);

  output_xml_scaninfo_records(ports);

  log_write(LOG_XML, "<verbose level=\"%d\" />\n<debugging level=\"%d\" />\n",
	    o.verbose, o.debugging);

  /* Before we randomize the ports scanned, lets output them to machine 
     parseable output */
  if (o.verbose)
    output_ports_to_machine_parseable_output(ports, o.TCPScan(), o.udpscan, o.ipprotscan);

  /* more fakeargv junk, BTW malloc'ing extra space in argv[0] doesn't work */
  if (quashargv) {
    argvlen = strlen(argv[0]);
    if (argvlen < strlen(FAKE_ARGV))
      fatal("If you want me to fake your argv, you need to call the program with a longer name.  Try the full pathname, or rename it fyodorssuperdedouperportscanner");
    strncpy(argv[0], FAKE_ARGV, strlen(FAKE_ARGV));
    for(j = strlen(FAKE_ARGV); j < argvlen; j++) argv[0][j] = '\0';
    for(i=1; i < argc; i++) {
      argvlen = strlen(argv[i]);
      for(j=0; j <= argvlen; j++)
	argv[i][j] = '\0';
    }
  }

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
  signal(SIGPIPE, SIG_IGN); /* ignore SIGPIPE so our program doesn't crash because
			       of it, but we really shouldn't get an unsuspected
			       SIGPIPE */
#endif

  if (o.max_parallelism && (i = max_sd()) && i < o.max_parallelism) {
    fprintf(stderr, "WARNING:  Your specified max_parallel_sockets of %d, but your system says it might only give us %d.  Trying anyway\n", o.max_parallelism, i);
  }

  if (o.debugging > 1) log_write(LOG_STDOUT, "The max # of sockets we are using is: %d\n", o.max_parallelism);


  if  (randomize) {
    if (ports->tcp_count) {
      shortfry(ports->tcp_ports, ports->tcp_count); 
      // move a few more common ports closer to the beginning to speed scan
      random_port_cheat(ports->tcp_ports, ports->tcp_count);
    }
    if (ports->udp_count) 
      shortfry(ports->udp_ports, ports->udp_count); 
    if (ports->prot_count) 
      shortfry(ports->prots, ports->prot_count); 
  }
  
  starttime = time(NULL);
  
  /* Time to create a hostgroup state object filled with all the requested
     machines */
  host_exp_group = (char **) safe_malloc(o.ping_group_sz * sizeof(char *));

  /* lets load our exclude list */
  if ((NULL != excludefd) || (NULL != exclude_spec)) {
    exclude_group = load_exclude(excludefd, exclude_spec);

    if (o.debugging > 3)
      dumpExclude(exclude_group);

    if ((FILE *)NULL != excludefd)
      fclose(excludefd);
    if ((char *)NULL != exclude_spec)
      free(exclude_spec);
  }

  while(num_host_exp_groups < o.ping_group_sz &&
	(host_spec = grab_next_host_spec(inputfd, argc, fakeargv))) {
    host_exp_group[num_host_exp_groups++] = strdup(host_spec);
    // For purposes of random scan
    if (o.max_ips_to_scan && o.max_ips_to_scan <= numhosts_scanned + num_host_exp_groups)
      break;
  }

  if (num_host_exp_groups == 0)
    fatal("No target machines/networks specified!");
  hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,
			      host_exp_group, num_host_exp_groups);

  do {
    ideal_scan_group_sz = determineScanGroupSize(numhosts_scanned, ports);
    while(Targets.size() < ideal_scan_group_sz) {
      currenths = nexthost(hstate, exclude_group, ports, &(o.pingtype));
      if (!currenths) {
	/* Try to refill with any remaining expressions */
	/* First free the old ones */
	for(i=0; i < num_host_exp_groups; i++)
	  free(host_exp_group[i]);
	num_host_exp_groups = 0;
	/* Now grab any new expressions */
	while(num_host_exp_groups < o.ping_group_sz && 
	      (!o.max_ips_to_scan ||  o.max_ips_to_scan > numhosts_scanned + num_host_exp_groups) &&
	      (host_spec = grab_next_host_spec(inputfd, argc, fakeargv))) {
	  // For purposes of random scan
	  host_exp_group[num_host_exp_groups++] = strdup(host_spec);
	}
	if (num_host_exp_groups == 0)
	  break;
	delete hstate;
	hstate = new HostGroupState(o.ping_group_sz, o.randomize_hosts,
				    host_exp_group, num_host_exp_groups);
      
	/* Try one last time -- with new expressions */
	currenths = nexthost(hstate, exclude_group, ports, &(o.pingtype));
	if (!currenths)
	  break;
      }
      numhosts_scanned++;
    
      if (currenths->flags & HOST_UP && !o.listscan) 
	numhosts_up++;
    
      /* Lookup the IP */
      if (((currenths->flags & HOST_UP) || resolve_all) && !o.noresolve) {
	if (currenths->TargetSockAddr(&ss, &sslen) != 0)
	  fatal("Failed to get target socket address.");
	if (getnameinfo((struct sockaddr *)&ss, sslen, hostname, 
			sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0) {
	  currenths->setHostName(hostname);
	}
      }
    
      if (o.pingscan || o.listscan) {
	/* We're done with the hosts */
	log_write(LOG_XML, "<host>");
	write_host_status(currenths, resolve_all);
	printmacinfo(currenths);
	//	if (currenths->flags & HOST_UP)
	//  log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"\n");
	log_write(LOG_XML, "</host>\n");
	log_flush_all();
	delete currenths;
	continue;
      }
    
      if (o.spoofsource) {
	o.SourceSockAddr(&ss, &sslen);
	currenths->setSourceSockAddr(&ss, sslen);
      }
    
      /* I used to check that !currenths->wierd_responses, but in some
	 rare cases, such IPs CAN be port successfully scanned and even connected to */
      if (!(currenths->flags & HOST_UP)) {
	delete currenths;
	continue;
      }

      if (o.af() == AF_INET && o.RawScan()) { 
	if (currenths->SourceSockAddr(NULL, NULL) != 0) {
	  if (o.SourceSockAddr(&ss, &sslen) == 0) {
	    currenths->setSourceSockAddr(&ss, sslen);
	  } else {
	    if (gethostname(myname, MAXHOSTNAMELEN) || 
		resolve(myname, &ss, &sslen, o.af()) == 0)
	      fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n"); 
	    
	    o.setSourceSockAddr(&ss, sslen);
	    currenths->setSourceSockAddr(&ss, sslen);
	    if (! sourceaddrwarning) {
	      fprintf(stderr, "WARNING:  We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.\n", inet_socktop(&ss));
	      sourceaddrwarning = 1;
	    }
	  }
	}
	if (!*currenths->device)
	  if (ipaddr2devname( currenths->device, currenths->v4sourceip()) != 0)
	    fatal("Could not figure out what device to send the packet out on!  You might possibly want to try -S (but this is probably a bigger problem).  If you are trying to sp00f the source of a SYN/FIN scan with -S <fakeip>, then you must use -e eth0 (or other devicename) to tell us what interface to use.\n");
	
	/* Groups should generally use the same device as properties
	   change quite a bit between devices.  Plus dealing with a
	   multi-device group can be a pain programmatically. So if
	   this Target has a different device the rest, we give it
	   back. */
	if (Targets.size() > 0 && strcmp(Targets[Targets.size() - 1]->device, currenths->device)) {
	  returnhost(hstate);
	  numhosts_scanned--; numhosts_up--;
	  break;
	}
	o.decoys[o.decoyturn] = currenths->v4source();
      }
      Targets.push_back(currenths);
    }
    
    if (Targets.size() == 0)
      break; /* Couldn't find any more targets */
    
    // Our source must be set in decoy list because nexthost() call can
    // change it (that issue really should be fixed when possible)
    if (o.af() == AF_INET && o.RawScan())
      o.decoys[o.decoyturn] = Targets[0]->v4source();
    
    /* I now have the group for scanning in the Targets vector */
    /* TODO: Add parallel-capable scans here */
    if (o.synscan)
      ultra_scan(Targets, ports, SYN_SCAN);
    
    if (o.ackscan)
      ultra_scan(Targets, ports, ACK_SCAN);
    
    if (o.windowscan)
      ultra_scan(Targets, ports, WINDOW_SCAN);
    
    if (o.finscan)
      ultra_scan(Targets, ports, FIN_SCAN);
    
    if (o.xmasscan)
      ultra_scan(Targets, ports, XMAS_SCAN);
    
    if (o.nullscan)
      ultra_scan(Targets, ports, NULL_SCAN);
    
    if (o.maimonscan)
      ultra_scan(Targets, ports, MAIMON_SCAN);
    
    if (o.udpscan)
      ultra_scan(Targets, ports, UDP_SCAN);
    
    if (o.connectscan)
      ultra_scan(Targets, ports, CONNECT_SCAN);
    
    if (o.ipprotscan)
      ultra_scan(Targets, ports, IPPROT_SCAN);
    
    /* These lame functions can only handle one target at a time */
    for(targetno = 0; targetno < Targets.size(); targetno++) {
      currenths = Targets[targetno];
      if (o.idlescan) idle_scan(currenths, ports->tcp_ports, 
				ports->tcp_count, idleProxy);
      if (o.bouncescan) {
	if (ftp.sd <= 0) ftp_anon_connect(&ftp);
	if (ftp.sd > 0) bounce_scan(currenths, ports->tcp_ports, 
				    ports->tcp_count, &ftp);
      }
    }

    if (o.servicescan)
      service_scan(Targets);

    for(targetno = 0; targetno < Targets.size(); targetno++) {
      currenths = Targets[targetno];
    
      /* This scantype must be after any TCP or UDP scans since it
       * get's it's port scan list from the open port list of the current
       * host rather than port list the user specified.
       */
      if (o.servicescan || o.rpcscan)  pos_scan(currenths, NULL, 0, RPC_SCAN);

      // Should be host parallelized.  Though rarely takes a huge amt. of time.
      if (o.osscan) 
	os_scan(currenths);
      
    /* Now I can do the output and such for each host */
      log_write(LOG_XML, "<host>");
      write_host_status(currenths, resolve_all);
      if (currenths->timedOut(NULL)) {
	log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT,"Skipping host %s due to host timeout\n", 
		  currenths->NameIP(hostname, sizeof(hostname)));
	log_write(LOG_MACHINE,"Host: %s (%s)\tStatus: Timeout", 
		  currenths->targetipstr(), currenths->HostName());
      } else {
	printportoutput(currenths, &currenths->ports);
	printmacinfo(currenths);
	printosscanoutput(currenths);
      }
    
      if (o.debugging) 
	log_write(LOG_STDOUT, "Final times for host: srtt: %d rttvar: %d  to: %d\n", 
		  currenths->to.srtt, currenths->to.rttvar, currenths->to.timeout);
      log_write(LOG_NORMAL|LOG_SKID|LOG_STDOUT|LOG_MACHINE,"\n");
      log_write(LOG_XML, "</host>\n");
    }
    log_flush_all();
  
    /* Free all of the Targets */
    while(!Targets.empty()) {
      currenths = Targets.back();
      delete currenths;
      Targets.pop_back();
    }
  } while(!o.max_ips_to_scan || o.max_ips_to_scan > numhosts_scanned);
  
  delete hstate;
  if (exclude_group)
    delete[] exclude_group;

  hstate = NULL;

  /* Free host expressions */
  for(i=0; i < num_host_exp_groups; i++)
    free(host_exp_group[i]);
  num_host_exp_groups = 0;
  free(host_exp_group);

  printfinaloutput(numhosts_scanned, numhosts_up, starttime);

  if (ports) {
    free(ports->tcp_ports);
    free(ports->udp_ports);
    free(ports->prots);
    free(ports);
  }

  /* Free fake argv */
  for(i=0; i < argc; i++)
    free(fakeargv[i]);
  free(fakeargv);

  return 0;
}      
      

/* Reads in a (normal or machine format) Nmap log file and gathers enough
   state to allow Nmap to continue where it left off.  The important things
   it must gather are:
   1) The last host completed
   2) The command arguments
*/
   
int gather_logfile_resumption_state(char *fname, int *myargc, char ***myargv) {
  char *filestr;
  int filelen;
  char nmap_arg_buffer[1024];
  struct in_addr lastip;
  char *p, *q, *found; /* I love C! */
  /* We mmap it read/write since we will change the last char to a newline if it is not already */
  filestr = mmapfile(fname, &filelen, O_RDWR);
  if (!filestr) {
    fatal("Could not mmap() %s read/write", fname);
  }

  if (filelen < 20) {
    fatal("Output file %s is too short -- no use resuming", fname);
  }

  /* For now we terminate it with a NUL, but we will terminate the file with
     a '\n' later */
  filestr[filelen - 1] = '\0';

  /* First goal is to find the nmap args */
  p = strstr(filestr, " as: ");
  p += 5;
  while(*p && !isspace((int) *p))
    p++;
  if (!*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);
  p++; /* Skip the space between program name and first arg */
  if (*p == '\n' || !*p) fatal("Unable to parse supposed log file %s.  Sorry", fname);

  q = strchr(p, '\n');
  if (!q || ((unsigned int) (q - p) >= sizeof(nmap_arg_buffer) - 32))
    fatal("Unable to parse supposed log file %s.  Perhaps the Nmap execution had not finished at least one host?  In that case there is no use \"resuming\"", fname);


  strcpy(nmap_arg_buffer, "nmap --append_output ");
  if ((q-p) + 21 + 1 >= (int) sizeof(nmap_arg_buffer)) fatal("0verfl0w");
  memcpy(nmap_arg_buffer + 21, p, q-p);
  nmap_arg_buffer[21 + q-p] = '\0';

  if (strstr(nmap_arg_buffer, "--randomize_hosts") != NULL) {
    error("WARNING:  You are attempting to resume a scan which used --randomize_hosts.  Some hosts in the last randomized batch make be missed and others may be repeated once");
  }

  *myargc = arg_parse(nmap_arg_buffer, myargv);
  if (*myargc == -1) {  
    fatal("Unable to parse supposed log file %s.  Sorry", fname);
  }
     
  /* Now it is time to figure out the last IP that was scanned */
  q = p;
  found = NULL;
  /* Lets see if its a machine log first */
  while((q = strstr(q, "\nHost: ")))
    found = q = q + 7;

  if (found) {
    q = strchr(found, ' ');
    if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = '\0';
    if (inet_aton(found, &lastip) == 0)
      fatal("Unable to parse supposed log file %s.  Sorry", fname);
    *q = ' ';
  } else {
    /* OK, I guess (hope) it is a normal log then */
    q = p;
    found = NULL;
    while((q = strstr(q, "\nInteresting ports on ")))
      found = q++;

    /* There may be some later IPs of the form 'All [num] scanned ports on  ([ip]) are: state */
    if (found) q = found;
    if (q) {    
      while((q = strstr(q, "\nAll "))) {
	q+= 5;
	while(isdigit(*q)) q++;
	if (strncmp(q, " scanned ports on", 17) == 0)
	  found = q;
      }
    }

    if (found) {    
      found = strchr(found, '(');
      if (!found) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      found++;
      q = strchr(found, ')');
      if (!q) fatal("Unable to parse supposed log file %s.  Sorry", fname);
      *q = '\0';
      if (inet_aton(found, &lastip) == 0)
	fatal("Unable to parse ip (%s) supposed log file %s.  Sorry", found, fname);
      *q = ')';
    } else {
      error("Warning: You asked for --resume but it doesn't look like any hosts in the log file were successfully scanned.  Starting from the beginning.");
      lastip.s_addr = 0;
    }
  }
  o.resume_ip = lastip;

  /* Ensure the log file ends with a newline */
  filestr[filelen - 1] = '\n';
  munmap(filestr, filelen);
  return 0;
}

/* We set the socket lingering so we will RST connection instead of wasting
   bandwidth with the four step close  */
void init_socket(int sd) {
  struct linger l;
  int res;
  static int bind_failed=0;
  struct sockaddr_storage ss;
  size_t sslen;

  l.l_onoff = 1;
  l.l_linger = 0;

  if (setsockopt(sd, SOL_SOCKET, SO_LINGER,  (const char *) &l, sizeof(struct linger)))
    {
      fprintf(stderr, "Problem setting socket SO_LINGER, errno: %d\n", socket_errno());
      perror("setsockopt");
    }
  if (o.spoofsource && !bind_failed)
    {
      o.SourceSockAddr(&ss, &sslen);
      res=bind(sd, (struct sockaddr*)&ss, sslen);
      if (res<0)
	{
	  fprintf(stderr, "init_socket: Problem binding source address (%s), errno :%d\n", inet_socktop(&ss), socket_errno());
	  perror("bind");
	  bind_failed=1;
	}
    }
}

/* Convert a string like "-100,200-1024,3000-4000,60000-" into an array 
   of port numbers. Note that one trailing comma is OK -- this is actually
   useful for machine generated lists */
struct scan_lists *getpts(char *origexpr) {
  u8 *porttbl;
  int portwarning = 0; /* have we warned idiot about dup ports yet? */
  long rangestart = -2343242, rangeend = -9324423;
  char *current_range;
  char *endptr;
  int i;
  int tcpportcount = 0, udpportcount = 0, protcount = 0;
  struct scan_lists *ports;
  int range_type = SCAN_TCP_PORT|SCAN_UDP_PORT|SCAN_PROTOCOLS;

  porttbl = (u8 *) safe_zalloc(65536);

  current_range = origexpr;
  do {
    while(isspace((int) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */
    if (*current_range == 'T' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_TCP_PORT;
	continue;
    }
    if (*current_range == 'U' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_UDP_PORT;
	continue;
    }
    if (*current_range == 'P' && *++current_range == ':') {
	current_range++;
	range_type = SCAN_PROTOCOLS;
	continue;
    }
    if (*current_range == '-') {
      rangestart = 1;
    }
    else if (isdigit((int) *current_range)) {
      rangestart = strtol(current_range, &endptr, 10);
      if (rangestart < 0 || rangestart > 65535) {
	fatal("Ports to be scanned must be between 0 and 65535 inclusive");
      }
/*      if (rangestart == 0) {
	error("WARNING:  Scanning \"port 0\" is supported, but unusual.");
      } */
      current_range = endptr;
      while(isspace((int) *current_range)) current_range++;
    } else {
      fatal("Error #485: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,T:3000-4000,U:60000-\"");
    }
    /* Now I have a rangestart, time to go after rangeend */
    if (!*current_range || *current_range == ',') {
      /* Single port specification */
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',') {
	/* Ended with a -, meaning up until the last possible port */
	rangeend = 65535;
      } else if (isdigit((int) *current_range)) {
	rangeend = strtol(current_range, &endptr, 10);
	if (rangeend < 0 || rangeend > 65535) {
	  fatal("Ports to be scanned must be between 0 and 65535 inclusive");
	}
	current_range = endptr;
      } else {
	fatal("Error #486: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
      }
    } else {
	fatal("Error #487: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
    }

    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while(rangestart <= rangeend) {
      if (porttbl[rangestart] & range_type) {
	if (!portwarning) {
	  error("WARNING:  Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
	  portwarning++;
	} 
      } else {      
	if (range_type & SCAN_TCP_PORT)
	  tcpportcount++;
	if (range_type & SCAN_UDP_PORT)
	  udpportcount++;
	if (range_type & SCAN_PROTOCOLS && rangestart < 256)
	  protcount++;
	porttbl[rangestart] |= range_type;
      }
      rangestart++;
    }
    
    /* Find the next range */
    while(isspace((int) *current_range)) current_range++;
    if (*current_range && *current_range != ',') {
      fatal("Error #488: Your port specifications are illegal.  Example of proper form: \"-100,200-1024,3000-4000,60000-\"");
    }
    if (*current_range == ',')
      current_range++;
  } while(current_range && *current_range);

  if ( 0 == (tcpportcount + udpportcount + protcount))
    fatal("No ports specified -- If you really don't want to scan any ports use ping scan...");

  ports = (struct scan_lists *) safe_zalloc(sizeof(struct scan_lists));

  if (tcpportcount) {
    ports->tcp_ports = (unsigned short *)safe_zalloc(tcpportcount * sizeof(unsigned short));
  }
  if (udpportcount) {
    ports->udp_ports = (unsigned short *)safe_zalloc(udpportcount * sizeof(unsigned short));
  }
  if (protcount) {
    ports->prots = (unsigned short *)safe_zalloc(protcount * sizeof(unsigned short));
  }
  ports->tcp_count = tcpportcount;
  ports->udp_count = udpportcount;
  ports->prot_count = protcount;

  tcpportcount=0;
  udpportcount=0;
  protcount=0;
  for(i=0; i <= 65535; i++) {
    if (porttbl[i] & SCAN_TCP_PORT)
      ports->tcp_ports[tcpportcount++] = i;
    if (porttbl[i] & SCAN_UDP_PORT)
      ports->udp_ports[udpportcount++] = i;
    if (porttbl[i] & SCAN_PROTOCOLS && i < 256)
      ports->prots[protcount++] = i;
  }

  free(porttbl);
  return ports;
}

void printusage(char *name, int rc) {
#ifdef WIN32
#define WIN32_PRINTF "  --win_help Windows-specific features\n"
#else
#define WIN32_PRINTF
#endif
  printf(
	 "Nmap %s Usage: nmap [Scan Type(s)] [Options] <host or net list>\n"
	 "Some Common Scan Types ('*' options require root privileges)\n"
	 "* -sS TCP SYN stealth port scan (default if privileged (root))\n"
	 "  -sT TCP connect() port scan (default for unprivileged users)\n"
	 "* -sU UDP port scan\n"
	 "  -sP ping scan (Find any reachable machines)\n"
	 "* -sF,-sX,-sN Stealth FIN, Xmas, or Null scan (experts only)\n"
         "  -sV Version scan probes open ports determining service & app names/versions\n"
	 "  -sR RPC scan (use with other scan types)\n"
	 "Some Common Options (none are required, most can be combined):\n"
	 "* -O Use TCP/IP fingerprinting to guess remote operating system\n"
	 "  -p <range> ports to scan.  Example range: 1-1024,1080,6666,31337\n"
	 "  -F Only scans ports listed in nmap-services\n"
	 "  -v Verbose. Its use is recommended.  Use twice for greater effect.\n"
	 "  -P0 Don't ping hosts (needed to scan www.microsoft.com and others)\n"
	 "* -Ddecoy_host1,decoy2[,...] Hide scan using many decoys\n"
         "  -6 scans via IPv6 rather than IPv4\n"
	 "  -T <Paranoid|Sneaky|Polite|Normal|Aggressive|Insane> General timing policy\n"
	 "  -n/-R Never do DNS resolution/Always resolve [default: sometimes resolve]\n"
	 "  -oN/-oX/-oG <logfile> Output normal/XML/grepable scan logs to <logfile>\n"
	 "  -iL <inputfile> Get targets from file; Use '-' for stdin\n"
	 "* -S <your_IP>/-e <devicename> Specify source address or network interface\n"
	 "  --interactive Go into interactive mode (then press h for help)\n"
         WIN32_PRINTF
	 "Example: nmap -v -sS -O www.my.com 192.168.0.0/16 '192.88-90.*.*'\n"
	 "SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES \n", NMAP_VERSION);
  exit(rc);
}

void printinteractiveusage() {
  printf(
	 "Nmap Interactive Commands:\n\
n <nmap args> -- executes an nmap scan using the arguments given and\n\
waits for nmap to finish.  Results are printed to the\n\
screen (of course you can still use file output commands).\n\
! <command>   -- runs shell command given in the foreground\n\
x             -- Exit Nmap\n\
f [--spoof <fakeargs>] [--nmap_path <path>] <nmap args>\n\
-- Executes nmap in the background (results are NOT\n\
printed to the screen).  You should generally specify a\n\
file for results (with -oX, -oG, or -oN).  If you specify\n\
fakeargs with --spoof, Nmap will try to make those\n\
appear in ps listings.  If you wish to execute a special\n\
version of Nmap, specify --nmap_path.\n\
n -h          -- Obtain help with Nmap syntax\n\
h             -- Prints this help screen.\n\
Examples:\n\
n -sS -O -v example.com/24\n\
f --spoof \"/usr/local/bin/pico -z hello.c\" -sS -oN e.log example.com/24\n\n");
}

char *seqreport(struct seq_info *seq) {
  static char report[512];
  char tmp[256];
  char *p;
  int i;

  snprintf(report, sizeof(report), "TCP Sequence Prediction: Class=%s\n                         Difficulty=%d (%s)\n", seqclass2ascii(seq->seqclass), seq->index, seqidx2difficultystr(seq->index));
  if (o.verbose > 1 || o.debugging ) {
    p = tmp;
    strcpy(p, "TCP ISN Seq. Numbers: ");
    p += 22;
    for(i=0; i < seq->responses; i++) {
      if (p - tmp + 20 > ((int) sizeof(tmp)))
	fatal("0verfl0w Error #234112");
      p += snprintf(p, 16, "%X ", seq->seqs[i]);
    }
    *--p = '\n';
    strcat(report, tmp);
  }
  return report;
}

/* Convert a TCP sequence prediction difficulty index like 1264386
   into a difficulty string like "Worthy Challenge */
const char *seqidx2difficultystr(unsigned long idx) {
  return  (idx < 10)? "Trivial joke" : (idx < 80)? "Easy" : (idx < 3000)? "Medium" : (idx < 5000)? "Formidable" : (idx < 100000)? "Worthy challenge" : "Good luck!";
}

char *seqclass2ascii(int seqclass) {
  switch(seqclass) {
  case SEQ_CONSTANT:
    return "constant sequence number (!)";
  case SEQ_64K:
    return "64K rule";
  case SEQ_TD:
    return "trivial time dependency";
  case SEQ_i800:
    return "increments by 800";
  case SEQ_RI:
    return "random positive increments";
  case SEQ_TR:
    return "truly random";
  case SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "ERROR, WTF?";
  }
}

char *ipidclass2ascii(int seqclass) {
  switch(seqclass) {
  case IPID_SEQ_CONSTANT:
    return "Duplicated ipid (!)";
  case IPID_SEQ_INCR:
    return "Incremental";
  case IPID_SEQ_BROKEN_INCR:
    return "Broken little-endian incremental";
  case IPID_SEQ_RD:
    return "Randomized";
  case IPID_SEQ_RPI:
    return "Random positive increments";
  case IPID_SEQ_ZERO:
    return "All zeros";
  case IPID_SEQ_UNKNOWN:
    return "Busy server or unknown class";
  default:
    return "ERROR, WTF?";
  }
}

char *tsseqclass2ascii(int seqclass) {
  switch(seqclass) {
  case TS_SEQ_ZERO:
    return "zero timestamp";
  case TS_SEQ_2HZ:
    return "2HZ";
  case TS_SEQ_100HZ:
    return "100HZ";
  case TS_SEQ_1000HZ:
    return "1000HZ";
  case TS_SEQ_UNSUPPORTED:
    return "none returned (unsupported)";
  case TS_SEQ_UNKNOWN:
    return "unknown class";
  default:
    return "ERROR, WTF?";
  }
}


/**
 * Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 *
 * We try to optimize speed when ordering the tests. This optimization
 * assumes that all byte values are equally likely in the input.
 *
 * Warning: This function could easily become outdated if the IANA
 * starts to assign some more IPv4 ranges to RIPE, etc. as they have
 * started doing this year (2001), for example 80.0.0.0/4 used to be
 * completely unassigned until they gave 80.0.0.0/7 to RIPE in April
 * 2001 (www.junk.org is an example of a new address in this range).
 *
 * Check <http://www.iana.org/assignments/ipv4-address-space> for
 * the most recent assigments.
 */

int ip_is_reserved(struct in_addr *ip)
{
  char *ipc = (char *) &(ip->s_addr);
  unsigned char i1 = ipc[0], i2 = ipc[1], i3 = ipc[2], i4 = ipc[3];

  /* 224-239/8 is all multicast stuff */
  /* 240-255/8 is IANA reserved */
  if (i1 >= 224)
    return 1;

  /* 096-123/8 is IANA reserved */
  /* 127/8 is reserved for loopback */
  if (i1 >= 96 && i1 <= 123)
    return 1;

  /* 073-079/8 is IANA reserved */
  if (i1 >= 73 && i1 <= 79)
    return 1;

  /* 089-095/8 is IANA reserved */
  if (i1 >= 83 && i1 <= 95)
    return 1;

  /* do all the /7's and /8's with a big switch statement, hopefully the
   * compiler will be able to optimize this a little better using a jump table
   * or what have you
   */
  switch (i1)
    {
    case 0:         /* 000/8 is IANA reserved       */
    case 1:         /* 001/8 is IANA reserved       */
    case 2:         /* 002/8 is IANA reserved       */
    case 5:         /* 005/8 is IANA reserved       */
    case 6:         /* USA Army ISC                 */
    case 7:         /* used for BGP protocol        */
    case 10:        /* the infamous 10.0.0.0/8      */
    case 23:        /* 023/8 is IANA reserved       */
    case 27:        /* 027/8 is IANA reserved       */
    case 31:        /* 031/8 is IANA reserved       */
    case 36:        /* 036/8 is IANA reserved       */
    case 37:        /* 037/8 is IANA reserved       */
    case 39:        /* 039/8 is IANA reserved       */
    case 41:        /* 041/8 is IANA reserved       */
    case 42:        /* 042/8 is IANA reserved       */
    case 55:        /* misc. U.S.A. Armed forces    */
    case 197:
      return 1;
    default:
      break;
    }

  /* 172.16.0.0/12 is reserved for private nets by RFC1819 */
  if (i1 == 172 && i2 >= 16 && i2 <= 31)
    return 1;

  /* 192.168.0.0/16 is reserved for private nets by RFC1819 */
  /* 192.0.2.0/24 is reserved for documentation and examples */
  if (i1 == 192) {
    if (i2 == 168)
      return 1;
    else if (i2 == 0 && i3 == 2)
      return 1;
  }

  /* reserved for DHCP clients seeking addresses, not routable outside LAN */
  if (i1 == 169 && i2 == 254)
    return 1;

  /* believe it or not, 204.152.64.0/23 is some bizarre Sun proprietary
   * clustering thing */
  if (i1 == 204 && i2 == 152 && (i3 == 64 || i3 == 65))
    return 1;

  /* 255.255.255.255, note we already tested for i1 in this range */
  if (i2 == 255 && i3 == 255 && i4 == 255)
    return 1;

  return 0;

}

char *grab_next_host_spec(FILE *inputfd, int argc, char **fakeargv) {
  static char host_spec[1024];
  unsigned int host_spec_index;
  int ch;
  struct in_addr ip;

  if (o.generate_random_ips) {
    do {
      ip.s_addr = get_random_u32();
    } while (ip_is_reserved(&ip));
    strcpy(host_spec, inet_ntoa(ip));
  } else if (!inputfd) {
    return( (optind < argc)?  fakeargv[optind++] : NULL);
  } else { 
    host_spec_index = 0;
    while((ch = getc(inputfd)) != EOF) {
      if (ch == ' ' || ch == '\n' || ch == '\t' || ch == '\0') {
	if (host_spec_index == 0) continue;
	host_spec[host_spec_index] = '\0';
	return host_spec;
      } else if (host_spec_index < sizeof(host_spec) / sizeof(char) -1) {
	host_spec[host_spec_index++] = (char) ch;
      } else fatal("One of the host_specifications from your input file is too long (> %d chars)", (int) sizeof(host_spec));
    }
    host_spec[host_spec_index] = '\0';
  }
  if (!*host_spec) return NULL;
  return host_spec;
}

/* Just a routine for obtaining a string for printing based on the scantype */
char *scantype2str(stype scantype) {

  switch(scantype) {
  case ACK_SCAN: return "ACK Scan"; break;
  case SYN_SCAN: return "SYN Stealth Scan"; break;
  case FIN_SCAN: return "FIN Scan"; break;
  case XMAS_SCAN: return "XMAS Scan"; break;
  case UDP_SCAN: return "UDP Scan"; break;
  case CONNECT_SCAN: return "Connect() Scan"; break;
  case NULL_SCAN: return "NULL Scan"; break;
  case WINDOW_SCAN: return "Window Scan"; break;
  case RPC_SCAN: return "RPCGrind Scan"; break;
  case MAIMON_SCAN: return "Maimon Scan"; break;
  case IPPROT_SCAN: return "IPProto Scan"; break;
  case PING_SCAN: return "Ping Scan"; break;
  case PING_SCAN_ARP: return "ARP Ping Scan"; break;
  default: assert(0); break;
  }

  return NULL; /* Unreached */

}

char *statenum2str(int state) {
  switch(state) {
  case PORT_OPEN: return "open"; break;
  case PORT_FILTERED: return "filtered"; break;
  case PORT_UNFILTERED: return "UNfiltered"; break;
  case PORT_CLOSED: return "closed"; break;
  case PORT_OPENFILTERED: return "open|filtered"; break;
  case PORT_CLOSEDFILTERED: return "closed|filtered"; break;
  default: return "unknown"; break;
  }
  return "unknown";
}

int ftp_anon_connect(struct ftpinfo *ftp) {
  int sd;
  struct sockaddr_in sock;
  int res;
  char recvbuf[2048];
  char command[512];

  if (o.verbose || o.debugging) 
    log_write(LOG_STDOUT, "Attempting connection to ftp://%s:%s@%s:%i\n", ftp->user, ftp->pass,
	      ftp->server_name, ftp->port);

  if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("Couldn't create ftp_anon_connect socket");
    return 0;
  }

  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = ftp->server.s_addr;
  sock.sin_port = htons(ftp->port); 
  res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in));
  if (res < 0 ) {
    fprintf(stderr, "Your ftp bounce proxy server won't talk to us!\n");
    exit(1);
  }
  if (o.verbose || o.debugging) log_write(LOG_STDOUT, "Connected:");
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,7, NULL)) > 0) 
    if (o.debugging || o.verbose) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }

  snprintf(command, 511, "USER %s\r\n", ftp->user);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12, NULL);
  if (res <= 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }
  recvbuf[res] = '\0';
  if (o.debugging) log_write(LOG_STDOUT, "sent username, received: %s", recvbuf);
  if (recvbuf[0] == '5') {
    fprintf(stderr, "Your ftp bounce server doesn't like the username \"%s\"\n", 
	    ftp->user);
    exit(1);
  }

  snprintf(command, 511, "PASS %s\r\n", ftp->pass);

  send(sd, command, strlen(command), 0);
  res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,12, NULL);
  if (res < 0) {
    perror("recv problem from ftp bounce server\n");
    exit(1);
  }
  if (!res) fprintf(stderr, "Timeout from bounce server ...");
  else {
    recvbuf[res] = '\0';
    if (o.debugging) log_write(LOG_STDOUT, "sent password, received: %s", recvbuf);
    if (recvbuf[0] == '5') {
      fprintf(stderr, "Your ftp bounce server refused login combo (%s/%s)\n",
	      ftp->user, ftp->pass);
      exit(1);
    }
  }
  while ((res = recvtime(sd, recvbuf, sizeof(recvbuf) - 1,2, NULL)) > 0) 
    if (o.debugging) {
      recvbuf[res] = '\0';
      log_write(LOG_STDOUT, "%s", recvbuf);
    }
  if (res < 0) {
    perror("recv problem from ftp bounce server");
    exit(1);
  }
  if (o.verbose) log_write(LOG_STDOUT, "Login credentials accepted by ftp server!\n");

  ftp->sd = sd;
  return sd;
}

#ifndef WIN32

void reaper(int signo) {
  int status;
  pid_t pid;

  if ((pid = wait(&status)) == -1) {
    gh_perror("waiting to reap child");
  } else {
    fprintf(stderr, "\n[%d finished status=%d (%s)]\nnmap> ", (int) pid, status, (status == 0)? "success"  : "failure");
  }
}
#endif

void sigdie(int signo) {
  int abt = 0;

  switch(signo) {
  case SIGINT:
    fprintf(stderr, "caught SIGINT signal, cleaning up\n");
    break;

#ifdef SIGTERM
  case SIGTERM:
    fprintf(stderr, "caught SIGTERM signal, cleaning up\n");
    break;
#endif

#ifdef SIGHUP
  case SIGHUP:
    fprintf(stderr, "caught SIGHUP signal, cleaning up\n");
    break;
#endif

#ifdef SIGSEGV
  case SIGSEGV:
    fprintf(stderr, "caught SIGSEGV signal, cleaning up\n");
    abt = 1;
    break;
#endif

#ifdef SIGBUS
  case SIGBUS:
    fprintf(stderr, "caught SIGBUS signal, cleaning up\n");
    abt = 1;
    break;
#endif

  default:
    fprintf(stderr, "caught signal %d, cleaning up\n", signo);
    abt = 1;
    break;
  }
  fflush(stdout);
  fflush(stderr);
  log_close(LOG_MACHINE|LOG_NORMAL|LOG_SKID);
  if (abt) abort();
  exit(1);
}


int nmap_fetchfile(char *filename_returned, int bufferlen, char *file) {
  char *dirptr;
  int res;
  int foundsomething = 0;
  struct passwd *pw;
  char dot_buffer[512];
  static int warningcount = 0;

  /* First we try [--datadir]/file, then $NMAPDIR/file
     next we try ~user/nmap/file
     then we try NMAPDATADIR/file <--NMAPDATADIR 
     finally we try ./file

	 -- or on Windows --

	 --datadir -> $NMAPDIR -> nmap.exe directory -> NMAPDATADIR -> .
  */

  if (o.datadir) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", o.datadir, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }

  if (!foundsomething && (dirptr = getenv("NMAPDIR"))) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", dirptr, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }
#ifndef WIN32
  if (!foundsomething) {
    pw = getpwuid(getuid());
    if (pw) {
      res = snprintf(filename_returned, bufferlen, "%s/.nmap/%s", pw->pw_dir, file);
      if (res > 0 && res < bufferlen) {
	if (fileexistsandisreadable(filename_returned))
	  foundsomething = 1;
      }
    }
    if (!foundsomething && getuid() != geteuid()) {
      pw = getpwuid(geteuid());
      if (pw) {
	res = snprintf(filename_returned, bufferlen, "%s/.nmap/%s", pw->pw_dir, file);
	if (res > 0 && res < bufferlen) {
	  if (fileexistsandisreadable(filename_returned))
	    foundsomething = 1;
	}
      }
    }
  }
#else
  if (!foundsomething) { /* Try the nMap directory */
	  char fnbuf[MAX_PATH];
	  int i;
	  res = GetModuleFileName(GetModuleHandle(0), fnbuf, 1024);
      if(!res) fatal("GetModuleFileName failed (!)\n");
	  /*	Strip it */
	  for(i = res - 1; i >= 0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--);
	  if(i >= 0) /* we found it */
		  fnbuf[i] = 0;
	  res = snprintf(filename_returned, bufferlen, "%s/%s", fnbuf, file);
	  if(res > 0 && res < bufferlen) {
		  if (fileexistsandisreadable(filename_returned))
            foundsomething = 1;
      }
  }
#endif
  if (!foundsomething) {
    res = snprintf(filename_returned, bufferlen, "%s/%s", NMAPDATADIR, file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }
  if (foundsomething && (*filename_returned != '.')) {    
    res = snprintf(dot_buffer, sizeof(dot_buffer), "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(dot_buffer)) {
#ifdef WIN32
	if (warningcount++ < 1 && o.debugging)
#else
	if(warningcount++ < 1)
#endif
	  error("Warning: File %s exists, but Nmap is using %s for security and consistency reasons.  set NMAPDIR=. to give priority to files in your local directory (may affect the other data files too).", dot_buffer, filename_returned);
      }
    }
  }

  if (!foundsomething) {
    res = snprintf(filename_returned, bufferlen, "./%s", file);
    if (res > 0 && res < bufferlen) {
      if (fileexistsandisreadable(filename_returned))
	foundsomething = 1;
    }
  }

  if (!foundsomething) {
    filename_returned[0] = '\0';
    return -1;
  }

  if (o.debugging > 1)
    error("Fetchfile found %s\n", filename_returned);

  return 0;

}

int fileexistsandisreadable(char *pathname) {
  FILE *fp;
  /* We check this the easy way! */
  fp = fopen(pathname, "r");
  if (fp) fclose(fp);
  return (fp == NULL)? 0 : 1;
}

