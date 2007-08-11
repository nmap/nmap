
/***************************************************************************
 * utils.cc -- Various miscellaneous utility functions which defy          *
 * categorization :)                                                       *
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

#include "nmap.h"
#include "utils.h"
#include "NmapOps.h"

extern NmapOps o;



/* Test a wildcard mask against a test string. Wildcard mask
 * can include '*' and '?' which work the same as they do
 * in /bin/sh (except it's case insensitive)
 * Return val of 1 means it DID match. 0 means it DIDN'T
 * - Doug Hoyte, 2005
 */

int wildtest(char *wild, char *test) {

  int i;

  while(*wild != '\0'  ||  *test != '\0') {
    if (*wild == '*') {

      /* --- Deal with multiple asterisks. --- */
      while (wild[1] == '*') wild++;

      /* --- Deal with terminating asterisks. --- */
      if (wild[1] == '\0') return 1;

      for(i=0; test[i]!='\0'; i++)
        if ((tolower((int)wild[1]) == tolower((int)test[i]) || wild[1] == '?')
            &&  wildtest(wild+1, test+i) == 1) return 1;

      return 0;
    }

    /* --- '?' can't match '\0'. --- */
    if (*wild == '?' && *test == '\0') return 0;

    if (*wild != '?' && tolower((int)*wild) != tolower((int)*test)) return 0;
    wild++; test++;
  }

  if (tolower((int)*wild) == tolower((int)*test)) return 1;
  return 0;

}



/* Hex dump */
void hdump(unsigned char *packet, unsigned int len) {
unsigned int i=0, j=0;

log_write(LOG_PLAIN, "Here it is:\n");

for(i=0; i < len; i++){
  j = (unsigned) (packet[i]);
  log_write(LOG_PLAIN, "%-2X ", j);
  if (!((i+1)%16))
    log_write(LOG_PLAIN, "\n");
  else if (!((i+1)%4))
    log_write(LOG_PLAIN, "  ");
}
log_write(LOG_PLAIN, "\n");
}

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@insecure.org) */
void lamont_hdump(char *cp, unsigned int length) {

  /* stolen from tcpdump, then kludged extensively */

  static const char asciify[] = "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

  const u_short *sp;
  const u_char *ap;
  unsigned char *bp = (unsigned char *) cp;
  u_int i, j;
  int nshorts, nshorts2;
  int padding;
  
  log_write(LOG_PLAIN, "\n\t");
  padding = 0;
  sp = (u_short *)bp;
  ap = (u_char *)bp;
  nshorts = (u_int) length / sizeof(u_short);
  nshorts2 = (u_int) length / sizeof(u_short);
  i = 0;
  j = 0;
  while(1) {
    while (--nshorts >= 0) {
      log_write(LOG_PLAIN, " %04x", ntohs(*sp));
      sp++;
      if ((++i % 8) == 0)
        break;
    }
    if (nshorts < 0) {
      if ((length & 1) && (((i-1) % 8) != 0)) {
        log_write(LOG_PLAIN, " %02x  ", *(u_char *)sp);
        padding++;
      }
      nshorts = (8 - (nshorts2 - nshorts));
      while(--nshorts >= 0) {
        log_write(LOG_PLAIN, "     ");
      }
      if (!padding) log_write(LOG_PLAIN, "     ");
    }
    log_write(LOG_PLAIN, "  ");

    while (--nshorts2 >= 0) {
      log_write(LOG_PLAIN, "%c%c", asciify[*ap], asciify[*(ap+1)]);
      ap += 2;
      if ((++j % 8) == 0) {
        log_write(LOG_PLAIN, "\n\t");
        break;
      }
    }
    if (nshorts2 < 0) {
      if ((length & 1) && (((j-1) % 8) != 0)) {
        log_write(LOG_PLAIN, "%c", asciify[*ap]);
      }
      break;
    }
  }
  if ((length & 1) && (((i-1) % 8) == 0)) {
    log_write(LOG_PLAIN, " %02x", *(u_char *)sp);
    log_write(LOG_PLAIN, "                                       %c", asciify[*ap]);
  }
  log_write(LOG_PLAIN, "\n");
}

#ifndef HAVE_STRERROR
char *strerror(int errnum) {
  static char buf[1024];
  sprintf(buf, "your system is too old for strerror of errno %d\n", errnum);
  return buf;
}
#endif

/* Like the perl equivalent -- It removes the terminating newline from string
   IF one exists.  It then returns the POSSIBLY MODIFIED string */
char *chomp(char *string) {
  int len = strlen(string);
  if (len && string[len - 1] == '\n') {
    if (len > 1 && string[len - 2] == '\r')
      string[len - 2] = '\0';
    else
      string[len - 1] = '\0';
  }
  return string;
}

/* Compare a canonical option name (e.g. "max-scan-delay") with a
   user-generated option such as "max_scan_delay" and returns 0 if the
   two values are considered equivalant (for example, - and _ are
   considered to be the same), nonzero otherwise. */
int optcmp(const char *a, const char *b) {
  while(*a && *b) {
    if (*a == '_' || *a == '-') {
      if (*b != '_' && *b != '-')
	return 1;
    }
    else if (*a != *b)
      return 1;
    a++; b++;
  }
  if (*a || *b)
    return 1;
  return 0;
}

/* Convert a comma-separated list of ASCII u16-sized numbers into the
   given 'dest' array, which is of total size (meaning sizeof() as
   opposed to numelements) of destsize.  If min_elem and max_elem are
   provided, each number must be within (or equal to) those
   constraints.  The number of numbers stored in 'dest' is returned,
   except that -1 is returned in the case of an error. If -1 is
   returned and errorstr is non-null, *errorstr is filled with a ptr to a
   static string literal describing the error. */

int numberlist2array(char *expr, u16 *dest, int destsize, char **errorstr, u16 min_elem, u16 max_elem) {
  char *current_range;
  char *endptr;
  char *errbogus;
  long val;
  int max_vals = destsize / 2;
  int num_vals_saved = 0;
  current_range = expr;

  if (!errorstr)
    errorstr = &errbogus;

  if (destsize % 2 != 0) {
    *errorstr = "Bogus call to numerlist2array() -- destsize must be a multiple of 2";
    return -1;
  }

  if (!expr || !*expr)
    return 0;

  do {
    if (num_vals_saved == max_vals) {
      *errorstr = "Buffer would overflow -- too many numbers in provided list";
      return -1;
    }
    if( !isdigit((int) *current_range) ) {
      *errorstr = "Alleged number begins with nondigit!  Example of proper form: \"20,80,65532\"";
      return -1;
    }
    val = strtol(current_range, &endptr, 10);
    if( val < min_elem || val > max_elem ) {
      *errorstr = "Number given in list is outside given legal range";
      return -1;
    }
    dest[num_vals_saved++] = (u16) val;
    current_range = endptr;
    while (*current_range == ',' || isspace(*current_range))
      current_range++;
    if (*current_range && !isdigit(*current_range)) {
      *errorstr = "Bogus character in supposed number-list string. Example of proper form: \"20,80,65532\"";
      return -1;
    }
  } while( current_range && *current_range);

  return num_vals_saved;
}

/* Scramble the contents of an array*/
void genfry(unsigned char *arr, int elem_sz, int num_elem) {
int i;
unsigned int pos;
unsigned char *bytes;
unsigned char *cptr;
unsigned short *sptr;
unsigned int *iptr;
unsigned char *tmp;
int bpe;

if (sizeof(unsigned char) != 1)
  fatal("%s() requires 1 byte chars", __func__);

if (num_elem < 2)
  return;

 if (elem_sz == sizeof(unsigned short)) {
   shortfry((unsigned short *)arr, num_elem);
   return;
 }

/* OK, so I am stingy with the random bytes! */
if (num_elem < 256) 
  bpe = sizeof(unsigned char);
else if (num_elem < 65536)
  bpe = sizeof(unsigned short);
else bpe = sizeof(unsigned int);

bytes = (unsigned char *) safe_malloc(bpe * num_elem);
tmp = (unsigned char *) safe_malloc(elem_sz);

get_random_bytes(bytes, bpe * num_elem);
cptr = bytes;
sptr = (unsigned short *)bytes;
iptr = (unsigned int *) bytes;

 for(i=num_elem - 1; i > 0; i--) {
   if (num_elem < 256) {
     pos = *cptr; cptr++;
   }
   else if (num_elem < 65536) {
     pos = *sptr; sptr++;
   } else {
     pos = *iptr; iptr++;
   }
   pos %= i+1;
   memcpy(tmp, arr + elem_sz * i, elem_sz);
   memcpy(arr + elem_sz * i, arr + elem_sz * pos, elem_sz);
   memcpy(arr + elem_sz * pos, tmp, elem_sz);
 }
 free(bytes);
 free(tmp);
}

void shortfry(unsigned short *arr, int num_elem) {
int num;
unsigned short tmp;
int i;

if (num_elem < 2)
  return;
 
 for(i= num_elem - 1; i > 0 ; i--) {
   num = get_random_ushort() % (i + 1);
   if (i == num) continue;
   tmp = arr[i];
   arr[i] = arr[num];
   arr[num] = tmp;
 } 

 return;
}

// Send data to a socket, keep retrying until an error or the full length
// is sent.  Returns -1 if there is an error, or len if the full length was sent.
int Send(int sd, const void *msg, size_t len, int flags) {
  int res;
  unsigned int sentlen = 0;

  do {
    res = send(sd,(char *) msg + sentlen, len - sentlen, 0);
    if (res > 0)
      sentlen += res;
  } while(sentlen < len && (res != -1 || socket_errno() == EINTR));

  return (res < 0)? -1 : (int) len;
}

unsigned int gcd_n_uint(int nvals, unsigned int *val)
 {
   unsigned int a,b,c;
   
   if (!nvals) return 1;
   a=*val;
   for (nvals--;nvals;nvals--)
     {
       b=*++val;
       if (a<b) { c=a; a=b; b=c; }
       while (b) { c=a%b; a=b; b=c; }
     }
   return a;
 }

/* This function takes a command and the address of an uninitialized
   char ** .  It parses the command (by separating out whitespace)
   into an argv[] style char **, which it sets the argv parameter to.
   The function returns the number of items filled up in the array
   (argc), or -1 in the case of an error.  This function allocates
   memory for argv and thus it must be freed -- use argv_parse_free()
   for that.  If arg_parse returns <1, then argv does not need to be freed.
   The returned arrays are always terminated with a NULL pointer */
int arg_parse(const char *command, char ***argv) {
  char **myargv = NULL;
  int argc = 0;
  char mycommand[4096];
  char *start, *end;
  char oldend;

  *argv = NULL;
  if (Strncpy(mycommand, command, 4096) == -1) {      
    return -1;
  }
  myargv = (char **) safe_malloc((MAX_PARSE_ARGS + 2) * sizeof(char *));
  memset(myargv, 0, (MAX_PARSE_ARGS+2) * sizeof(char *));
  myargv[0] = (char *) 0x123456; /* Integrity checker */
  myargv++;
  start = mycommand;
  while(start && *start) {
    while(*start && isspace((int) *start))
      start++;
    if (*start == '"') {
      start++;
      end = strchr(start, '"');
    } else if (*start == '\'') {
      start++;
      end = strchr(start, '\'');      
    } else if (!*start) {
      continue;
    } else {
      end = start+1;
      while(*end && !isspace((int) *end)) {      
	end++;
      }
    }
    if (!end) {
      arg_parse_free(myargv);
      return -1;
    }
    if (argc >= MAX_PARSE_ARGS) {
      arg_parse_free(myargv);
      return -1;
    }
    oldend = *end;
    *end = '\0';
    myargv[argc++] = strdup(start);
    if (oldend)
      start = end + 1;
    else start = end;
  }
  myargv[argc+1] = 0;
  *argv = myargv;
  return argc;
}

/* Free an argv allocated inside arg_parse */
void arg_parse_free(char **argv) {
  char **current;
  /* Integrity check */
  argv--;
  assert(argv[0] == (char *) 0x123456);
  current = argv + 1;
  while(*current) {
    free(*current);
    current++;
  }
  free(argv);
}

/* Converts an Nmap time specification string into milliseconds.  If
   the string is a plain non-negative number, it is considered to
   already be in milliseconds and is returned.  If it is a number
   followed by 's' (for seconds), 'm' (minutes), or 'h' (hours), the
   number is converted to milliseconds and returned.  If Nmap cannot
   parse the string, it is returned instead. */
long tval2msecs(char *tspec) {
  long l;
  char *endptr = NULL;
  l = strtol(tspec, &endptr, 10);
  if (l < 0 || !endptr) return -1;
  if (*endptr == '\0') return l;
  if (*endptr == 's' || *endptr == 'S') return l * 1000;
  if ((*endptr == 'm' || *endptr == 'M')) {
    if (*(endptr + 1) == 's' || *(endptr + 1) == 'S') 
      return l;
    return l * 60000;
  }
  if (*endptr == 'h' || *endptr == 'H') return l * 3600000;
  return -1;
}

// A simple function to form a character from 2 hex digits in ASCII form
static unsigned char hex2char(unsigned char a, unsigned char b)
{
  int val;
  if (!isxdigit(a) || !isxdigit(b)) return 0;
  a = tolower(a);
  b = tolower(b);
  if (isdigit(a))
    val = (a - '0') << 4;
  else val = (10 + (a - 'a')) << 4;

  if (isdigit(b))
    val += (b - '0');
  else val += 10 + (b - 'a');

  return (unsigned char) val;
}

/* Convert a string in the format of a roughly C-style string literal
   (e.g. can have \r, \n, \xHH escapes, etc.) into a binary string.
   This is done in-place, and the new (shorter or the same) length is
   stored in newlen.  If parsing fails, NULL is returned, otherwise
   str is returned. */
char *cstring_unescape(char *str, unsigned int *newlen) {
  char *dst = str, *src = str;
  char newchar;

  while(*src) {
    if (*src == '\\' ) {
      src++;
      switch(*src) {
      case '0':
	newchar = '\0'; src++; break;
      case 'a': // Bell (BEL)
	newchar = '\a'; src++; break;	
      case 'b': // Backspace (BS)
	newchar = '\b'; src++; break;	
      case 'f': // Formfeed (FF)
	newchar = '\f'; src++; break;	
      case 'n': // Linefeed/Newline (LF)
	newchar = '\n'; src++; break;	
      case 'r': // Carriage Return (CR)
	newchar = '\r'; src++; break;	
      case 't': // Horizontal Tab (TAB)
	newchar = '\t'; src++; break;	
      case 'v': // Vertical Tab (VT)
	newchar = '\v'; src++; break;	
      case 'x':
	src++;
	if (!*src || !*(src + 1)) return NULL;
	if (!isxdigit(*src) || !isxdigit(*(src + 1))) return NULL;
	newchar = hex2char(*src, *(src + 1));
	src += 2;
	break;
      default:
	if (isalnum(*src))
	  return NULL; // I don't really feel like supporting octals such as \015
	// Other characters I'll just copy as is
	newchar = *src;
	src++;
	break;
      }
      *dst = newchar;
      dst++;
    } else {
      if (dst != src)
	*dst = *src;
      dst++; src++;
    }
  }

  *dst = '\0'; // terminated, but this string can include other \0, so use newlen
  if (newlen) *newlen = dst - str;
  return str;
}

/* This function converts zero-terminated 'txt' string to binary 'data'.
   It is used to parse user input for ip options. Some examples of possible input
   strings and results:
   	'\x01*2\xA2'	-> [0x01,0x01,0xA2]	// with 'x' number is parsed in hex
   	'\01\01\255'	-> [0x01,0x01,0xFF]	// without 'x' its in decimal
   	'\x01\x00*2'	-> [0x01,0x00,0x00]	// '*' is copying char
   	'R'		-> Record Route with 9 slots
   	'S 192.168.0.1 172.16.0.1' -> Strict Route with 2 slots
   	'L 192.168.0.1 172.16.0.1' -> Loose Route with 2 slots
   	'T'		-> Record Timestamp with 9 slots
   	'U'		-> Record Timestamp and Ip Address with 4 slots
*/
int parse_ip_options(char *txt, u8 *data, int datalen, int* firsthopoff, int* lasthopoff){
  enum{
    NONE  = 0,
    SLASH = 1,
    MUL   = 2,
    RR	  = 3,
    TIME  = 4,
  } s = NONE;
  char *n, lc;
  char *c = txt;
  u8 *d = data;
  int i,j;
  int base = 10;
  u8 *dataend = &data[datalen];
  u8 *len = NULL;
  char buf[32];
  memset(data, 0, datalen);
  bool sourcerouting = false;
  

  for(;*c;c++){
    switch(s){
    case SLASH:
      // parse \x00 string
      if(*c == 'x'){// just ignore this char
      	base = 16;
        break;
      }
      if(isxdigit(*c)){
        *d++ = strtol(c, &n, base);
        c=n-1;
      }else
        fatal("not a digit after '\\'");
      s = NONE;
      break;
    case MUL:
      if(d==data)
        fatal("nothing before '*' char");
      i = strtol(c, &n, 10);
      if(i<2)
        fatal("bad number after '*'");
      c = n-1;		// move current txt pointer
      lc = *(d-1);	// last char, we'll copy this
      for(j=1; j<i; j++){
        *d++ = lc;
        if(d == dataend) // check for overflow
          goto after;
      }
      s = NONE;
      break;
    case RR:
      if(*c==' ' || *c==',')
        break;
      n = buf;
      while((*c=='.' || (*c>='0' && *c<='9')) && n-buf <= ((int)sizeof(buf)-1))
      	 *n++ = *c++;
      *n = '\0'; c--;
      if(d+4>=dataend)
        fatal("Buffer too small. Or input data too big :)");
      i = inet_pton(AF_INET, buf, d);
      if(i<1)
        fatal("Not a valid ipv4 address '%s'",buf);
      // remember offset of first hop
      if(sourcerouting && !*firsthopoff)
        *firsthopoff = d - data;
      d+=4;
      if(*len<37)
        *len += 4;
      break;
    case TIME:
      fatal("No more arguments allowed!");
    default:
      switch(*c){
      case '\\':s = SLASH;base=10;break;
      case '*':s = MUL;break;
      case 'R':
      case 'S':
      case 'L':
        if(d != data)
          fatal("This option can't be used in that way");
        *d++ = '\x01';//NOP
        switch(*c){
        case 'R':*d++ = 7;break;
        case 'S':*d++ = 137; sourcerouting=true; break;
        case 'L':*d++ = 131; sourcerouting=true; break;
        }
	len = d;
        *d++ = (*c=='R')? 39 : 3; // length: 3+4*9 bytes
        *d++ = 4; //pointer          
        s = RR;
        break;
      case 'T':
      case 'U':
        if(d != data)
          fatal("This option can't be used in that way");
	*d++ = 68;	// option type
	len = d;
        *d++ = (*c=='U') ? 36 : 40;   // length: 3+4*9 bytes or 4+4*9 bytes
        *d++ = 5; // pointer
        *d++ = (*c=='U') ? 1 : 0; // flag: address and Time fields
        s = TIME;
        break;
      default://*d++ = *c;
      	fatal("Bad character in ip option '%c'",*c);
      }
    }
    if(d == dataend)
      break;
    assert(d<dataend);
  }
  if(sourcerouting){
    if(*len<37){
      *len+=4;
      *lasthopoff = d - data;
      *d++ = 0;*d++ = 0;*d++ = 0;*d++ = 0;
    }else
      fatal("When using source routing you must leave at least one slot for target's ip.");
  }
  if(s == RR)
    return(*len+1); // because we inject NOP before
  if(s == TIME)
    return(*len);
after:
  return(d - data);
}

void bintohexstr(char *buf, int buflen, char *src, int srclen){
    int bp=0;
    int i;
    for(i=0; i<srclen; i++){
      bp += snprintf(buf+bp, buflen-bp, "\\x%02hhx",src[i]);
      if(bp >= buflen)break;
      if(i%16==7){
        bp += snprintf(buf+bp, buflen-bp," ");
        if(bp >= buflen)break;
      }
      if(i%16==15){
        bp += snprintf(buf+bp, buflen-bp,"\n");
        if(bp >= buflen)break;
      }
    }
    if(i%16!=0 && bp < buflen)
      bp += snprintf(buf+bp, buflen-bp,"\n");
}

static inline char* STRAPP(char *fmt, ...) {
  static char buf[256];
  static int bp;
  int left = (int)sizeof(buf)-bp;
  if(!fmt){
    bp = 0;
    return(buf);
  }
  if (left <= 0)
    return buf;
  va_list ap;
  va_start(ap, fmt);
  bp += vsnprintf (buf+bp, left, fmt, ap);
  va_end(ap);

  return(buf);
}

#define HEXDUMP -2
#define UNKNOWN -1

#define BREAK()		\
	{option_type = HEXDUMP; break;}
#define CHECK(tt)	\
  if(tt >= option_end)	\
  	{option_type = HEXDUMP; break;}
/* It tries to decode ip options.
   Returns static buffer. watch out. */
char* print_ip_options(u8* ipopt, int ipoptlen) {
  char ipstring[32];
  int option_type = UNKNOWN;// option type
  int option_len  = 0; // option length
  int option_pt   = 0; // option pointer
  int option_fl   = 0;  // option flag
  u8 *tptr;		// temp pointer
  u32 *tint;		// temp int

  int option_sta = 0;	// option start offset
  int option_end = 0;	// option end offset
  int pt = 0;		// current offset

  // clear buffer
  STRAPP(NULL,NULL);

  if(!ipoptlen)
    return(NULL);

  while(pt<ipoptlen){	// for every char in ipopt
    // read ip option header
    if(option_type == UNKNOWN) {
      option_sta  = pt;
      option_type = ipopt[pt++];
      if(option_type != 0 && option_type != 1) { // should we be interested in length field?
        if(pt >= ipoptlen)	// no more chars
          {option_type = HEXDUMP;pt--; option_end = 255; continue;} // no length field, hex dump to the end
        option_len  = ipopt[pt++];
        // end must not be greater than length
        option_end  = MIN(option_sta + option_len, ipoptlen);
        // end must not be smaller than current position
        option_end  = MAX(option_end, option_sta+2);
      }
    }
    switch(option_type) {
    case 0:	// IPOPT_END
    	STRAPP(" EOL", NULL);
    	option_type = UNKNOWN;
  	break;
    case 1:	// IPOPT_NOP
    	STRAPP(" NOP", NULL);
    	option_type = UNKNOWN;
  	break;
/*    case 130:	// IPOPT_SECURITY
    	option_type=-1;
  	break;*/
    case 131:	// IPOPT_LSRR	-> Loose Source and Record Route
    case 137:	// IPOPT_SSRR	-> Strict Source and Record Route
    case 7:	// IPOPT_RR	-> Record Route
	if(pt - option_sta == 2) {
    	  STRAPP(" %s%s{", (option_type==131)?"LS":(option_type==137)?"SS":"", "RR");
    	  // option pointer
    	  CHECK(pt);
    	  option_pt = ipopt[pt++];
    	  if(option_pt%4 != 0 || (option_sta + option_pt-1)>option_end || option_pt<4)	//bad or too big pointer
    	    STRAPP(" [bad ptr=%02i]", option_pt);
    	}
    	if(pt - option_sta > 2) { // ip's
    	  int i, s = (option_pt)%4;
    	  // if pointer is mangled, fix it. it's max 3 bytes wrong
    	  CHECK(pt+3);
    	  for(i=0; i<s; i++)
    	    STRAPP("\\x%02x", ipopt[pt++]);
    	  option_pt -= i;
    	  // okay, now we can start printing ip's
    	  CHECK(pt+3);
	  tptr = &ipopt[pt]; pt+=4;
	  if(inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL)
	    fatal("Failed to convert target address to presentation format!?!  Error: %s", strerror(socket_errno()));
    	  STRAPP("%c%s",(pt-3-option_sta)==option_pt?'#':' ', ipstring);
    	  if(pt == option_end)
    	    STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":""); // pointer in the end?
    	}else BREAK();
  	break;
    case 68:	// IPOPT_TS	-> Internet Timestamp
	if(pt - option_sta == 2){
	  STRAPP(" TM{");
    	  // pointer
    	  CHECK(pt);
    	  option_pt  = ipopt[pt++];
	  // bad or too big pointer
    	  if(option_pt%4 != 1 || (option_sta + option_pt-1)>option_end || option_pt<5)
    	    STRAPP(" [bad ptr=%02i]", option_pt);
    	  // flags + overflow
    	  CHECK(pt);
    	  option_fl  = ipopt[pt++];
    	  if((option_fl&0x0C) || (option_fl&0x03)==2)
    	    STRAPP(" [bad flags=\\x%01hhx]", option_fl&0x0F);
  	  STRAPP("[%i hosts not recorded]", option_fl>>4);
  	  option_fl &= 0x03;
	}
    	if(pt - option_sta > 2) {// ip's
    	  int i, s = (option_pt+3)%(option_fl==0?4:8);
    	  // if pointer is mangled, fix it. it's max 3 bytes wrong
    	  CHECK(pt+(option_fl==0?3:7));
    	  for(i=0; i<s; i++)
    	    STRAPP("\\x%02x", ipopt[pt++]);
    	  option_pt-=i;

	  // print pt
  	  STRAPP("%c",(pt+1-option_sta)==option_pt?'#':' ');
    	  // okay, first grab ip.
    	  if(option_fl!=0){
    	    CHECK(pt+3);
	    tptr = &ipopt[pt]; pt+=4;
	    if(inet_ntop(AF_INET, (char *) tptr, ipstring, sizeof(ipstring)) == NULL)
	      fatal("Failed to convert target address to presentation format!?!  Error: %s", strerror(socket_errno()));
	    STRAPP("%s@", ipstring);
    	  }
    	  CHECK(pt+3);
	  tint = (u32*)&ipopt[pt]; pt+=4;
	  STRAPP("%u", ntohl(*tint));

    	  if(pt == option_end)
  	    STRAPP("%s",(pt-option_sta)==(option_pt-1)?"#":" ");
    	}else BREAK();
  	break;
    case 136:	// IPOPT_SATID	-> (SANET) Stream Identifier
	if(pt - option_sta == 2){
	  u16 *sh;
    	  STRAPP(" SI{",NULL);
    	  // length
    	  if(option_sta+option_len > ipoptlen || option_len!=4)
    	    STRAPP("[bad len %02i]", option_len);

    	  // stream id
    	  CHECK(pt+1);
    	  sh = (u16*) &ipopt[pt]; pt+=2;
    	  option_pt  = ntohs(*sh);
    	  STRAPP("id=%i", option_pt);
    	  if(pt != option_end)
    	    BREAK();
	}else BREAK();
  	break;
    case UNKNOWN:
    default:
    	// we read option_type and option_len, print them.
    	STRAPP(" ??{\\x%02hhx\\x%02hhx", option_type, option_len);
    	// check option_end once more:
    	if(option_len < ipoptlen)
    	  option_end = MIN(MAX(option_sta+option_len, option_sta+2),ipoptlen);
    	else
    	  option_end = 255;
    	option_type = HEXDUMP;
    	break;
    case HEXDUMP:
    	assert(pt<=option_end);
    	if(pt == option_end){
	  STRAPP("}",NULL);
    	  option_type=-1;
    	  break;
    	}
	STRAPP("\\x%02hhx", ipopt[pt++]);
    	break;
    }
    if(pt == option_end && option_type != UNKNOWN) {
      STRAPP("}",NULL);
      option_type = UNKNOWN;
    }
  } // while 
  if(option_type != UNKNOWN)
    STRAPP("}");

  return(STRAPP("",NULL));
}
#undef CHECK
#undef BREAK
#undef UNKNOWN
#undef HEXDUMP


/* mmap() an entire file into the address space.  Returns a pointer
   to the beginning of the file.  The mmap'ed length is returned
   inside the length parameter.  If there is a problem, NULL is
   returned, the value of length is undefined, and errno is set to
   something appropriate.  The user is responsible for doing
   an munmap(ptr, length) when finished with it.  openflags should 
   be O_RDONLY or O_RDWR, or O_WRONLY
*/

#ifndef WIN32
char *mmapfile(char *fname, int *length, int openflags) {
  struct stat st;
  int fd;
  char *fileptr;

  if (!length || !fname) {
    errno = EINVAL;
    return NULL;
  }

  *length = -1;

  if (stat(fname, &st) == -1) {
    errno = ENOENT;
    return NULL;
  }

  fd = open(fname, openflags);
  if (fd == -1) {
    return NULL;
  }

  fileptr = (char *)mmap(0, st.st_size, (openflags == O_RDONLY)? PROT_READ :
			 (openflags == O_RDWR)? (PROT_READ|PROT_WRITE) 
			 : PROT_WRITE, MAP_SHARED, fd, 0);

  close(fd);

#ifdef MAP_FAILED
  if (fileptr == (void *)MAP_FAILED) return NULL;
#else
  if (fileptr == (char *) -1) return NULL;
#endif

  *length = st.st_size;
  return fileptr;
}
#else /* WIN32 */
/* FIXME:  From the looks of it, this function can only handle one mmaped 
   file at a time (note how gmap is used).*/
/* I believe this was written by Ryan Permeh ( ryan@eeye.com) */

static HANDLE gmap = NULL;

char *mmapfile(char *fname, int *length, int openflags)
{
	HANDLE fd;
	DWORD mflags, oflags;
	char *fileptr;

	if (!length || !fname) {
		WSASetLastError(EINVAL);
		return NULL;
	}

 if (openflags == O_RDONLY) {
  oflags = GENERIC_READ;
  mflags = PAGE_READONLY;
  }
 else {
  oflags = GENERIC_READ | GENERIC_WRITE;
  mflags = PAGE_READONLY | PAGE_READWRITE;
 }

 fd = CreateFile (
   fname,
   oflags,                       // open flags
   0,                            // do not share
   NULL,                         // no security
   OPEN_EXISTING,                // open existing
   FILE_ATTRIBUTE_NORMAL,
   NULL);                        // no attr. template
 if (!fd)
  pfatal ("%s(%u): CreateFile()", __FILE__, __LINE__);

 *length = (int) GetFileSize (fd, NULL);

 gmap = CreateFileMapping (fd, NULL, mflags, 0, 0, NULL);
 if (!gmap)
  pfatal ("%s(%u): CreateFileMapping(), file '%s', length %d, mflags %08lX",
    __FILE__, __LINE__, fname, *length, mflags);

 fileptr = (char*) MapViewOfFile (gmap, oflags == GENERIC_READ ? FILE_MAP_READ : FILE_MAP_WRITE,
                                     0, 0, 0);
 if (!fileptr)
  pfatal ("%s(%u): MapViewOfFile()", __FILE__, __LINE__);

 CloseHandle (fd);

 if (o.debugging > 2)
  log_write(LOG_PLAIN, "%s(): fd %08lX, gmap %08lX, fileptr %08lX, length %d\n",
    __func__, (DWORD)fd, (DWORD)gmap, (DWORD)fileptr, *length);

	return fileptr;
}


/* FIXME:  This only works if the file was mapped by mmapfile (and only
   works if the file is the most recently mapped one */
int win32_munmap(char *filestr, int filelen)
{
  if (gmap == 0)
    fatal("%s: no current mapping !\n", __func__);

  FlushViewOfFile(filestr, filelen);
  UnmapViewOfFile(filestr);
  CloseHandle(gmap);
  gmap = NULL;
  return 0;
}

#endif
