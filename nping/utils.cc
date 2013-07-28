
/***************************************************************************
 * utils.cc -- Miscellaneous utils that didn't fit into any of the other   *
 * source files.                                                           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2013 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@insecure.com).  Dozens of software  *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the special and conditions of the license text as well.       *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@insecure.com for     *
 * further information.                                                    *
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
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
 *                                                                         *
 ***************************************************************************/

#include "nping.h"
#include "utils.h"
#include "NpingOps.h"
#include "global_structures.h"
#include "output.h"
#include "nbase.h"
#include "pcap.h"
#include "dnet.h"

#include <errno.h>
#include <vector>

extern NpingOps o;


/** Returns true if "source" contains at least one instance of "substring" */
bool contains(const char *source, const char *substring){
  if(source==NULL || substring==NULL )
    nping_fatal(QT_3,"contains(): NULL value received.");
  if( strcasestr(source, substring) )
    return true;
  else
    return false;
} /* End of contains() */


/** Returns true if the supplied string matches "rand" or "random" (not case
 * sensitive)*/
bool meansRandom(const char *source){
  if(source==NULL)
    nping_fatal(QT_3,"meansRandom(): NULL value received.");
  if( !strcasecmp(source, "rand") || !strcasecmp(source, "random") )
    return true;
  else
    return false;
} /* End of meansRandom() */


/** Returns true if source contains the representation of a number >= min and
 * <= max in the given base (with nothing following). */
static bool isNumber_range(const char *source, int base,
  unsigned long min, unsigned long max){
  unsigned long ul;
  char *tail;
  errno = 0;
  ul = strtoul(source, &tail, base);
  if (errno != 0 || tail == source || *tail != '\0')
    return false;

  return ul >= min && ul <= max;
}


/** Returns true if "source" is a number in the supplied base that can fit
 * into a 8-bit var */
bool isNumber_u8(const char *source, int base){
  return isNumber_range(source, base, 0UL, 0xFFUL);
}


/** Returns true if "source" is a number in the supplied base that can fit
 * into a 16-bit var */
bool isNumber_u16(const char *source, int base){
  return isNumber_range(source, base, 0UL, 0xFFFFUL);
}


/** Returns true if "source" is a number in the supplied base that can fit
 * into a 32-bit var */
bool isNumber_u32(const char *source, int base){
  return isNumber_range(source, base, 0UL, 0xFFFFFFFFUL);
}


/** Returns a buffer that contains the binary equivalent to the supplied
 *  hex spec or NULL in case of error.
 *  @warning Returned pointer points to a static buffer that subsequent calls
 *  will overwrite. */
u8 *parseBufferSpec(char *str, size_t *outlen){
  char auxbuff[1024];
  static u8 dst[16384];
  size_t dstlen=16384;
  unsigned int i=0, j=0;
  char *start=NULL;

  if(str==NULL || outlen==NULL)
    return NULL;
  /* This catches the empty string possibility "" */
  if(strlen(str) == 0)
    return NULL;
  else
    memset(auxbuff,0,1024);

  /* String should be treated as a hex number in this format: 0xAABBCCDDEE...
   * We process it the way it is specified, we don't perform byte order
   * conversions so if the users says 0x00AA we write dst[0]=0x00, dst[1]==0xAA
   * no matter the endianness of the host system. */
  if( !strncmp("0x", str, 2) ){
    /* This catches the case of an empty "0x" */
    if(strlen(str) == 2)
        return NULL;
        start=str+2;
  }
  /* String should be treated as list of hex char in this format: \x00\xFF\x0A*/
  else if( !strncmp("\\x", str, 2) ){
    /* This catches the case of an empty "\x" */
    if(strlen(str) == 2)
        return NULL;
    /* Copy all interesting bytes to an aux array, discard "\x" */  
    for(i=0; i<strlen(str) && j<1023; i++){
        if( str[i]!='\\' && str[i]!='x' && str[i]!='X')
            auxbuff[j++]=str[i];
    }
    auxbuff[j]='\0'; /* NULL terminate the string */
    start=auxbuff;
  }
  /* It must be a hex number in this format: AABBCCDDEE (without 0x or \x) */
  else{
    start=str;
  }

  /*OK, here we should have "start" pointing to the beginning of a string
   * in the format AABBCCDDEE... */
   /* Check if all we've got are hex chars */
  for(i=0; i<strlen(start); i++){
    if( !isxdigit(start[i]) )
        return NULL;
   }
  /* Check if we have an even number of hex chars */
  if( strlen(start)%2 != 0 )
    return NULL;

  /* We are ready to parse this string */
  for(i=0, j=0; j<dstlen && i<strlen(start)-1; i+=2){
    char twobytes[3];
    twobytes[0]=start[i];
    twobytes[1]=start[i+1];
    twobytes[2]='\0';
    dst[j++]=(u8)strtol(twobytes, NULL, 16);
  }
  /* Store final length */
  *outlen=j;
  return dst;
} /* End of parseBufferSpec*/


/* Determines how many bits "a" and "b" have in common until they differ. For
 * example, if A is 11111111 and B is 11111101, this function will return 6,
 * as the first 6 bits of A and B are equal.
 * @param len is the length in BYTES of "a" and "b".
 *
 * TODO: Check if this function is endian-safe. 
 */
int bitcmp(u8 *a, u8*b, int len){
 int equal=0;
 int firstpart=len-1;

  if(a==NULL || b==NULL || len<=0)
    return -1;

  for(int i=0; i<len; i++){
    if(a[i]!=b[i]){
        firstpart=i;
        break;
    }
  }

  /* Do all bits match? */
  if(firstpart==len)
    return len*8;
  else
    equal=firstpart*8;

   /* Take the first byte that didn't match completely and determine how
    * many bits they have in common until they differ */
  for(int i=0, j=0x80; i<8; i++, j/=2){
    if( (a[firstpart] & j) == (b[firstpart] & j) )
        equal++;
    else
        return equal;
  }
  return equal;  
} /* End of bitcmp() */



/** Removes every instance of the character stored in parameter "c" in the
 * supplied string.
 * @warning the supplied buffer is modified by this function. Whenever a
 * colon is found, the rest of the string is moved one position to the left
 * so the colon gets overwritten. */
int removechar(char *string, char c){
  size_t len=0, i=0, j=0;
  if(string==NULL)
    return OP_FAILURE;
  len=strlen(string);
  for(i=0; i<len; i++){
    /* Found the character, move everything one position to the left */
    if( string[i]== c ){
        for(j=i; j<len-1; j++)
            string[j]=string[j+1];
        len-=1;
        string[len]='\0';
        /* Start again from the beginning because otherwise we don't catch
         * consecutive colons */
        i=-1; /* (get incremented by one by the loop control) */ 
    }
  }
  return OP_SUCCESS;
} /* End of removechar() */



/** Removes every instance of ':' in the supplied string.
 * @warning the supplied buffer is modified by this function. Whenever a
 * colon is found, the rest of the string is moved one position to the left
 * so the colon gets overwritten. */
int removecolon(char *string){
  return removechar(string, ':');
}/* End of removecolon() */



/* lamont_hdump() has a bug so 3-byte lines are not printed correctly.
 * This function is a better version of hdump written by Luis MartinGarcia.
 * It uses current locale to determine if a character is printable or
 * not. It prints 73char wide lines like these:

0000   e8 60 65 86 d7 86 6d 30  35 97 54 87 ff 67 05 9e  .`e...m05.T..g.. 
0010   07 5a 98 c0 ea ad 50 d2  62 4f 7b ff e1 34 f8 fc  .Z....P.bO{..4.. 
0020   c4 84 0a 6a 39 ad 3c 10  63 b2 22 c4 24 40 f4 b1  ...j9.<.c.".$@.. 

 * The lines look basically like Wireshark hex dump.
 * */
void luis_hdump(char *cp, unsigned int length) {
  static char asciify[257];          /* Stores character table           */
  static bool asc_init=false;        /* Flag to generate table only once */
  unsigned int i=0, hex=0, asc=0;    /* Array indexes                    */
  int line_count=0;                  /* For byte count at line start     */
  u8 current_char=0;                 /* Current character to print       */
  #define LINE_LEN 70                /* Lenght of printed line           */
  char line2print[LINE_LEN];         /* Stores current line              */
  char printbyte[16];                /* For byte conversion              */
  memset(line2print, ' ', LINE_LEN);
  line2print[LINE_LEN-1]='\0';

  /* On the first run, generate a list of nice printable characters
   * (according to current locale) */
  if( asc_init==false){
      asc_init=true;
      for(int i=0; i<256; i++){
        if( isalnum(i) || isdigit(i) || ispunct(i) ){ asciify[i]=i; }
        else{ asciify[i]='.'; }
      }
  }

#define HEX_START 3
#define ASC_START 53
  for(i=0, hex=HEX_START, asc=ASC_START; i<length; i++){
    current_char=cp[i];
    if( hex==HEX_START+24) hex++; /* Insert space every 8 bytes */
    /* First print the hex number */
    sprintf(printbyte,"%02x", current_char);    
    line2print[hex++]=printbyte[0];
    line2print[hex++]=printbyte[1];
    line2print[hex++]=' ';
    /* Then print its ascii equivalent */
    line2print[asc++]=asciify[ current_char ];
    /* Every 16 buffer bytes, print the line. */
    if( (((i+1)%16)==0 && i!=0) || i+1==length ){
        printf("%04x%s\n", (16*line_count++), line2print);
        hex=HEX_START;  asc=ASC_START;
        memset(line2print, ' ', LINE_LEN);
        line2print[LINE_LEN-1]='\0';
    }
  }
 return;
} /* End of luis_hdump() */


/** Takes a string representing a number, converts it to an unsigned
  * long, and stores it in *dst.
  * @param str is the string to be converted. The number may be in any
  * of the following forms:
  *     - Hexadecimal number: It must start with "0x" and have an even
  *       number of hex digits after it.
  *     - Octal number: It must start with "0" and have any number of
  *       octal digits ([0,7]) after it.
  *     - Decimal number: Any string that does not start with "0x" or
  *       "0" will be treated as a decimal number. It may only contain
  *       decimal digits (no whitespace, no weird symbols, and not even
  *       a sign character (+ or -).
  *     - Random number: The number specification may contain the special
  *       value "rand" or "random". In that case, a random number of the
  *       requested length will be generated and stored in the supplied
  *       buffer.
  * @param min values less than this cause an error.
  * @param max values greater than this cause an error.
  * @param dst should be the address of an unsigned long variable.
  * @return OP_SUCCESS if conversion was successful or OP_FAILURE in
  * case of error. */
static int parse_unsigned_number(const char *str, unsigned long min, unsigned long max, unsigned long *dst){
  unsigned long int result;
  char *tail=NULL;

  if(str==NULL || dst==NULL)
    return OP_FAILURE;

  /* Check if the spec contains a sign character */
  if(strpbrk(str, "-+") != NULL)
    return OP_FAILURE;

  /* Case 1: User wants a random value */
  if(!strcasecmp(str, "rand") || !strcasecmp(str, "random")){
    u32 r = get_random_u32();
    *dst = min + (unsigned long) ((max - min + 1) * ((double) r / 0xffffffffUL));
    return OP_SUCCESS;
  }

  /* Case 2: User supplied an actual number */
  errno=0;
  result=strtoul(str, &tail, 0);
  if(errno!=0 || tail==str || *tail!='\0')
    return OP_FAILURE;

  if (result >= min && result <= max) {
    *dst = result;
    return OP_SUCCESS;
  } else {
    return OP_FAILURE;
  }
} /* End of parse_number() */



/** Takes a string representing an 8-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u8(const char *str, u8 *dst){
  unsigned long ul;
  int ret;
  ret = parse_unsigned_number(str, 0UL, 0xffUL, &ul);
  if (ret == OP_SUCCESS)
    *dst = ul;
  return ret;
}


/** Takes a string representing a 16-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u16(const char *str, u16 *dst){
  unsigned long ul;
  int ret;
  ret = parse_unsigned_number(str, 0UL, 0xffffUL, &ul);
  if (ret == OP_SUCCESS)
    *dst = ul;
  return ret;
}


/** Takes a string representing a 32-bit number and converts it into an
  * actual integer. The result is stored in memory area pointed by
  * "dstbuff". Returns OP_SUCCESS if conversion was successful or
  * OP_FAILURE in case of error.*/
int parse_u32(const char *str, u32 *dst){
  unsigned long ul;
  int ret;
  ret = parse_unsigned_number(str, 0UL, 0xffffffffUL, &ul);
  if (ret == OP_SUCCESS)
    *dst = ul;
  return ret;
}


/** Prints the hexadecimal dump of the supplied buffer to standard output */
int print_hexdump(int level, const u8 *cp, u32 length){
  char *str = hexdump(cp, length);
  if(str==NULL)
    return OP_FAILURE;
  nping_print(level, "%s", str);
  free(str);
  return OP_SUCCESS;
} /* End of print_hexdump() */
