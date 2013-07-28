
/***************************************************************************
 * HopByHopHeader.cc -- The HopByHopHeader Class represents an IPv6        *
 * Hop-by-Hop extension header.                                            *
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
/* This code was originally part of the Nping tool.                        */

#include "HopByHopHeader.h"
#include <assert.h>

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
HopByHopHeader::HopByHopHeader() {
  this->reset();
} /* End of HopByHopHeader constructor */


HopByHopHeader::~HopByHopHeader() {

} /* End of HopByHopHeader destructor */


/** Sets every attribute to its default value */
void HopByHopHeader::reset(){
  memset(&this->h, 0, sizeof(nping_ipv6_ext_hopbyhop_hdr_t));
  curr_option=(u8*)this->h.options;
  this->length=2;
  this->addOption(EXTOPT_PADN, 4, (const u8*)"\x00\x00\x00\x00");
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *HopByHopHeader::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The HopByHopHeader class is able to hold a maximum of
  * sizeof(nping_icmpv6_hdr_t) bytes. If the supplied buffer is longer than
  * that, only the first 1508 bytes will be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int HopByHopHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<HOPBYHOP_MIN_HEADER_LEN){
    this->length=0;
    return OP_FAILURE;
  }else{
     /* Store the first 4 bytes, so we can access the HdrExtLen field. */
     memcpy(&(this->h), buf, 4);

     /* Check that the HdrExtLen field makes sense:
      * 1) Check that it carries as many octets as it claims
      * 2) Check that we don't exceed our internal storage space. */
     if( ((unsigned int)(this->h.len+1))*8 > len || (this->h.len+1)*8 > HOPBYHOP_MAX_HEADER_LEN){
       this->length=0;
       return OP_FAILURE;
     }else{
        int mylen=(this->h.len+1)*8;
        this->reset();
        this->length=mylen;
        memcpy(&(this->h), buf, this->length);
        return OP_SUCCESS;
     }
  }
  return OP_FAILURE;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int HopByHopHeader::protocol_id() const {
    return HEADER_TYPE_IPv6_HOPOPT;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int HopByHopHeader::validate(){
  nping_ipv6_ext_hopbyhop_opt_t *curr_opt=NULL;
  u8 *curr_pnt=(u8 *)this->h.options;
  int bytes_left=this->length-2;

  /* Check the object's length makes sense*/
  if(this->length%8!=0 || this->length < HOPBYHOP_MIN_HEADER_LEN || this->length > HOPBYHOP_MAX_HEADER_LEN){
    return OP_FAILURE;
  }
  /* Check the header's length field. It should match the object's length */
  if( (this->h.len+1)*8 != this->length){
    return OP_FAILURE;
  }

  /* Now validate the TLV-encoded options.  */
  while(bytes_left>0){
      /* Use the opts structure as a template to access current option */
      curr_opt=(nping_ipv6_ext_hopbyhop_opt_t *)curr_pnt;

      /* Let's see what we have. */
      switch(curr_opt->type){

        /* Pad1
        +-+-+-+-+-+-+-+-+
        |       0       |
        +-+-+-+-+-+-+-+-+  */
        case EXTOPT_PAD1:
          curr_pnt++; /* Skip one octet */
          bytes_left++;
        break;

        /* PadN
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
        |       1       |  Padding Len  |  Padding
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - - */
        case EXTOPT_PADN:
          /* Check we have as many octets as the option advertises */
          if(bytes_left<2+curr_opt->len)
            return OP_FAILURE;
          curr_pnt+=2+curr_opt->len;
          bytes_left-=2+curr_opt->len;
        break;

        /* Jumbo Payload Option (RFC 2675).
                                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                        |  Option Type  |  Opt Data Len |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                     Jumbo Payload Length                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        case EXTOPT_JUMBO:
          /* Jumbo has a fixed length of 4 octets (plus 2). */
          if(curr_opt->len!=4)
            return OP_FAILURE;
          /* Check if we actually have all the octets */
          if(bytes_left<2+4)
            return OP_FAILURE;
          curr_pnt+=6;
          bytes_left-=6;
        break;

        /* Tunnel Encapsulation limit (RFC 2473).
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Option Type  |       1       | Tun Encap Lim |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        case EXTOPT_TUNENCAPLIM:
          /* This one also has a fixed length. */
          if(curr_opt->len!=1)
            return OP_FAILURE;
          /* Check if we actually have all the octets */
          if(bytes_left<2+1)
            return OP_FAILURE;
          curr_pnt+=3;
          bytes_left-=3;
        break;

        /* Router Alert (RFC 2711).
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Option Type  |       2       |        Value (2 octets)       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        case EXTOPT_ROUTERALERT:
          /* Fixed length (two octets)*/
          if(curr_opt->len!=2)
            return OP_FAILURE;
          /* Check that we actually have all the octets */
          if(bytes_left<2+2)
            return OP_FAILURE;
          curr_pnt+=4;
          bytes_left-=4;
        break;

        /*  Quick-Start (RFC 4782).
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |   Option      |   Length=6    | Func. | Rate  |   Not Used    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        QS Nonce                           | R |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ */
        case EXTOPT_QUICKSTART:
          /* Fixed length (two octets)*/
          if(curr_opt->len!=6)
            return OP_FAILURE;
          /* Check that we actually have all the octets */
          if(bytes_left<2+6)
            return OP_FAILURE;
          curr_pnt+=8;
          bytes_left-=8;
        break;

        /*  CALIPSO (RFC 5570).
                                      +----------------------------+
                                      | Option Type | Option Length|
        +-------------+---------------+-------------+--------------+
        |             CALIPSO Domain of Interpretation             |
        +-------------+---------------+-------------+--------------+
        | Cmpt Length |  Sens Level   |     Checksum (CRC-16)      |
        +-------------+---------------+-------------+--------------+
        |      Compartment Bitmap (Optional; variable length)      |
        +-------------+---------------+-------------+--------------+ */
        case EXTOPT_CALIPSO:
          /* The length of the CALIPSO option is variable because the
           * Compartment Bitmap is not mandatory. However, the length
           * must be at least 8. */
          if(curr_opt->len<8)
            return OP_FAILURE;
          /* Check that we actually have all the octets */
          if(bytes_left<2+curr_opt->len)
            return OP_FAILURE;
          curr_pnt+=2+curr_opt->len;
          bytes_left-=2+curr_opt->len;
        break;


        /* Home Address (RFC 6275).
                                        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                        |  Option Type  | Option Length |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        +                                                               +
        |                                                               |
        +                          Home Address                         +
        |                                                               |
        +                                                               +
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
        case EXTOPT_HOMEADDR:
          /* Fixed length of 16 */
          if(curr_opt->len!=16)
            return OP_FAILURE;
          /* Check if we actually have all the octets */
          if(bytes_left<2+16)
            return OP_FAILURE;
          curr_pnt+=18;
          bytes_left-=18;
        break;

        /* Option Type Unknown */
        default:
          /* If we don't know the option, we can still try to validate it,
           * checking if the OptionLength contains something reasonable. */
          /* Fixed length of 16 */
          if(bytes_left<2+curr_opt->len)
            return OP_FAILURE;
          curr_pnt+=2+curr_opt->len;
          bytes_left-=2+curr_opt->len;
        break;
      }
  }
  return this->length;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int HopByHopHeader::print(FILE *output, int detail) const {
  fprintf(output, "HopByHop[%d,%d]", this->h.nh, this->h.len);
  // TODO: @todo : Implement this
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

/** Set Next Header field */
int HopByHopHeader::setNextHeader(u8 val){
  this->h.nh = val;
  return OP_SUCCESS;
} /* End of setNextHeader() */


/** Returns next header id */
u8 HopByHopHeader::getNextHeader(){
  return this->h.nh;
} /* End of getNextHeader() */


/* Add TLV encoded option */
int HopByHopHeader::addOption(u8 type, u8 len, const u8 *data){
  /* Make sure we don't screw up due to buffer length issues */
  if(data==NULL)
    return OP_FAILURE;
  if ( (this->length+len+2) > HOPBYHOP_MAX_HEADER_LEN ) /* No space for more */
    return OP_FAILURE;

  /* Store the option */
  curr_option[0]=type;
  curr_option[1]=len;
  memcpy(curr_option+2, data, len);
  /* Update internal option offset and object's length */
  curr_option+=(len+2);
  this->length+=(len+2);
  this->addPadding();
  return OP_SUCCESS;

} /* End of addOption() */


/* If the current length of the extension header is not a multiple of 8 octets,
 * this method adds the neccessary padding (either PadN or Pad1 options)*/
int HopByHopHeader::addPadding(){
  u8 zeroes[8]={0,0,0,0,0,0,0,0};
  int required_octets=8-(this->length%8);

  /* Make sure we have enough space for the padding. */
  if ( (this->length+required_octets) > HOPBYHOP_MAX_HEADER_LEN )
    return OP_FAILURE;

  /* Insert Pad1 or PadN to fill the necessary octets */
  if(required_octets>0 && required_octets<8){
      if(required_octets==1){
          curr_option[0]=EXTOPT_PAD1;
          curr_option++;
          this->length++;
      }else{
          this->addOption(EXTOPT_PADN, required_octets-2, zeroes );
      }
  }
  assert(this->length%8==0);
  this->h.len=(this->length/8)-1;
  return OP_SUCCESS;
} /* End of addPadding() */
