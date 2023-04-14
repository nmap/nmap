/***************************************************************************
 * HopByHopHeader.cc -- The HopByHopHeader Class represents an IPv6        *
 * Hop-by-Hop extension header.                                            *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
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
     // h.len cannot exceed 0xff, so max is (0xff+1)*8, but HOPBYHOP_MAX_HEADER_LEN is 8 + 0x100*8
     if( ((unsigned int)(this->h.len+1))*8 > len){
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
 * this method adds the necessary padding (either PadN or Pad1 options)*/
int HopByHopHeader::addPadding(){
  u8 zeroes[8]={0,0,0,0,0,0,0,0};
  // required_octets in range [0,7]
  int required_octets=(8 - (this->length % 8)) % 8;

  /* Make sure we have enough space for the padding. */
  if ( (this->length+required_octets) > HOPBYHOP_MAX_HEADER_LEN )
    return OP_FAILURE;

  /* Insert Pad1 or PadN to fill the necessary octets */
  if (required_octets == 1) {
    curr_option[0]=EXTOPT_PAD1;
    curr_option++;
    this->length++;
  }
  else if (required_octets > 0) {
    this->addOption(EXTOPT_PADN, required_octets-2, zeroes );
  }
  assert(this->length%8==0);
  this->h.len=(this->length/8)-1;
  return OP_SUCCESS;
} /* End of addPadding() */
