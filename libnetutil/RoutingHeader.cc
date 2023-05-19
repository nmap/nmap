/***************************************************************************
 * RoutingHeader.cc -- The RoutingHeader Class represents an IPv6 Routing  *
 * extension header.                                                       *
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

#include "RoutingHeader.h"
#include <assert.h>

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
RoutingHeader::RoutingHeader() {
  this->reset();
} /* End of RoutingHeader constructor */


RoutingHeader::~RoutingHeader() {

} /* End of RoutingHeader destructor */


/** Sets every attribute to its default value */
void RoutingHeader::reset(){
  memset(&this->h, 0, sizeof(nping_ipv6_ext_routing_hdr_t));
  this->length=ROUTING_HEADER_MIN_LEN;
  this->curr_addr=(u8 *)this->h.data;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

/** @warning This method is essential for the superclass getBinaryBuffer()
 *  method to work. Do NOT change a thing unless you know what you're doing  */
u8 *RoutingHeader::getBufferPointer(){
  return (u8*)(&this->h);
} /* End of getBufferPointer() */


/** Stores supplied packet in the internal buffer so the information
  * can be accessed using the standard get & set methods.
  * @warning  The RoutingHeader class is able to hold a maximum of
  * sizeof(nping_icmpv6_hdr_t) bytes. If the supplied buffer is longer than
  * that, only the first 1508 bytes will be stored in the internal buffer.
  * @warning Supplied len MUST be at least 8 bytes (min ICMPv6 header length).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error */
int RoutingHeader::storeRecvData(const u8 *buf, size_t len){
  if(buf==NULL || len<ROUTING_HEADER_MIN_LEN){
    this->length=0;
    return OP_FAILURE;
  }else{
     /* Store the first 4 bytes, so we can access length and routing type */
     memcpy(&(this->h), buf, 4);

     /* Our behaviour is different depending on the routing type. */
     switch(this->h.type){

         // No checks against ROUTING_HEADER_MAX_LEN because h.len cannot get that large:
         // h.len is u8, max value 0xff, so (0xff+1)*8 = 0x800
         // but ROUTING_HEADER_MAX_LEN is 8+256*8 = 0x808

         /* Routing Type 0 (deprecated by RFC 5095)*/
         case 0:
             /* Type 0 has a variable length, but the value of its HdrExtLen
              * field must be even (because it must be a multiple of the
              * IPv6 address size). We also make sure that the received buffer
              * has as many bytes as the HdrExtLen field says it has, and
              * that it doesn't exceed the maximum number of octets we
              * can store in this object. */
             if(this->h.len%2==1 || ((unsigned int)(this->h.len+1))*8 > len){
               this->length=0;
               return OP_FAILURE;
             }else{
                int pkt_len=(this->h.len+1)*8;
                this->reset();
                this->length=pkt_len;
                memcpy(&(this->h), buf, this->length);
                return OP_SUCCESS;
             }
         break;

         /* Routing Type 2 (For IPv6 Mobility. See RFC 6275) */
         case 2:
             /* Type 2 has a fixed length. If we have that many octets, store
              * them. We'll perform validation later in validate(). */
             if(len<ROUTING_TYPE_2_HEADER_LEN){
               this->length=0;
               return OP_FAILURE;
             }else{
                this->reset();
                memcpy(&(this->h), buf, ROUTING_TYPE_2_HEADER_LEN);
                this->length=ROUTING_TYPE_2_HEADER_LEN;
                return OP_SUCCESS;
             }
         break;

         /* Unknown routing type */
         default:
             /* If this is some routing type that we don't know about, we'll have
              * to store as much data as the header says it has. Obvioulsy, we
              * check that we received as much data as the HdrExtLen advertises,
              * and that we don't exceed our own internal limit. */
             if( ((unsigned int)(this->h.len+1))*8 > len){
               this->length=0;
               return OP_FAILURE;
             }else{
                this->reset();
                this->length=(this->h.len+1)*8;
                memcpy(&(this->h), buf, this->length);
                return OP_SUCCESS;
             }
         break;
     }
  }
 return OP_FAILURE;
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int RoutingHeader::protocol_id() const {
    return HEADER_TYPE_IPv6_ROUTE;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int RoutingHeader::validate(){

  /* Check the object's length makes sense*/
  if(this->length < ROUTING_HEADER_MIN_LEN || this->length%8!=0) {
      return OP_FAILURE;
  }

  switch(this->h.type){
     /* Routing Type 0 (deprecated by RFC 5095)*/
     case 0:
         /* Here we check that:
          * 1) The length in HdrExtLen is even.
          * 2) The length in HdrExtLen matches the octects stored in this object.
          * 3) The length in HdrExtLen does not exceed our internal limit. */
         if(this->h.len%2==1 || (this->h.len+1)*8 != this->length){
           return OP_FAILURE;
         }

         /* Also, for Type 0, the value in the SegmentsLeft field should be less
          * than or equal to the number of addresses in the packet. We verify
          * that using the value of the HDrExtLen field which, divided by two,
          * yields the number of addresses in the packet. It certainly doesn't
          * make sense for the packet to say there are 5 hops left when we
          * have less than 5 IPv6 addresses. We allow it to be less than
          * the number of addresses present in the packet because the RFC 2460
          * only talkes about segleft being greater than HDrExtLen/2, not less. */
         if(this->h.segleft > this->h.len/2){
           return OP_FAILURE;
         }
     break;

     /* Routing Type 2 (For IPv6 Mobility. See RFC 6275) */
     case 2:
         /* Check that we have the exact number of octets we expect. */
         if(this->length!= ROUTING_TYPE_2_HEADER_LEN){
           return OP_FAILURE;
         }
         /* Also check that the HdrExtLen and SegmentsLeft fields have the
          * value that RFC 6275 dictates. */
         if(this->h.segleft!=1 || this->h.len!=2){
           return OP_FAILURE;
         }
     break;

     /* Unknown routing type */
     default:
         /* If this is some routing type that we don't know about, we just
          * check that the length makes sense because we cannot make assumptions
          * about the semantics of other fields. */
         if( this->length!=(this->h.len+1)*8){
           return OP_FAILURE;
         }
     break;

  }
  return this->length;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int RoutingHeader::print(FILE *output, int detail) const {
  fprintf(output, "Routing[nh=%d len=%d type=%d segleft=%d]", this->h.nh, this->h.len, this->h.type, this->h.segleft);
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
int RoutingHeader::setNextHeader(u8 val){
  this->h.nh = val;
  return OP_SUCCESS;
} /* End of setNextHeader() */


/** Returns next header id */
u8 RoutingHeader::getNextHeader(){
  return this->h.nh;
} /* End of getNextHeader() */


/** Set routing type */
int RoutingHeader::setRoutingType(u8 val){
  this->h.type = val;
  return OP_SUCCESS;
} /* End of setRoutingType() */


/** Returns the routing type */
u8 RoutingHeader::getRoutingType(){
  return this->h.type;
} /* End of getRoutingType() */


/** Set number of segments left */
int RoutingHeader::setSegmentsLeft(u8 val){
  this->h.segleft = val;
  return OP_SUCCESS;
} /* End of setSegmentsLeft() */


/** Returns the number of segments left */
u8 RoutingHeader::getSegmentsLeft(){
  return this->h.segleft;
} /* End of getSegmentsLeft() */


/** Set number of segments left */
int RoutingHeader::addAddress(struct in6_addr val){
  /* Check we don't exceed max length */
  if((this->length + 16)>ROUTING_HEADER_MAX_LEN)
    return OP_FAILURE;
  memcpy(this->curr_addr, val.s6_addr, 16);
  this->curr_addr+=16;
  this->h.len+=2;
  this->length+=16;
  return OP_SUCCESS;
} /* End of setSegmentsLeft() */
