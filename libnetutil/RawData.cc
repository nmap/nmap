/***************************************************************************
 * RawData.cc -- The RawData Class represents a network packet payload. It *
 * is essentially a single buffer that may contain either random data or   *
 * caller supplied data. This class can be used, for example, to be linked *
 * to a UDP datagram.                                                      *
 *                                                                         *
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

#include "RawData.h"

/******************************************************************************/
/* CONTRUCTORS, DESTRUCTORS AND INITIALIZATION METHODS                        */
/******************************************************************************/
RawData::RawData(){
  this->reset();
} /* End of RawData contructor */


RawData::~RawData(){
  if(this->data!=NULL){
    free(this->data);
    this->data=NULL;
  }
} /* End of RawData destructor */


/** Sets every attribute to its default value */
void RawData::reset(){
  this->data=NULL;
  this->length=0;
} /* End of reset() */


/******************************************************************************/
/* PacketElement:: OVERWRITTEN METHODS                                        */
/******************************************************************************/

u8 * RawData::getBufferPointer(){
  return this->getBufferPointer(NULL);
} /* End of getBufferPointer() */


u8 * RawData::getBufferPointer(int *mylen){
  if(mylen!=NULL)
    *mylen=this->length;
  return this->data;
} /* End of getBufferPointer() */


/** Added for consistency with the rest of classes of the PacketElement family. */
int RawData::storeRecvData(const u8 *buf, size_t len){
  return this->store(buf, len);
} /* End of storeRecvData() */


/* Returns a protocol identifier. This is used by packet parsing funtions
 * that return linked lists of PacketElement objects, to determine the protocol
 * the object represents. */
int RawData::protocol_id() const {
    return HEADER_TYPE_RAW_DATA;
} /* End of protocol_id() */


/** Determines if the data stored in the object after an storeRecvData() call
  * is valid and safe to use. This mainly checks the length of the data but may
  * also test the value of certain protocol fields to ensure their correctness.
  * @return the length, in bytes, of the header, if its found to be valid or
  * OP_FAILURE (-1) otherwise. */
int RawData::validate(){
  return this->length;
} /* End of validate() */


/** Prints the contents of the header and calls print() on the next protocol
  * header in the chain (if there is any).
  * @return OP_SUCCESS on success and OP_FAILURE in case of error. */
int RawData::print(FILE *output, int detail) const {
  fprintf(output, "Payload[");
  fprintf(output, "%d byte%s]", this->length, (this->length!=1)? "s":"");
  if(this->next!=NULL){
    print_separator(output, detail);
    next->print(output, detail);
  }
  return OP_SUCCESS;
} /* End of print() */


/******************************************************************************/
/* PROTOCOL-SPECIFIC METHODS                                                  */
/******************************************************************************/

int RawData::store(const u8 *buf, size_t len){
  /* If buffer had already been set, try to reuse it. */
  if(this->data!=NULL){
    if( this->length >= (int)len ){
        memcpy(this->data, buf, len);
        this->length=(int)len;
        return OP_SUCCESS;
    }else{
        free(this->data);
    }
  }
  if( (this->data=(u8 *)calloc(len, sizeof(u8)))==NULL )
    return OP_FAILURE;
  memcpy(this->data, buf, len);
  this->length=(int)len;
  return OP_SUCCESS;
} /* End of store() */


int RawData::store(const char *str){
  if(str==NULL)
    return OP_FAILURE;
  else
    return this->store((const u8*)str, strlen(str));
} /* End of store() */


