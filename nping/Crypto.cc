
/***************************************************************************
 * Crypto.cc -- The Crypto Class contains miscellaneous methods and helpers*
 * that may be used to provide properties such as authentication, integrity*
 * or confidentiality.                                                     *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
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
 * including the terms and conditions of this license text as well.        *
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
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
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
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/
#include "nping.h"
#include "Crypto.h"
#include "output.h"
#include "NpingOps.h"

#ifdef HAVE_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

extern NpingOps o;

Crypto::Crypto(){
  this->reset();
} /* End of Crypto constructor */


Crypto::~Crypto(){

} /* End of Crypto destructor */


/** Sets every attribute to its default value. */
void Crypto::reset() {

} /* End of reset() */


int Crypto::hmac_sha256(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len){

  #ifdef HAVE_OPENSSL
    if( o.doCrypto() ){
        u8 result[EVP_MAX_MD_SIZE];
        memset(result, 0, EVP_MAX_MD_SIZE);
        unsigned int result_len;
        HMAC(EVP_sha256(), key, (int)key_len, inbuff, (int)inlen, result, &result_len);
        memcpy(dst_buff, result, 256/8);
        return OP_SUCCESS;
    }
  #endif
  /* Set a bogus sum: all zero */
  memset(dst_buff, 0, HMAC_SHA256_CODE_LEN);
  return OP_SUCCESS;
} /* End of hmac_sha256() */


int Crypto::aes128_cbc_encrypt(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len, u8 *iv){
  nping_print(DBG_4, "%s(%p, %lu, %p, %p, %lu, %p)", __func__, inbuff, (unsigned long)inlen, dst_buff, key, (unsigned long)key_len, iv);
  if(inbuff==NULL || dst_buff==NULL || key==NULL || iv==NULL)
      return OP_FAILURE;
  if( ((inlen%AES_BLOCK_SIZE)!=0) || key_len<AES_KEY_SIZE)
    return OP_FAILURE;

  #ifdef HAVE_OPENSSL
    if( o.doCrypto() ){
        int flen=0, flen2=0;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
          EVP_CIPHER_CTX ctx;
          EVP_CIPHER_CTX_init(&ctx);
          EVP_CIPHER_CTX_set_padding(&ctx, 0);
          int result=OP_SUCCESS;
          if( EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), key, iv)==0 ){
              nping_print(DBG_4, "EVP_EncryptInit() failed");
              result=OP_FAILURE;
          }else if( EVP_EncryptUpdate(&ctx, dst_buff, &flen, inbuff, (int)inlen)==0 ){
              nping_print(DBG_4, "EVP_EncryptUpdate() failed");
              result=OP_FAILURE;
          }else if( EVP_EncryptFinal(&ctx, dst_buff+flen, &flen2)==0 ){
              nping_print(DBG_4, "EVP_EncryptFinal() failed");
              result=OP_FAILURE;
          }
          EVP_CIPHER_CTX_cleanup(&ctx);
        #else
          EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
          EVP_CIPHER_CTX_reset(ctx);
          EVP_CIPHER_CTX_set_padding(ctx, 0);
          int result=OP_SUCCESS;
          if( EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv)==0 ){
              nping_print(DBG_4, "EVP_EncryptInit() failed");
              result=OP_FAILURE;
          }else if( EVP_EncryptUpdate(ctx, dst_buff, &flen, inbuff, (int)inlen)==0 ){
              nping_print(DBG_4, "EVP_EncryptUpdate() failed");
              result=OP_FAILURE;
          }else if( EVP_EncryptFinal(ctx, dst_buff+flen, &flen2)==0 ){
              nping_print(DBG_4, "EVP_EncryptFinal() failed");
              result=OP_FAILURE;
          }
          EVP_CIPHER_CTX_cleanup(ctx);
        #endif
        return result;
    }
  #endif
  /* Do not encrypt, just set the plaintext */
  for(size_t i=0; i<inlen; i++)
    dst_buff[i]=inbuff[i];
  return OP_SUCCESS;
} /* End of aes128_cbc_encrypt() */


int Crypto::aes128_cbc_decrypt(u8 *inbuff, size_t inlen, u8 *dst_buff, u8 *key, size_t key_len, u8 *iv){
  nping_print(DBG_4, "%s(%p, %lu, %p, %p, %lu, %p)", __func__, inbuff, (unsigned long)inlen, dst_buff, key, (unsigned long)key_len, iv);
  if(inbuff==NULL || dst_buff==NULL || key==NULL || iv==NULL)
      return OP_FAILURE;
  if( ((inlen%AES_BLOCK_SIZE)!=0) || key_len<AES_KEY_SIZE)
    return OP_FAILURE;

  #ifdef HAVE_OPENSSL
    if( o.doCrypto() ){
        int flen1=0, flen2=0;
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
          EVP_CIPHER_CTX ctx;
          EVP_CIPHER_CTX_init(&ctx);
          EVP_CIPHER_CTX_set_padding(&ctx, 0);
          int result=OP_SUCCESS;
          if( EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), key, iv)==0 ){
              nping_print(DBG_4, "EVP_DecryptInit() failed");
              result=OP_FAILURE;
          }else if( EVP_DecryptUpdate(&ctx, dst_buff, &flen1, inbuff, (int)inlen)==0 ){
              nping_print(DBG_4, "EVP_DecryptUpdate() failed");
              result=OP_FAILURE;
          }else  if( EVP_DecryptFinal(&ctx, dst_buff+flen1, &flen2)==0 ){
              nping_print(DBG_4, "OpenSSL bug: it says EVP_DecryptFinal() failed when it didn't (%s).",
                      ERR_error_string(ERR_peek_last_error(), NULL));
        #else
          EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
          EVP_CIPHER_CTX_reset(ctx);
          EVP_CIPHER_CTX_set_padding(ctx, 0);
          int result=OP_SUCCESS;
          if( EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv)==0 ){
              nping_print(DBG_4, "EVP_DecryptInit() failed");
              result=OP_FAILURE;
          }else if( EVP_DecryptUpdate(ctx, dst_buff, &flen1, inbuff, (int)inlen)==0 ){
              nping_print(DBG_4, "EVP_DecryptUpdate() failed");
              result=OP_FAILURE;
          }else  if( EVP_DecryptFinal(ctx, dst_buff+flen1, &flen2)==0 ){
              nping_print(DBG_4, "OpenSSL bug: it says EVP_DecryptFinal() failed when it didn't (%s).",
                      ERR_error_string(ERR_peek_last_error(), NULL));
        #endif
            /* We do not return OP_FAILURE in this case because the
             * EVP_DecryptFinal() function seems to be buggy and fails when it shouldn't.
             * We are passing a buffer whose length is multiple of the AES block
             * size, we've disable padding, and still, the call fails.
             * The call to EVP_DecryptUpdate() says we've decrypted all blocks but
             * the last one and then EVP_DecryptFinal says we have decrypted nothing.
             * However I've tested this for hours and everything works fine. The
             * full buffer is decrypted correctly, from the first to the last byte,
             * so we return OP_SUCCESS even if OpenSSL says the opposite. */

            /* NOTE for developers debugging memory issues with Valgrind:
             * None of these seems to free OpenSSL's internal error structures.
             * Valgrind currently reports things like:
             ==12849== 592 bytes in 1 blocks are still reachable in loss record 7 of 9
            ==12849==    at 0x4C284A8: malloc (vg_replace_malloc.c:236)
            ==12849==    by 0x531BF21: CRYPTO_malloc (in /lib/libcrypto.so.0.9.8)
            ==12849==    by 0x537F25D: ERR_get_state (in /lib/libcrypto.so.0.9.8)
            ==12849==    by 0x537E7BE: ERR_put_error (in /lib/libcrypto.so.0.9.8)
            ==12849==    by 0x5381EB0: EVP_DecryptFinal_ex (in /lib/libcrypto.so.0.9.8)
            ==12849==    by 0x429A49: Crypto::aes128_cbc_decrypt(unsigned char*...
            ==12849==    by 0x41ABBA: EchoHeader::decrypt(unsigned char*, unsign...
             */
            //ERR_clear_error();
            //ERR_free_strings();
            //ERR_pop_to_mark();
        }
        #if OPENSSL_VERSION_NUMBER < 0x10100000L
          EVP_CIPHER_CTX_cleanup(&ctx);
        #else
          EVP_CIPHER_CTX_reset(ctx);
        #endif
        return result;
    }
  #endif
  /* Do not decrypt, just leave the ciphertext */
  for(size_t i=0; i<inlen; i++)
    dst_buff[i]=inbuff[i];
  return OP_SUCCESS;
} /* End of aes128_cbc_decrypt() */


int Crypto::generateNonce(u8 *dst_buff, size_t bufflen){
  nping_print(DBG_4, "%s()", __func__);
  if(dst_buff==NULL || bufflen<=0)
      return OP_FAILURE;
  #ifdef HAVE_OPENSSL
    // Get cryptographically secure random data from OpenSSL
    // @todo TODO finish this.
    get_random_bytes(dst_buff, bufflen); /* Provided by nbase */
  #else
    get_random_bytes(dst_buff, bufflen); /* Provided by nbase */
  #endif
  return OP_SUCCESS;
} /* End of generateNonce() */


#define TIMES_KEY_DERIVATION 1000
u8 *Crypto::deriveKey(const u8 *from, size_t fromlen, size_t *final_len){
  nping_print(DBG_4, "%s()", __func__);
  if(from==NULL || fromlen==0)
      return NULL;

  #ifdef HAVE_OPENSSL
    if( o.doCrypto() ){
        static u8 hash[MAX(SHA256_HASH_LEN, EVP_MAX_MD_SIZE)];
        static u8 next[MAX(SHA256_HASH_LEN, EVP_MAX_MD_SIZE)];
        unsigned int lastlen;
      #if OPENSSL_VERSION_NUMBER < 0x10100000L
        EVP_MD_CTX ctx;
        EVP_MD_CTX_init(&ctx);

        if( EVP_MD_size(EVP_sha256()) != SHA256_HASH_LEN )
          nping_fatal(QT_2, "OpenSSL is broken. SHA256 len is %d\n", EVP_MD_size(EVP_sha256()) );

        /* Compute the SHA256 hash of the supplied buffer */
        EVP_DigestInit(&ctx, EVP_sha256());
        EVP_DigestUpdate(&ctx, from, fromlen);
        EVP_DigestFinal(&ctx, hash, &lastlen);

        /* Now compute the 1000th hash of that hash */
        for(int i=0; i<TIMES_KEY_DERIVATION; i++){
        EVP_MD_CTX_init(&ctx);
        EVP_DigestInit(&ctx, EVP_sha256());
        EVP_DigestUpdate(&ctx, hash, SHA256_HASH_LEN);
        EVP_DigestFinal(&ctx, next, &lastlen);
        memcpy(hash, next, SHA256_HASH_LEN);
        }
        if(final_len!=NULL)
          *final_len=SHA256_HASH_LEN;

        EVP_MD_CTX_cleanup(&ctx);
      #else
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_MD_CTX_init(ctx);

        if( EVP_MD_size(EVP_sha256()) != SHA256_HASH_LEN )
          nping_fatal(QT_2, "OpenSSL is broken. SHA256 len is %d\n", EVP_MD_size(EVP_sha256()) );

        /* Compute the SHA256 hash of the supplied buffer */
        EVP_DigestInit(ctx, EVP_sha256());
        EVP_DigestUpdate(ctx, from, fromlen);
        EVP_DigestFinal(ctx, hash, &lastlen);

        /* Now compute the 1000th hash of that hash */
        for(int i=0; i<TIMES_KEY_DERIVATION; i++){
        EVP_MD_CTX_init(ctx);
        EVP_DigestInit(ctx, EVP_sha256());
        EVP_DigestUpdate(ctx, hash, SHA256_HASH_LEN);
        EVP_DigestFinal(ctx, next, &lastlen);
        memcpy(hash, next, SHA256_HASH_LEN);
        }
        if(final_len!=NULL)
          *final_len=SHA256_HASH_LEN;

        EVP_MD_CTX_free(ctx);
      #endif
        return hash;
    }
  #endif
  static u8 zerohash[SHA256_HASH_LEN];
  memset(zerohash, 0, SHA256_HASH_LEN);
  if(final_len!=NULL)
      *final_len=SHA256_HASH_LEN;
  return zerohash;

} /* End of deriveKey() */
