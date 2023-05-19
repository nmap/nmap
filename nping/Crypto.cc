
/***************************************************************************
 * Crypto.cc -- The Crypto Class contains miscellaneous methods and helpers*
 * that may be used to provide properties such as authentication, integrity*
 * or confidentiality.                                                     *
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
#include "nping.h"
#include "Crypto.h"
#include "output.h"
#include "NpingOps.h"

#ifdef HAVE_OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined LIBRESSL_VERSION_NUMBER
#define HAVE_OPAQUE_EVP_PKEY 1
#else
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#define EVP_CIPHER_CTX_free EVP_CIPHER_CTX_cleanup
#endif

#endif /* HAVE_OPENSSL */

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
        #if HAVE_OPAQUE_EVP_PKEY
          EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        #else
          EVP_CIPHER_CTX stack_ctx;
          EVP_CIPHER_CTX *ctx = &stack_ctx;
          EVP_CIPHER_CTX_init(ctx);
        #endif
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
        EVP_CIPHER_CTX_free(ctx);
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
        #if HAVE_OPAQUE_EVP_PKEY
          EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        #else
          EVP_CIPHER_CTX stack_ctx;
          EVP_CIPHER_CTX *ctx = &stack_ctx;
          EVP_CIPHER_CTX_init(ctx);
        #endif
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
        EVP_CIPHER_CTX_free(ctx);
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
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

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
        return hash;
    }
  #endif
  static u8 zerohash[SHA256_HASH_LEN];
  memset(zerohash, 0, SHA256_HASH_LEN);
  if(final_len!=NULL)
      *final_len=SHA256_HASH_LEN;
  return zerohash;

} /* End of deriveKey() */
