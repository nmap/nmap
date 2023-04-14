
/***************************************************************************
 * NEPContext.cc --                                                        *
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

#ifndef __NEPCONTEXT_H__
#define __NEPCONTEXT_H__ 1



#include "nsock.h"
#include "EchoHeader.h"
#include <vector>

/* SERVER STATE MACHINE                                                       */
/*                      _                                                     */
/*                     (O)                                                    */
/*                      |                                                     */
/* Capture Raw /        |                  Rcvd TCP Connection /              */
/* Send NEP_ECHO        |     +--------+   Send NEP_HANDSHAKE_SERVER          */
/*   +----------+       +---->| LISTEN |-----------------+                    */
/*   |          |             +--------+                 |                    */
/*   |         \|/                                      \|/                   */
/*   |     +----+------+                      +----------+-----------+        */
/*   +-----| NEP_READY |                      | NEP_HANDSHAKE_SERVER |        */
/*         |    SENT   |                      |         SENT         |        */
/*         +----+------+                      +----------+-----------+        */
/*             /|\                                       |                    */
/*              |                                        |                    */
/*              |       +---------------------+          |                    */
/*              |       | NEP_HANDSHAKE_FINAL |          |                    */
/*              +-------|        SENT         |<---------+                    */
/*                      +---------------------+   Rcvd NEP_HANDSHAKE_CLIENT/  */
/*  Rcvd NEP_PACKETSPEC /                         Send NEP_HANDSHAKE_FINAL    */
/*  Send NEP_READY                                                            */
/*                                                                            */
/*                                                                            */



#define STATE_LISTEN          0x00
#define STATE_HS_SERVER_SENT  0x01
#define STATE_HS_FINAL_SENT   0x02
#define STATE_READY_SENT      0x03

#define CLIENT_NOT_FOUND -1
typedef int clientid_t; /**< Type for client identifiers */

#define MAC_KEY_S2C_INITIAL 0x01
#define MAC_KEY_S2C         0x02
#define MAC_KEY_C2S         0x03
#define CIPHER_KEY_C2S      0x04
#define CIPHER_KEY_S2C      0x05


/* Client field specifier */
typedef struct field_spec{
  u8 field; /* Field identifier (See NEP RFC) */
  u8 len;   /* Field length */
  u8 value[PACKETSPEC_FIELD_LEN]; /* Field data */
}fspec_t;

class NEPContext {

    private:

        clientid_t id;     /**<  Client identifier */
        nsock_iod nsi;     /**<  Client nsock IOD  */
        int state;
        u32 last_seq_client;
        u32 last_seq_server;
        u8 next_iv_enc[CIPHER_BLOCK_SIZE];
        u8 next_iv_dec[CIPHER_BLOCK_SIZE];
        u8 nep_key_mac_c2s[MAC_KEY_LEN];
        u8 nep_key_mac_s2c[MAC_KEY_LEN];
        u8 nep_key_ciphertext_c2s[CIPHER_KEY_LEN];
        u8 nep_key_ciphertext_s2c[CIPHER_KEY_LEN];
        u8 server_nonce[NONCE_LEN];
        u8 client_nonce[NONCE_LEN];
        bool server_nonce_set;
        bool client_nonce_set;
        std::vector<fspec_t> fspecs;
        struct sockaddr_storage clnt_addr;

        u8 *generateKey(int key_type, size_t *final_len);

    public:

        NEPContext();
        ~NEPContext();
        void reset();

        int setIdentifier(clientid_t clnt);
        clientid_t getIdentifier();

        int setAddress(const struct sockaddr_storage &a);
        struct sockaddr_storage getAddress();

        int setNsockIOD(nsock_iod iod);
        nsock_iod getNsockIOD();

        int setState(int state);
        int getState();

        bool ready();

        int setNextEncryptionIV(u8 *block);
        u8 *getNextEncryptionIV(size_t *final_len);
        u8 *getNextEncryptionIV();

        int setNextDecryptionIV(u8 *block);
        u8 *getNextDecryptionIV(size_t *final_len);
        u8 *getNextDecryptionIV();

        int setLastServerSequence(u32 seq);
        u32 getLastServerSequence();
        u32 getNextServerSequence();
        int setLastClientSequence(u32 seq);
        u32 getLastClientSequence();
        u32 getNextClientSequence();
        int generateInitialServerSequence();
        int generateInitialClientSequence();

        int setMacKeyC2S(u8 *key);
        u8 *getMacKeyC2S();
        u8 *getMacKeyC2S(size_t *final_len);
        int generateMacKeyC2S();

        int setMacKeyS2C(u8 *key);
        u8 *getMacKeyS2C();
        u8 *getMacKeyS2C(size_t *final_len);
        int generateMacKeyS2C();

        int setCipherKeyC2S(u8 *key);
        u8 *getCipherKeyC2S();
        u8 *getCipherKeyC2S(size_t *final_len);
        int generateCipherKeyC2S();
        int generateMacKeyS2CInitial();

        int setCipherKeyS2C(u8 *key);
        u8 *getCipherKeyS2C();
        u8 *getCipherKeyS2C(size_t *final_len);
        int generateCipherKeyS2C();

        int generateClientNonce();
        int generateServerNonce();
        int setClientNonce(u8 *buff);
        u8 *getClientNonce();
        int setServerNonce(u8 *buff);
        u8 *getServerNonce();

        int addClientFieldSpec(u8 field, u8 len, u8 *value);
        fspec_t *getClientFieldSpec(int index);
        bool isDuplicateFieldSpec(u8 test_field);
        int resetClientFieldSpecs();

};

#endif /* __NEPCONTEXT_H__ */
