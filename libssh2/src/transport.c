/* Copyright (C) The Written Word, Inc.
 * Copyright (C) Daniel Stenberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * This file handles reading and writing to the SECSH transport layer. RFC4253.
 */

#include "libssh2_priv.h"

#include <errno.h>
#include <ctype.h>
#include <assert.h>

#include "transport.h"
#include "mac.h"

#ifdef LIBSSH2DEBUG
#define UNPRINTABLE_CHAR '.'
static void
debugdump(LIBSSH2_SESSION * session,
          const char *desc, const unsigned char *ptr, size_t size)
{
    size_t i;
    size_t c;
    unsigned int width = 0x10;
    char buffer[256];  /* Must be enough for width*4 + about 30 or so */
    size_t used;
    static const char *hex_chars = "0123456789ABCDEF";

    if(!(session->showmask & LIBSSH2_TRACE_TRANS)) {
        /* not asked for, bail out */
        return;
    }

    used = snprintf(buffer, sizeof(buffer), "=> %s (%lu bytes)\n",
                    desc, (unsigned long) size);
    if(session->tracehandler)
        (session->tracehandler)(session, session->tracehandler_context,
                                buffer, used);
    else
        fprintf(stderr, "%s", buffer);

    for(i = 0; i < size; i += width) {

        used = snprintf(buffer, sizeof(buffer), "%04lx: ", (long)i);

        /* hex not disabled, show it */
        for(c = 0; c < width; c++) {
            if(i + c < size) {
                buffer[used++] = hex_chars[(ptr[i + c] >> 4) & 0xF];
                buffer[used++] = hex_chars[ptr[i + c] & 0xF];
            }
            else {
                buffer[used++] = ' ';
                buffer[used++] = ' ';
            }

            buffer[used++] = ' ';
            if((width/2) - 1 == c)
                buffer[used++] = ' ';
        }

        buffer[used++] = ':';
        buffer[used++] = ' ';

        for(c = 0; (c < width) && (i + c < size); c++) {
            buffer[used++] = isprint(ptr[i + c]) ?
                ptr[i + c] : UNPRINTABLE_CHAR;
        }
        buffer[used++] = '\n';
        buffer[used] = 0;

        if(session->tracehandler)
            (session->tracehandler)(session, session->tracehandler_context,
                                    buffer, used);
        else
            fprintf(stderr, "%s", buffer);
    }
}
#else
#define debugdump(a,x,y,z) do {} while(0)
#endif


/* decrypt() decrypts 'len' bytes from 'source' to 'dest' in units of
 * blocksize.
 *
 * returns 0 on success and negative on failure
 */

static int
decrypt(LIBSSH2_SESSION * session, unsigned char *source,
        unsigned char *dest, ssize_t len, int firstlast)
{
    struct transportpacket *p = &session->packet;
    int blocksize = session->remote.crypt->blocksize;

    /* if we get called with a len that isn't an even number of blocksizes
       we risk losing those extra bytes. AAD is an exception, since those first
       few bytes aren't encrypted so it throws off the rest of the count. */
    if(!CRYPT_FLAG_L(session, PKTLEN_AAD))
        assert((len % blocksize) == 0);

    while(len > 0) {
        /* normally decrypt up to blocksize bytes at a time */
        ssize_t decryptlen = LIBSSH2_MIN(blocksize, len);
        /* The first block is special (since it needs to be decoded to get the
           length of the remainder of the block) and takes priority. When the
           length finally gets to the last blocksize bytes, and there's no
           more data to come, it's the end. */
        int lowerfirstlast = IS_FIRST(firstlast) ? FIRST_BLOCK :
            ((len <= blocksize) ? firstlast : MIDDLE_BLOCK);
        /* If the last block would be less than a whole blocksize, combine it
           with the previous block to make it larger. This ensures that the
           whole MAC is included in a single decrypt call. */
        if(CRYPT_FLAG_L(session, PKTLEN_AAD) && IS_LAST(firstlast)
           && (len < blocksize*2)) {
            decryptlen = len;
            lowerfirstlast = LAST_BLOCK;
        }

        if(session->remote.crypt->crypt(session, 0, source, decryptlen,
                                        &session->remote.crypt_abstract,
                                        lowerfirstlast)) {
            LIBSSH2_FREE(session, p->payload);
            return LIBSSH2_ERROR_DECRYPT;
        }

        /* if the crypt() function would write to a given address it
           wouldn't have to memcpy() and we could avoid this memcpy()
           too */
        memcpy(dest, source, decryptlen);

        len -= decryptlen;       /* less bytes left */
        dest += decryptlen;      /* advance write pointer */
        source += decryptlen;    /* advance read pointer */
    }
    return LIBSSH2_ERROR_NONE;         /* all is fine */
}

/*
 * fullpacket() gets called when a full packet has been received and properly
 * collected.
 */
static int
fullpacket(LIBSSH2_SESSION * session, int encrypted /* 1 or 0 */ )
{
    unsigned char macbuf[MAX_MACSIZE];
    struct transportpacket *p = &session->packet;
    int rc;
    int compressed;
    const LIBSSH2_MAC_METHOD *remote_mac = NULL;
    uint32_t seq = session->remote.seqno;

    if(!encrypted || (!CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET) &&
                      !CRYPT_FLAG_R(session, INTEGRATED_MAC))) {
        remote_mac = session->remote.mac;
    }

    if(session->fullpacket_state == libssh2_NB_state_idle) {
        session->fullpacket_macstate = LIBSSH2_MAC_CONFIRMED;
        session->fullpacket_payload_len = p->packet_length - 1;

        if(encrypted && remote_mac) {

            /* Calculate MAC hash */
            int etm = remote_mac->etm;
            size_t mac_len = remote_mac->mac_len;
            if(etm) {
                /* store hash here */
                remote_mac->hash(session, macbuf,
                                 session->remote.seqno,
                                 p->payload, p->total_num - mac_len,
                                 NULL, 0,
                                 &session->remote.mac_abstract);
            }
            else {
                /* store hash here */
                remote_mac->hash(session, macbuf,
                                 session->remote.seqno,
                                 p->init, 5,
                                 p->payload,
                                 session->fullpacket_payload_len,
                                 &session->remote.mac_abstract);
            }

            /* Compare the calculated hash with the MAC we just read from
             * the network. The read one is at the very end of the payload
             * buffer. Note that 'payload_len' here is the packet_length
             * field which includes the padding but not the MAC.
             */
            if(memcmp(macbuf, p->payload + p->total_num - mac_len, mac_len)) {
                _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                               "Failed MAC check"));
                session->fullpacket_macstate = LIBSSH2_MAC_INVALID;

            }
            else if(etm) {
                /* MAC was ok and we start by decrypting the first block that
                   contains padding length since this allows us to decrypt
                   all other blocks to the right location in memory
                   avoiding moving a larger block of memory one byte. */
                unsigned char first_block[MAX_BLOCKSIZE];
                ssize_t decrypt_size;
                unsigned char *decrypt_buffer;
                int blocksize = session->remote.crypt->blocksize;

                rc = decrypt(session, p->payload + 4,
                             first_block, blocksize, FIRST_BLOCK);
                if(rc) {
                    return rc;
                }

                /* we need buffer for decrypt */
                decrypt_size = p->total_num - mac_len - 4;
                decrypt_buffer = LIBSSH2_ALLOC(session, decrypt_size);
                if(!decrypt_buffer) {
                    return LIBSSH2_ERROR_ALLOC;
                }

                /* grab padding length and copy anything else
                   into target buffer */
                p->padding_length = first_block[0];
                if(blocksize > 1) {
                    memcpy(decrypt_buffer, first_block + 1, blocksize - 1);
                }

                /* decrypt all other blocks packet */
                if(blocksize < decrypt_size) {
                    rc = decrypt(session, p->payload + blocksize + 4,
                                 decrypt_buffer + blocksize - 1,
                                 decrypt_size - blocksize, LAST_BLOCK);
                    if(rc) {
                        LIBSSH2_FREE(session, decrypt_buffer);
                        return rc;
                    }
                }

                /* replace encrypted payload with plain text payload */
                LIBSSH2_FREE(session, p->payload);
                p->payload = decrypt_buffer;
            }
        }
        else if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
            /* etm trim off padding byte from payload */
            memmove(p->payload, &p->payload[1], p->packet_length - 1);
        }

        session->remote.seqno++;

        /* ignore the padding */
        session->fullpacket_payload_len -= p->padding_length;

        /* Check for and deal with decompression */
        compressed = session->local.comp &&
                     session->local.comp->compress &&
                     ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
                      session->local.comp->use_in_auth);

        if(compressed && session->remote.comp_abstract) {
            /*
             * The buffer for the decompression (remote.comp_abstract) is
             * initialised in time when it is needed so as long it is NULL we
             * cannot decompress.
             */

            unsigned char *data;
            size_t data_len;
            rc = session->remote.comp->decomp(session,
                                              &data, &data_len,
                                              LIBSSH2_PACKET_MAXDECOMP,
                                              p->payload,
                                              session->fullpacket_payload_len,
                                              &session->remote.comp_abstract);
            LIBSSH2_FREE(session, p->payload);
            if(rc)
                return rc;

            p->payload = data;
            session->fullpacket_payload_len = data_len;
        }

        session->fullpacket_packet_type = p->payload[0];

        debugdump(session, "libssh2_transport_read() plain",
                  p->payload, session->fullpacket_payload_len);

        session->fullpacket_state = libssh2_NB_state_created;
    }

    if(session->fullpacket_state == libssh2_NB_state_created) {
        rc = _libssh2_packet_add(session, p->payload,
                                 session->fullpacket_payload_len,
                                 session->fullpacket_macstate, seq);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return rc;
        if(rc) {
            session->fullpacket_state = libssh2_NB_state_idle;
            return rc;
        }
    }

    session->fullpacket_state = libssh2_NB_state_idle;

    if(session->kex_strict &&
        session->fullpacket_packet_type == SSH_MSG_NEWKEYS) {
        session->remote.seqno = 0;
    }

    return session->fullpacket_packet_type;
}


/*
 * _libssh2_transport_read
 *
 * Collect a packet into the input queue.
 *
 * Returns packet type added to input queue (0 if nothing added), or a
 * negative error number.
 */

/*
 * This function reads the binary stream as specified in chapter 6 of RFC4253
 * "The Secure Shell (SSH) Transport Layer Protocol"
 *
 * DOES NOT call _libssh2_error() for ANY error case.
 */
int _libssh2_transport_read(LIBSSH2_SESSION * session)
{
    int rc;
    struct transportpacket *p = &session->packet;
    ssize_t remainpack; /* how much there is left to add to the current payload
                           package */
    ssize_t remainbuf;  /* how much data there is remaining in the buffer to
                           deal with before we should read more from the
                           network */
    ssize_t numbytes;   /* how much data to deal with from the buffer on this
                           iteration through the loop */
    ssize_t numdecrypt; /* number of bytes to decrypt this iteration */
    unsigned char block[MAX_BLOCKSIZE]; /* working block buffer */
    int blocksize;  /* minimum number of bytes we need before we can
                       use them */
    int encrypted = 1; /* whether the packet is encrypted or not */
    int firstlast = FIRST_BLOCK; /* if the first or last block to decrypt */
    unsigned int auth_len = 0; /* length of the authentication tag */
    const LIBSSH2_MAC_METHOD *remote_mac = NULL; /* The remote MAC, if used */

    /* default clear the bit */
    session->socket_block_directions &= ~LIBSSH2_SESSION_BLOCK_INBOUND;

    /*
     * All channels, systems, subsystems, etc eventually make it down here
     * when looking for more incoming data. If a key exchange is going on
     * (LIBSSH2_STATE_EXCHANGING_KEYS bit is set) then the remote end will
     * ONLY send key exchange related traffic. In non-blocking mode, there is
     * a chance to break out of the kex_exchange function with an EAGAIN
     * status, and never come back to it. If LIBSSH2_STATE_EXCHANGING_KEYS is
     * active, then we must redirect to the key exchange. However, if
     * kex_exchange is active (as in it is the one that calls this execution
     * of packet_read, then don't redirect, as that would be an infinite loop!
     */

    if(session->state & LIBSSH2_STATE_EXCHANGING_KEYS &&
        !(session->state & LIBSSH2_STATE_KEX_ACTIVE)) {

        /* Whoever wants a packet won't get anything until the key re-exchange
         * is done!
         */
        _libssh2_debug((session, LIBSSH2_TRACE_TRANS, "Redirecting into the"
                       " key re-exchange from _libssh2_transport_read"));
        rc = _libssh2_kex_exchange(session, 1, &session->startup_key_state);
        if(rc)
            return rc;
    }

    /*
     * =============================== NOTE ===============================
     * I know this is very ugly and not a really good use of "goto", but
     * this case statement would be even uglier to do it any other way
     */
    if(session->readPack_state == libssh2_NB_state_jump1) {
        session->readPack_state = libssh2_NB_state_idle;
        encrypted = session->readPack_encrypted;
        goto libssh2_transport_read_point1;
    }

    do {
        int etm;
        if(session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
            return LIBSSH2_ERROR_SOCKET_DISCONNECT;
        }

        if(session->state & LIBSSH2_STATE_NEWKEYS) {
            blocksize = session->remote.crypt->blocksize;
        }
        else {
            encrypted = 0;      /* not encrypted */
            blocksize = 5;      /* not strictly true, but we can use 5 here to
                                   make the checks below work fine still */
        }

        if(encrypted) {
            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
                auth_len = session->remote.crypt->auth_len;
            }
            else {
                remote_mac = session->remote.mac;
            }
        }

        etm = encrypted && remote_mac ? remote_mac->etm : 0;

        /* read/use a whole big chunk into a temporary area stored in
           the LIBSSH2_SESSION struct. We will decrypt data from that
           buffer into the packet buffer so this temp one doesn't have
           to be able to keep a whole SSH packet, just be large enough
           so that we can read big chunks from the network layer. */

        /* how much data there is remaining in the buffer to deal with
           before we should read more from the network */
        remainbuf = p->writeidx - p->readidx;

        /* if remainbuf turns negative we have a bad internal error */
        assert(remainbuf >= 0);

        if(remainbuf < blocksize ||
           (CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)
            && ((ssize_t)p->total_num) > remainbuf)) {
            /* If we have less than a blocksize left, it is too
               little data to deal with, read more */
            ssize_t nread;

            /* move any remainder to the start of the buffer so
               that we can do a full refill */
            if(remainbuf) {
                memmove(p->buf, &p->buf[p->readidx], remainbuf);
                p->readidx = 0;
                p->writeidx = remainbuf;
            }
            else {
                /* nothing to move, just zero the indexes */
                p->readidx = p->writeidx = 0;
            }

            /* now read a big chunk from the network into the temp buffer */
            nread = LIBSSH2_RECV(session, &p->buf[remainbuf],
                                 PACKETBUFSIZE - remainbuf,
                                 LIBSSH2_SOCKET_RECV_FLAGS(session));
            if(nread <= 0) {
                /* check if this is due to EAGAIN and return the special
                   return code if so, error out normally otherwise */
                if((nread < 0) && (nread == -EAGAIN)) {
                    session->socket_block_directions |=
                        LIBSSH2_SESSION_BLOCK_INBOUND;
                    return LIBSSH2_ERROR_EAGAIN;
                }
                _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                               "Error recving %ld bytes (got %ld)",
                               (long)(PACKETBUFSIZE - remainbuf),
                               (long)-nread));
                return LIBSSH2_ERROR_SOCKET_RECV;
            }
            _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                           "Recved %ld/%ld bytes to %p+%ld", (long)nread,
                           (long)(PACKETBUFSIZE - remainbuf), (void *)p->buf,
                           (long)remainbuf));

            debugdump(session, "libssh2_transport_read() raw",
                      &p->buf[remainbuf], nread);
            /* advance write pointer */
            p->writeidx += nread;

            /* update remainbuf counter */
            remainbuf = p->writeidx - p->readidx;
        }

        /* how much data to deal with from the buffer */
        numbytes = remainbuf;

        if(!p->total_num) {
            size_t total_num; /* the number of bytes following the initial
                                 (5 bytes) packet length and padding length
                                 fields */

            /* packet length is not encrypted in encode-then-mac mode
               and we donøt need to decrypt first block */
            ssize_t required_size = etm ? 4 : blocksize;

            /* No payload package area allocated yet. To know the
               size of this payload, we need enough to decrypt the first
               blocksize data. */

            if(numbytes < required_size) {
                /* we can't act on anything less than blocksize, but this
                   check is only done for the initial block since once we have
                   got the start of a block we can in fact deal with fractions
                */
                session->socket_block_directions |=
                    LIBSSH2_SESSION_BLOCK_INBOUND;
                return LIBSSH2_ERROR_EAGAIN;
            }

            if(etm) {
                /* etm size field is not encrypted */
                memcpy(block, &p->buf[p->readidx], 4);
                memcpy(p->init, &p->buf[p->readidx], 4);
            }
            else if(encrypted && session->remote.crypt->get_len) {
                unsigned int len = 0;
                unsigned char *ptr = NULL;

                rc = session->remote.crypt->get_len(session,
                                            session->remote.seqno,
                                            &p->buf[p->readidx],
                                            numbytes,
                                            &len,
                                            &session->remote.crypt_abstract);

                if(rc != LIBSSH2_ERROR_NONE) {
                    p->total_num = 0;   /* no packet buffer available */
                    if(p->payload)
                        LIBSSH2_FREE(session, p->payload);
                    p->payload = NULL;
                    return rc;
                }

                /* store size in buffers for use below */
                ptr = &block[0];
                _libssh2_store_u32(&ptr, len);

                ptr = &p->init[0];
                _libssh2_store_u32(&ptr, len);
            }
            else {
                if(encrypted) {
                    /* first decrypted block */
                    rc = decrypt(session, &p->buf[p->readidx],
                                 block, blocksize, FIRST_BLOCK);
                    if(rc != LIBSSH2_ERROR_NONE) {
                        return rc;
                    }
                    /* Save the first 5 bytes of the decrypted package, to be
                       used in the hash calculation later down.
                       This is ignored in the INTEGRATED_MAC case. */
                    memcpy(p->init, block, 5);
                }
                else {
                    /* the data is plain, just copy it verbatim to
                       the working block buffer */
                    memcpy(block, &p->buf[p->readidx], blocksize);
                }

                /* advance the read pointer */
                p->readidx += blocksize;

                /* we now have the initial blocksize bytes decrypted,
                 * and we can extract packet and padding length from it
                 */
                p->packet_length = _libssh2_ntohu32(block);
            }

            if(!encrypted || !CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
                if(p->packet_length < 1) {
                    return LIBSSH2_ERROR_DECRYPT;
                }
                else if(p->packet_length > LIBSSH2_PACKET_MAXPAYLOAD) {
                    return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
                }

                if(etm) {
                    /* we collect entire undecrypted packet including the
                     packet length field that we run MAC over */
                    p->packet_length = _libssh2_ntohu32(block);
                    total_num = 4 + p->packet_length +
                    remote_mac->mac_len;
                }
                else {
                    /* padding_length has not been authenticated yet, but it
                     won't actually be used (except for the sanity check
                     immediately following) until after the entire packet is
                     authenticated, so this is safe. */
                    p->padding_length = block[4];
                    if(p->padding_length > p->packet_length - 1) {
                        return LIBSSH2_ERROR_DECRYPT;
                    }

                    /* total_num is the number of bytes following the initial
                     (5 bytes) packet length and padding length fields */
                    total_num = p->packet_length - 1 +
                    (encrypted ? remote_mac->mac_len : 0);
                }
            }
            else {
                /* advance the read pointer past size field if the packet
                 length is not required for decryption */

                /* add size field to be included in total packet size
                 * calculation so it doesn't get dropped off on subsequent
                 * partial reads
                 */
                total_num = 4;

                p->packet_length = _libssh2_ntohu32(block);
                if(p->packet_length < 1)
                    return LIBSSH2_ERROR_DECRYPT;

                /* total_num may include size field, however due to existing
                 * logic it needs to be removed after the entire packet is read
                 */

                total_num += p->packet_length +
                    (remote_mac ? remote_mac->mac_len : 0) + auth_len;

                /* don't know what padding is until we decrypt the full
                   packet */
                p->padding_length = 0;
            }

            /* RFC4253 section 6.1 Maximum Packet Length says:
             *
             * "All implementations MUST be able to process
             * packets with uncompressed payload length of 32768
             * bytes or less and total packet size of 35000 bytes
             * or less (including length, padding length, payload,
             * padding, and MAC.)."
             */
            if(total_num > LIBSSH2_PACKET_MAXPAYLOAD || total_num == 0) {
                return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
            }

            /* Get a packet handle put data into. We get one to
               hold all data, including padding and MAC. */
            p->payload = LIBSSH2_ALLOC(session, total_num);
            if(!p->payload) {
                return LIBSSH2_ERROR_ALLOC;
            }
            p->total_num = total_num;
            /* init write pointer to start of payload buffer */
            p->wptr = p->payload;

            if(!encrypted || !CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
                if(!etm && blocksize > 5) {
                    /* copy the data from index 5 to the end of
                     the blocksize from the temporary buffer to
                     the start of the decrypted buffer */
                    if(blocksize - 5 <= (int) total_num) {
                        memcpy(p->wptr, &block[5], blocksize - 5);
                        p->wptr += blocksize - 5; /* advance write pointer */
                        if(etm) {
                            /* advance past unencrypted packet length */
                            p->wptr += 4;
                        }
                    }
                    else {
                        if(p->payload)
                            LIBSSH2_FREE(session, p->payload);
                        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
                    }
                }

                /* init the data_num field to the number of bytes of
                 the package read so far */
                p->data_num = p->wptr - p->payload;

                /* we already dealt with a blocksize worth of data */
                if(!etm)
                    numbytes -= blocksize;
            }
            else {
                /* haven't started reading payload yet */
                p->data_num = 0;

                /* we already dealt with packet size worth of data */
                if(!encrypted)
                    numbytes -= 4;
            }
        }

        /* how much there is left to add to the current payload
           package */
        remainpack = p->total_num - p->data_num;

        if(numbytes > remainpack) {
            /* if we have more data in the buffer than what is going into this
               particular packet, we limit this round to this packet only */
            numbytes = remainpack;
        }

        if(encrypted && CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
            if(numbytes < remainpack) {
                /* need a full packet before checking MAC */
                session->socket_block_directions |=
                LIBSSH2_SESSION_BLOCK_INBOUND;
                return LIBSSH2_ERROR_EAGAIN;
            }

            /* we have a full packet, now remove the size field from numbytes
               and total_num to process only the packet data */
            numbytes -= 4;
            p->total_num -= 4;
        }

        if(encrypted && !etm) {
            /* At the end of the incoming stream, there is a MAC,
               and we don't want to decrypt that since we need it
               "raw". We MUST however decrypt the padding data
               since it is used for the hash later on. */
            int skip = (remote_mac ? remote_mac->mac_len : 0) + auth_len;

            if(CRYPT_FLAG_R(session, INTEGRATED_MAC))
                /* This crypto method DOES need the MAC to go through
                   decryption so it can be authenticated. */
                skip = 0;

            /* if what we have plus numbytes is bigger than the
               total minus the skip margin, we should lower the
               amount to decrypt even more */
            if((p->data_num + numbytes) >= (p->total_num - skip)) {
                /* decrypt the entire rest of the package */
                numdecrypt = LIBSSH2_MAX(0,
                    (int)(p->total_num - skip) - (int)p->data_num);
                firstlast = LAST_BLOCK;
            }
            else {
                ssize_t frac;
                numdecrypt = numbytes;
                frac = numdecrypt % blocksize;
                if(frac) {
                    /* not an aligned amount of blocks, align it by reducing
                       the number of bytes processed this loop */
                    numdecrypt -= frac;
                    /* and make it no unencrypted data
                       after it */
                    numbytes = 0;
                }
                if(CRYPT_FLAG_R(session, INTEGRATED_MAC)) {
                    /* Make sure that we save enough bytes to make the last
                     * block large enough to hold the entire integrated MAC */
                    numdecrypt = LIBSSH2_MIN(numdecrypt,
                        (int)(p->total_num - skip - blocksize - p->data_num));
                    numbytes = 0;
                }
                firstlast = MIDDLE_BLOCK;
            }
        }
        else {
            /* unencrypted data should not be decrypted at all */
            numdecrypt = 0;
        }
        assert(numdecrypt >= 0);

        /* if there are bytes to decrypt, do that */
        if(numdecrypt > 0) {
            /* now decrypt the lot */
            if(CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
                rc = session->remote.crypt->crypt(session,
                                               session->remote.seqno,
                                               &p->buf[p->readidx],
                                               numdecrypt,
                                               &session->remote.crypt_abstract,
                                               0);

                if(rc != LIBSSH2_ERROR_NONE) {
                    p->total_num = 0;   /* no packet buffer available */
                    return rc;
                }

                memcpy(p->wptr, &p->buf[p->readidx], numbytes);

                /* advance read index past size field now that we've decrypted
                   full packet */
                p->readidx += 4;

                /* include auth tag in bytes decrypted */
                numdecrypt += auth_len;

                /* set padding now that the packet has been verified and
                   decrypted */
                p->padding_length = p->wptr[0];

                if(p->padding_length > p->packet_length - 1) {
                    return LIBSSH2_ERROR_DECRYPT;
                }
            }
            else {
                rc = decrypt(session, &p->buf[p->readidx], p->wptr, numdecrypt,
                             firstlast);

                if(rc != LIBSSH2_ERROR_NONE) {
                    p->total_num = 0;   /* no packet buffer available */
                    return rc;
                }
            }

            /* advance the read pointer */
            p->readidx += numdecrypt;
            /* advance write pointer */
            p->wptr += numdecrypt;
            /* increase data_num */
            p->data_num += numdecrypt;

            /* bytes left to take care of without decryption */
            numbytes -= numdecrypt;
        }

        /* if there are bytes to copy that aren't decrypted,
           copy them as-is to the target buffer */
        if(numbytes > 0) {

            if((size_t)numbytes <= (p->total_num - (p->wptr - p->payload))) {
                memcpy(p->wptr, &p->buf[p->readidx], numbytes);
            }
            else {
                if(p->payload)
                    LIBSSH2_FREE(session, p->payload);
                return LIBSSH2_ERROR_OUT_OF_BOUNDARY;
            }

            /* advance the read pointer */
            p->readidx += numbytes;
            /* advance write pointer */
            p->wptr += numbytes;
            /* increase data_num */
            p->data_num += numbytes;
        }

        /* now check how much data there's left to read to finish the
           current packet */
        remainpack = p->total_num - p->data_num;

        if(!remainpack) {
            /* we have a full packet */
libssh2_transport_read_point1:
            rc = fullpacket(session, encrypted);
            if(rc == LIBSSH2_ERROR_EAGAIN) {

                if(session->packAdd_state != libssh2_NB_state_idle) {
                    /* fullpacket only returns LIBSSH2_ERROR_EAGAIN if
                     * libssh2_packet_add() returns LIBSSH2_ERROR_EAGAIN. If
                     * that returns LIBSSH2_ERROR_EAGAIN but the packAdd_state
                     * is idle, then the packet has been added to the brigade,
                     * but some immediate action that was taken based on the
                     * packet type (such as key re-exchange) is not yet
                     * complete.  Clear the way for a new packet to be read
                     * in.
                     */
                    session->readPack_encrypted = encrypted;
                    session->readPack_state = libssh2_NB_state_jump1;
                }

                return rc;
            }

            p->total_num = 0;   /* no packet buffer available */

            return rc;
        }
    } while(1);                /* loop */

    return LIBSSH2_ERROR_SOCKET_RECV; /* we never reach this point */
}

static int
send_existing(LIBSSH2_SESSION *session, const unsigned char *data,
              size_t data_len, ssize_t *ret)
{
    ssize_t rc;
    ssize_t length;
    struct transportpacket *p = &session->packet;

    if(!p->olen) {
        *ret = 0;
        return LIBSSH2_ERROR_NONE;
    }

    /* send as much as possible of the existing packet */
    if((data != p->odata) || (data_len != p->olen)) {
        /* When we are about to complete the sending of a packet, it is vital
           that the caller doesn't try to send a new/different packet since
           we don't add this one up until the previous one has been sent. To
           make the caller really notice his/hers flaw, we return error for
           this case */
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Address is different, returning EAGAIN"));
        return LIBSSH2_ERROR_EAGAIN;
    }

    *ret = 1;                   /* set to make our parent return */

    /* number of bytes left to send */
    length = p->ototal_num - p->osent;

    rc = LIBSSH2_SEND(session, &p->outbuf[p->osent], length,
                      LIBSSH2_SOCKET_SEND_FLAGS(session));
    if(rc < 0)
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Error sending %ld bytes: %ld",
                       (long)length, (long)-rc));
    else {
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Sent %ld/%ld bytes at %p+%lu", (long)rc, (long)length,
                       (void *)p->outbuf, (unsigned long)p->osent));
        debugdump(session, "libssh2_transport_write send()",
                  &p->outbuf[p->osent], rc);
    }

    if(rc == length) {
        /* the remainder of the package was sent */
        p->ototal_num = 0;
        p->olen = 0;
        /* we leave *ret set so that the parent returns as we MUST return back
           a send success now, so that we don't risk sending EAGAIN later
           which then would confuse the parent function */
        return LIBSSH2_ERROR_NONE;

    }
    else if(rc < 0) {
        /* nothing was sent */
        if(rc != -EAGAIN)
            /* send failure! */
            return LIBSSH2_ERROR_SOCKET_SEND;

        session->socket_block_directions |= LIBSSH2_SESSION_BLOCK_OUTBOUND;
        return LIBSSH2_ERROR_EAGAIN;
    }

    p->osent += rc;         /* we sent away this much data */

    return rc < length ? LIBSSH2_ERROR_EAGAIN : LIBSSH2_ERROR_NONE;
}

/*
 * libssh2_transport_send
 *
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure.
 *
 * The data is provided as _two_ data areas that are combined by this
 * function.  The 'data' part is sent immediately before 'data2'. 'data2' may
 * be set to NULL to only use a single part.
 *
 * Returns LIBSSH2_ERROR_EAGAIN if it would block or if the whole packet was
 * not sent yet. If it does so, the caller should call this function again as
 * soon as it is likely that more data can be sent, and this function MUST
 * then be called with the same argument set (same data pointer and same
 * data_len) until ERROR_NONE or failure is returned.
 *
 * This function DOES NOT call _libssh2_error() on any errors.
 */
int _libssh2_transport_send(LIBSSH2_SESSION *session,
                            const unsigned char *data, size_t data_len,
                            const unsigned char *data2, size_t data2_len)
{
    int blocksize =
        (session->state & LIBSSH2_STATE_NEWKEYS) ?
        session->local.crypt->blocksize : 8;
    ssize_t padding_length;
    size_t packet_length;
    ssize_t total_length;
#ifdef LIBSSH2_RANDOM_PADDING
    int rand_max;
    int seed = data[0];         /* FIXME: make this random */
#endif
    struct transportpacket *p = &session->packet;
    int encrypted;
    int compressed;
    int etm;
    ssize_t ret;
    int rc;
    const unsigned char *orgdata = data;
    const LIBSSH2_MAC_METHOD *local_mac = NULL;
    unsigned int auth_len = 0;
    size_t orgdata_len = data_len;
    size_t crypt_offset, etm_crypt_offset;

    /*
     * If the last read operation was interrupted in the middle of a key
     * exchange, we must complete that key exchange before continuing to write
     * further data.
     *
     * See the similar block in _libssh2_transport_read for more details.
     */
    if(session->state & LIBSSH2_STATE_EXCHANGING_KEYS &&
        !(session->state & LIBSSH2_STATE_KEX_ACTIVE)) {
        /* Don't write any new packets if we're still in the middle of a key
         * exchange. */
        _libssh2_debug((session, LIBSSH2_TRACE_TRANS, "Redirecting into the"
                       " key re-exchange from _libssh2_transport_send"));
        rc = _libssh2_kex_exchange(session, 1, &session->startup_key_state);
        if(rc)
            return rc;
    }

    debugdump(session, "libssh2_transport_write plain", data, data_len);
    if(data2)
        debugdump(session, "libssh2_transport_write plain2", data2, data2_len);

    /* FIRST, check if we have a pending write to complete. send_existing
       only sanity-check data and data_len and not data2 and data2_len! */
    rc = send_existing(session, data, data_len, &ret);
    if(rc)
        return rc;

    session->socket_block_directions &= ~LIBSSH2_SESSION_BLOCK_OUTBOUND;

    if(ret)
        /* set by send_existing if data was sent */
        return rc;

    encrypted = (session->state & LIBSSH2_STATE_NEWKEYS) ? 1 : 0;

    if(encrypted && session->local.crypt &&
        CRYPT_FLAG_R(session, REQUIRES_FULL_PACKET)) {
        auth_len = session->local.crypt->auth_len;
    }
    else {
        local_mac = session->local.mac;
    }

    etm = encrypted && local_mac ? local_mac->etm : 0;

    compressed = session->local.comp &&
                 session->local.comp->compress &&
                 ((session->state & LIBSSH2_STATE_AUTHENTICATED) ||
                  session->local.comp->use_in_auth);

    if(encrypted && compressed && session->local.comp_abstract) {
        /* the idea here is that these function must fail if the output gets
           larger than what fits in the assigned buffer so thus they don't
           check the input size as we don't know how much it compresses */
        size_t dest_len = MAX_SSH_PACKET_LEN-5-256;
        size_t dest2_len = dest_len;

        /* compress directly to the target buffer */
        rc = session->local.comp->comp(session,
                                       &p->outbuf[5], &dest_len,
                                       data, data_len,
                                       &session->local.comp_abstract);
        if(rc)
            return rc;     /* compression failure */

        if(data2 && data2_len) {
            /* compress directly to the target buffer right after where the
               previous call put data */
            dest2_len -= dest_len;

            rc = session->local.comp->comp(session,
                                           &p->outbuf[5 + dest_len],
                                           &dest2_len,
                                           data2, data2_len,
                                           &session->local.comp_abstract);
        }
        else
            dest2_len = 0;
        if(rc)
            return rc;     /* compression failure */

        data_len = dest_len + dest2_len; /* use the combined length */
    }
    else {
        if((data_len + data2_len) >= (MAX_SSH_PACKET_LEN-0x100))
            /* too large packet, return error for this until we make this
               function split it up and send multiple SSH packets */
            return LIBSSH2_ERROR_INVAL;

        /* copy the payload data */
        memcpy(&p->outbuf[5], data, data_len);
        if(data2 && data2_len)
            memcpy(&p->outbuf[5 + data_len], data2, data2_len);
        data_len += data2_len; /* use the combined length */
    }


    /* RFC4253 says: Note that the length of the concatenation of
       'packet_length', 'padding_length', 'payload', and 'random padding'
       MUST be a multiple of the cipher block size or 8, whichever is
       larger. */

    /* Plain math: (4 + 1 + packet_length + padding_length) % blocksize == 0 */

    packet_length = data_len + 1 + 4;   /* 1 is for padding_length field
                                           4 for the packet_length field */
    /* subtract 4 bytes of the packet_length field when padding AES-GCM
       or with ETM */
    crypt_offset = (etm || auth_len ||
                    (encrypted && CRYPT_FLAG_R(session, PKTLEN_AAD)))
                   ? 4 : 0;
    etm_crypt_offset = etm ? 4 : 0;

    /* at this point we have it all except the padding */

    /* first figure out our minimum padding amount to make it an even
       block size */
    padding_length = blocksize - ((packet_length - crypt_offset) % blocksize);

    /* if the padding becomes too small we add another blocksize worth
       of it (taken from the original libssh2 where it didn't have any
       real explanation) */
    if(padding_length < 4) {
        padding_length += blocksize;
    }
#ifdef LIBSSH2_RANDOM_PADDING
    /* FIXME: we can add padding here, but that also makes the packets
       bigger etc */

    /* now we can add 'blocksize' to the padding_length N number of times
       (to "help thwart traffic analysis") but it must be less than 255 in
       total */
    rand_max = (255 - padding_length) / blocksize + 1;
    padding_length += blocksize * (seed % rand_max);
#endif

    packet_length += padding_length;

    /* append the MAC length to the total_length size */
    total_length =
        packet_length + (encrypted && local_mac ? local_mac->mac_len : 0);

    total_length += auth_len;

    /* store packet_length, which is the size of the whole packet except
       the MAC and the packet_length field itself */
    _libssh2_htonu32(p->outbuf, (uint32_t)(packet_length - 4));
    /* store padding_length */
    p->outbuf[4] = (unsigned char)padding_length;

    /* fill the padding area with random junk */
    if(_libssh2_random(p->outbuf + 5 + data_len, padding_length)) {
        return _libssh2_error(session, LIBSSH2_ERROR_RANDGEN,
                              "Unable to get random bytes for packet padding");
    }

    if(encrypted) {
        size_t i;

        /* Calculate MAC hash. Put the output at index packet_length,
           since that size includes the whole packet. The MAC is
           calculated on the entire unencrypted packet, including all
           fields except the MAC field itself. This is skipped in the
           INTEGRATED_MAC case, where the crypto algorithm also does its
           own hash. */
        if(!etm && local_mac && !CRYPT_FLAG_L(session, INTEGRATED_MAC)) {
            if(local_mac->hash(session, p->outbuf + packet_length,
                               session->local.seqno, p->outbuf,
                               packet_length, NULL, 0,
                               &session->local.mac_abstract))
                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,
                                      "Failed to calculate MAC");
        }

        if(CRYPT_FLAG_L(session, REQUIRES_FULL_PACKET)) {
            if(session->local.crypt->crypt(session,
                                           session->local.seqno,
                                           p->outbuf,
                                           packet_length,
                                           &session->local.crypt_abstract,
                                           0)) {
                return LIBSSH2_ERROR_ENCRYPT;
            }
        }
        else {
            /* Encrypt the whole packet data, one block size at a time.
             The MAC field is not encrypted unless INTEGRATED_MAC. */
            /* Some crypto back-ends could handle a single crypt() call for
             encryption, but (presumably) others cannot, so break it up
             into blocksize-sized chunks to satisfy them all. */
            for(i = etm_crypt_offset; i < packet_length;
                i += session->local.crypt->blocksize) {
                unsigned char *ptr = &p->outbuf[i];
                size_t bsize = LIBSSH2_MIN(session->local.crypt->blocksize,
                                           (int)(packet_length-i));
                /* The INTEGRATED_MAC case always has an extra call below, so
                 it will never be LAST_BLOCK up here. */
                int firstlast = i == 0 ? FIRST_BLOCK :
                (!CRYPT_FLAG_L(session, INTEGRATED_MAC)
                 && (i == packet_length - session->local.crypt->blocksize)
                 ? LAST_BLOCK : MIDDLE_BLOCK);
                /* In the AAD case, the last block would be only 4 bytes
                 because everything is offset by 4 since the initial
                 packet_length isn't encrypted. In this case, combine that last
                 short packet with the previous one since AES-GCM crypt()
                 assumes that the entire MAC is available in that packet so it
                 can set that to the authentication tag. */
                if(!CRYPT_FLAG_L(session, INTEGRATED_MAC))
                    if(i > packet_length - 2*bsize) {
                        /* increase the final block size */
                        bsize = packet_length - i;
                        /* advance the loop counter by the extra amount */
                        i += bsize - session->local.crypt->blocksize;
                    }
                _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                                "crypting bytes %lu-%lu", (unsigned long)i,
                                (unsigned long)(i + bsize - 1)));
                if(session->local.crypt->crypt(session, 0, ptr,
                                               bsize,
                                               &session->local.crypt_abstract,
                                               firstlast))
                    return LIBSSH2_ERROR_ENCRYPT;     /* encryption failure */
            }

            /* Call crypt one last time so it can be filled in with the MAC */
            if(CRYPT_FLAG_L(session, INTEGRATED_MAC)) {
                int authlen = local_mac->mac_len;
                assert((size_t)total_length <=
                       packet_length + session->local.crypt->blocksize);
                if(session->local.crypt->crypt(session,
                                               0,
                                               &p->outbuf[packet_length],
                                               authlen,
                                               &session->local.crypt_abstract,
                                               LAST_BLOCK))
                    return LIBSSH2_ERROR_ENCRYPT;     /* encryption failure */
            }
        }

        if(etm) {
            /* Calculate MAC hash. Put the output at index packet_length,
               since that size includes the whole packet. The MAC is
               calculated on the entire packet (length plain the rest
               encrypted), including all fields except the MAC field
               itself. */
            if(local_mac->hash(session, p->outbuf + packet_length,
                               session->local.seqno, p->outbuf,
                               packet_length, NULL, 0,
                               &session->local.mac_abstract))
                return _libssh2_error(session, LIBSSH2_ERROR_MAC_FAILURE,
                                      "Failed to calculate MAC");
        }
    }

    session->local.seqno++;

    if(session->kex_strict && data[0] == SSH_MSG_NEWKEYS) {
        session->local.seqno = 0;
    }

    ret = LIBSSH2_SEND(session, p->outbuf, total_length,
                       LIBSSH2_SOCKET_SEND_FLAGS(session));
    if(ret < 0)
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Error sending %ld bytes: %ld",
                       (long)total_length, (long)-ret));
    else {
        _libssh2_debug((session, LIBSSH2_TRACE_SOCKET,
                       "Sent %ld/%ld bytes at %p",
                       (long)ret, (long)total_length, (void *)p->outbuf));
        debugdump(session, "libssh2_transport_write send()", p->outbuf, ret);
    }

    if(ret != total_length) {
        if(ret >= 0 || ret == -EAGAIN) {
            /* the whole packet could not be sent, save the rest */
            session->socket_block_directions |= LIBSSH2_SESSION_BLOCK_OUTBOUND;
            p->odata = orgdata;
            p->olen = orgdata_len;
            p->osent = ret <= 0 ? 0 : ret;
            p->ototal_num = total_length;
            return LIBSSH2_ERROR_EAGAIN;
        }
        return LIBSSH2_ERROR_SOCKET_SEND;
    }

    /* the whole thing got sent away */
    p->odata = NULL;
    p->olen = 0;

    return LIBSSH2_ERROR_NONE;         /* all is good */
}
