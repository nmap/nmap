/* Copyright (C) 2007 The Written Word, Inc.
 * Copyright (C) 2008, Simon Josefsson
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
 */

#include "libssh2_priv.h"

static int
readline(char *line, int line_size, FILE * fp)
{
    size_t len;

    if (!line) {
        return -1;
    }
    if (!fgets(line, line_size, fp)) {
        return -1;
    }

    if (*line) {
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
    }

    if (*line) {
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
        }
    }

    return 0;
}

static int
readline_memory(char *line, size_t line_size,
                const char *filedata, size_t filedata_len,
                size_t *filedata_offset)
{
    size_t off, len;

    off = *filedata_offset;

    for (len = 0; off + len < filedata_len && len < line_size; len++) {
        if (filedata[off + len] == '\n' ||
            filedata[off + len] == '\r') {
                break;
        }
    }

    if (len) {
        memcpy(line, filedata + off, len);
        *filedata_offset += len;
    }

    line[len] = '\0';
    *filedata_offset += 1;

    return 0;
}

#define LINE_SIZE 128

int
_libssh2_pem_parse(LIBSSH2_SESSION * session,
                   const char *headerbegin,
                   const char *headerend,
                   FILE * fp, unsigned char **data, unsigned int *datalen)
{
    char line[LINE_SIZE];
    char *b64data = NULL;
    unsigned int b64datalen = 0;
    int ret;

    do {
        *line = '\0';

        if (readline(line, LINE_SIZE, fp)) {
            return -1;
        }
    }
    while (strcmp(line, headerbegin) != 0);

    *line = '\0';

    do {
        if (*line) {
            char *tmp;
            size_t linelen;

            linelen = strlen(line);
            tmp = LIBSSH2_REALLOC(session, b64data, b64datalen + linelen);
            if (!tmp) {
                ret = -1;
                goto out;
            }
            memcpy(tmp + b64datalen, line, linelen);
            b64data = tmp;
            b64datalen += linelen;
        }

        *line = '\0';

        if (readline(line, LINE_SIZE, fp)) {
            ret = -1;
            goto out;
        }
    } while (strcmp(line, headerend) != 0);

    if (!b64data) {
        return -1;
    }

    if (libssh2_base64_decode(session, (char**) data, datalen,
                              b64data, b64datalen)) {
        ret = -1;
        goto out;
    }

    ret = 0;
  out:
    if (b64data) {
        LIBSSH2_FREE(session, b64data);
    }
    return ret;
}

int
_libssh2_pem_parse_memory(LIBSSH2_SESSION * session,
                          const char *headerbegin,
                          const char *headerend,
                          const char *filedata, size_t filedata_len,
                          unsigned char **data, unsigned int *datalen)
{
    char line[LINE_SIZE];
    char *b64data = NULL;
    unsigned int b64datalen = 0;
    size_t off = 0;
    int ret;

    do {
        *line = '\0';

        if (readline_memory(line, LINE_SIZE, filedata, filedata_len, &off)) {
            return -1;
        }
    }
    while (strcmp(line, headerbegin) != 0);

    *line = '\0';

    do {
        if (*line) {
            char *tmp;
            size_t linelen;

            linelen = strlen(line);
            tmp = LIBSSH2_REALLOC(session, b64data, b64datalen + linelen);
            if (!tmp) {
                ret = -1;
                goto out;
            }
            memcpy(tmp + b64datalen, line, linelen);
            b64data = tmp;
            b64datalen += linelen;
        }

        *line = '\0';

        if (readline_memory(line, LINE_SIZE, filedata, filedata_len, &off)) {
            ret = -1;
            goto out;
        }
    } while (strcmp(line, headerend) != 0);

    if (!b64data) {
        return -1;
    }

    if (libssh2_base64_decode(session, (char**) data, datalen,
                              b64data, b64datalen)) {
        ret = -1;
        goto out;
    }

    ret = 0;
  out:
    if (b64data) {
        LIBSSH2_FREE(session, b64data);
    }
    return ret;
}

static int
read_asn1_length(const unsigned char *data,
                 unsigned int datalen, unsigned int *len)
{
    unsigned int lenlen;
    int nextpos;

    if (datalen < 1) {
        return -1;
    }
    *len = data[0];

    if (*len >= 0x80) {
        lenlen = *len & 0x7F;
        *len = data[1];
        if (1 + lenlen > datalen) {
            return -1;
        }
        if (lenlen > 1) {
            *len <<= 8;
            *len |= data[2];
        }
    } else {
        lenlen = 0;
    }

    nextpos = 1 + lenlen;
    if (lenlen > 2 || 1 + lenlen + *len > datalen) {
        return -1;
    }

    return nextpos;
}

int
_libssh2_pem_decode_sequence(unsigned char **data, unsigned int *datalen)
{
    unsigned int len;
    int lenlen;

    if (*datalen < 1) {
        return -1;
    }

    if ((*data)[0] != '\x30') {
        return -1;
    }

    (*data)++;
    (*datalen)--;

    lenlen = read_asn1_length(*data, *datalen, &len);
    if (lenlen < 0 || lenlen + len != *datalen) {
        return -1;
    }

    *data += lenlen;
    *datalen -= lenlen;

    return 0;
}

int
_libssh2_pem_decode_integer(unsigned char **data, unsigned int *datalen,
                            unsigned char **i, unsigned int *ilen)
{
    unsigned int len;
    int lenlen;

    if (*datalen < 1) {
        return -1;
    }

    if ((*data)[0] != '\x02') {
        return -1;
    }

    (*data)++;
    (*datalen)--;

    lenlen = read_asn1_length(*data, *datalen, &len);
    if (lenlen < 0 || lenlen + len > *datalen) {
        return -1;
    }

    *data += lenlen;
    *datalen -= lenlen;

    *i = *data;
    *ilen = len;

    *data += len;
    *datalen -= len;

    return 0;
}
