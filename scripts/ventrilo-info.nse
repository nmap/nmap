local bit = require "bit"
local stdnse = require "stdnse"
local math = require "math"
local nmap = require "nmap"
local strbuf = require "strbuf"
local string = require "string"
local table = require "table"
local shortport = require "shortport"

description = [[
Detects the Ventrilo voice communication server service versions 2.1.2
and above. Some of the older versions (pre 3.0.0) may not have the UDP
service this probe relies on enabled by default.

The Ventrilo server listens on a TCP (voice/control) and an UDP (ping/status)
port with the same port number (fixed to 3784 in the free version, otherwise
configurable). This script activates on both a TCP and UDP port version scan.
In both cases probe data is sent only to the UDP port because it allows for a
simple and informative status command as implemented by the
<code>ventrilo_status.exe</code> executable which has shipped alongside the Windows server
package since version 2.1.2 when the UDP status service was implemented.

When run as a version detection script (<code>-sV</code>), the script will report on the
server version, name, uptime, authentication scheme, and OS.  When run
explicitly (<code>--script ventrilo-info</code>), the script will additionally report on the
server name phonetic pronounciation string, the server comment, maximum number
of clients, voice codec, voice format, channel and client counts, and details
about channels and currently connected clients.

Original reversing of the protocol was done by Luigi Auriemma
(http://aluigi.altervista.org/papers.htm#ventrilo).
]]

-- @usage
-- nmap -sV <target>
-- @usage
-- nmap -Pn -sU -sV --script ventrilo-info -p <port> <target>
--
-- @output
-- PORT     STATE SERVICE  VERSION
-- 9408/tcp open  ventrilo Ventrilo 3.0.3.C (voice port; name: TypeFrag.com; uptime: 152h:56m; auth: pw)
-- | ventrilo-info:
-- | name: TypeFrag.com
-- | phonetic: Type Frag Dot Com
-- | comment: http://www.typefrag.com/
-- | auth: pw
-- | max. clients: 100
-- | voice codec: 3,Speex
-- | voice format: 32,32 KHz%2C 16 bit%2C 10 Qlty
-- | uptime: 152h:56m
-- | platform: WIN32
-- | version: 3.0.3.C
-- | channel count: 14
-- | channel fields: CID, PID, PROT, NAME, COMM
-- | client count: 6
-- | client fields: ADMIN, CID, PHAN, PING, SEC, NAME, COMM
-- | channels:
-- | <top level lobby> (CID: 0, PID: n/a, PROT: n/a, COMM: n/a): <empty>
-- | Group 1 (CID: 719, PID: 0, PROT: 0, COMM: ):
-- |   stabya (ADMIN: 0, PHAN: 0, PING: 47, SEC: 206304, COMM:
-- | Group 2 (CID: 720, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 3 (CID: 721, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 4 (CID: 722, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 5 (CID: 723, PID: 0, PROT: 0, COMM: ):
-- |   Sir Master Win (ADMIN: 0, PHAN: 0, PING: 32, SEC: 186890, COMM:
-- |   waterbukk (ADMIN: 0, PHAN: 0, PING: 31, SEC: 111387, COMM:
-- |   likez (ADMIN: 0, PHAN: 0, PING: 140, SEC: 22457, COMM:
-- |   Tweet (ADMIN: 0, PHAN: 0, PING: 140, SEC: 21009, COMM:
-- | Group 6 (CID: 724, PID: 0, PROT: 0, COMM: ): <empty>
-- | Raid (CID: 725, PID: 0, PROT: 0, COMM: ): <empty>
-- | Officers (CID: 726, PID: 0, PROT: 1, COMM: ): <empty>
-- | PG 13 (CID: 727, PID: 0, PROT: 0, COMM: ): <empty>
-- | Rated R (CID: 728, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 7 (CID: 729, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 8 (CID: 730, PID: 0, PROT: 0, COMM: ): <empty>
-- | Group 9 (CID: 731, PID: 0, PROT: 0, COMM: ): <empty>
-- | AFK - switch to this when AFK (CID: 732, PID: 0, PROT: 0, COMM: ):
-- |_  Eisennacher (ADMIN: 0, PHAN: 0, PING: 79, SEC: 181948, COMM:
-- Service Info: OS: WIN32
--
-- @xmloutput
-- <elem key="phonetic">Type Frag Dot Com</elem>
-- <elem key="comment">http://www.typefrag.com/</elem>
-- <elem key="auth">1</elem>
-- <elem key="maxclients">100</elem>
-- <elem key="voicecodec">3,Speex</elem>
-- <elem key="voiceformat">32,32 KHz%2C 16 bit%2C 10 Qlty</elem>
-- <elem key="uptime">551533</elem>
-- <elem key="platform">WIN32</elem>
-- <elem key="version">3.0.3.C</elem>
-- <elem key="channelcount">14</elem>
-- <table key="channelfields">
--   <elem>CID</elem>
--   <elem>PID</elem>
--   <elem>PROT</elem>
--   <elem>NAME</elem>
--   <elem>COMM</elem>
-- </table>
-- <table key="channels">
--   <table key="0">
--     <elem key="NAME">&lt;top level lobby&gt;</elem>
--     <elem key="CID">0</elem>
--   </table>
--   <table key="363">
--     <elem key="CID">363</elem>
--     <elem key="PID">0</elem>
--     <elem key="PROT">0</elem>
--     <elem key="NAME">Group 1</elem>
--     <elem key="COMM"></elem>
--     <table key="clients">
--       <table>
--         <elem key="ADMIN">0</elem>
--         <elem key="CID">363</elem>
--         <elem key="PHAN">0</elem>
--         <elem key="PING">47</elem>
--         <elem key="SEC">207276</elem>
--         <elem key="NAME">stabya</elem>
--         <elem key="COMM"></elem>
--       </table>
--     </table>
--   </table>
--   <!-- Channels other than the first and last cut for brevity -->
--   <table key="376">
--     <elem key="CID">376</elem>
--     <elem key="PID">0</elem>
--     <elem key="PROT">0</elem>
--     <elem key="NAME">AFK - switch to this when AFK</elem>
--     <elem key="COMM"></elem>
--     <table key="clients">
--       <table>
--         <elem key="ADMIN">0</elem>
--         <elem key="CID">376</elem>
--         <elem key="PHAN">0</elem>
--         <elem key="PING">78</elem>
--         <elem key="SEC">182920</elem>
--         <elem key="NAME">Eisennacher</elem>
--         <elem key="COMM"></elem>
--       </table>
--     </table>
--   </table>
-- </table>
-- <elem key="clientcount">6</elem>
-- <table key="clientfields">
--   <elem>ADMIN</elem>
--   <elem>CID</elem>
--   <elem>PHAN</elem>
--   <elem>PING</elem>
--   <elem>SEC</elem>
--   <elem>NAME</elem>
--   <elem>COMM</elem>
-- </table>

author = "Marin Maržić"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "default", "discovery", "safe", "version" }

local crypt_head = {
    0x80,0xe5,0x0e,0x38,0xba,0x63,0x4c,0x99,0x88,0x63,0x4c,0xd6,0x54,0xb8,0x65,0x7e,
    0xbf,0x8a,0xf0,0x17,0x8a,0xaa,0x4d,0x0f,0xb7,0x23,0x27,0xf6,0xeb,0x12,0xf8,0xea,
    0x17,0xb7,0xcf,0x52,0x57,0xcb,0x51,0xcf,0x1b,0x14,0xfd,0x6f,0x84,0x38,0xb5,0x24,
    0x11,0xcf,0x7a,0x75,0x7a,0xbb,0x78,0x74,0xdc,0xbc,0x42,0xf0,0x17,0x3f,0x5e,0xeb,
    0x74,0x77,0x04,0x4e,0x8c,0xaf,0x23,0xdc,0x65,0xdf,0xa5,0x65,0xdd,0x7d,0xf4,0x3c,
    0x4c,0x95,0xbd,0xeb,0x65,0x1c,0xf4,0x24,0x5d,0x82,0x18,0xfb,0x50,0x86,0xb8,0x53,
    0xe0,0x4e,0x36,0x96,0x1f,0xb7,0xcb,0xaa,0xaf,0xea,0xcb,0x20,0x27,0x30,0x2a,0xae,
    0xb9,0x07,0x40,0xdf,0x12,0x75,0xc9,0x09,0x82,0x9c,0x30,0x80,0x5d,0x8f,0x0d,0x09,
    0xa1,0x64,0xec,0x91,0xd8,0x8a,0x50,0x1f,0x40,0x5d,0xf7,0x08,0x2a,0xf8,0x60,0x62,
    0xa0,0x4a,0x8b,0xba,0x4a,0x6d,0x00,0x0a,0x93,0x32,0x12,0xe5,0x07,0x01,0x65,0xf5,
    0xff,0xe0,0xae,0xa7,0x81,0xd1,0xba,0x25,0x62,0x61,0xb2,0x85,0xad,0x7e,0x9d,0x3f,
    0x49,0x89,0x26,0xe5,0xd5,0xac,0x9f,0x0e,0xd7,0x6e,0x47,0x94,0x16,0x84,0xc8,0xff,
    0x44,0xea,0x04,0x40,0xe0,0x33,0x11,0xa3,0x5b,0x1e,0x82,0xff,0x7a,0x69,0xe9,0x2f,
    0xfb,0xea,0x9a,0xc6,0x7b,0xdb,0xb1,0xff,0x97,0x76,0x56,0xf3,0x52,0xc2,0x3f,0x0f,
    0xb6,0xac,0x77,0xc4,0xbf,0x59,0x5e,0x80,0x74,0xbb,0xf2,0xde,0x57,0x62,0x4c,0x1a,
    0xff,0x95,0x6d,0xc7,0x04,0xa2,0x3b,0xc4,0x1b,0x72,0xc7,0x6c,0x82,0x60,0xd1,0x0d
}

local crypt_data = {
    0x82,0x8b,0x7f,0x68,0x90,0xe0,0x44,0x09,0x19,0x3b,0x8e,0x5f,0xc2,0x82,0x38,0x23,
    0x6d,0xdb,0x62,0x49,0x52,0x6e,0x21,0xdf,0x51,0x6c,0x76,0x37,0x86,0x50,0x7d,0x48,
    0x1f,0x65,0xe7,0x52,0x6a,0x88,0xaa,0xc1,0x32,0x2f,0xf7,0x54,0x4c,0xaa,0x6d,0x7e,
    0x6d,0xa9,0x8c,0x0d,0x3f,0xff,0x6c,0x09,0xb3,0xa5,0xaf,0xdf,0x98,0x02,0xb4,0xbe,
    0x6d,0x69,0x0d,0x42,0x73,0xe4,0x34,0x50,0x07,0x30,0x79,0x41,0x2f,0x08,0x3f,0x42,
    0x73,0xa7,0x68,0xfa,0xee,0x88,0x0e,0x6e,0xa4,0x70,0x74,0x22,0x16,0xae,0x3c,0x81,
    0x14,0xa1,0xda,0x7f,0xd3,0x7c,0x48,0x7d,0x3f,0x46,0xfb,0x6d,0x92,0x25,0x17,0x36,
    0x26,0xdb,0xdf,0x5a,0x87,0x91,0x6f,0xd6,0xcd,0xd4,0xad,0x4a,0x29,0xdd,0x7d,0x59,
    0xbd,0x15,0x34,0x53,0xb1,0xd8,0x50,0x11,0x83,0x79,0x66,0x21,0x9e,0x87,0x5b,0x24,
    0x2f,0x4f,0xd7,0x73,0x34,0xa2,0xf7,0x09,0xd5,0xd9,0x42,0x9d,0xf8,0x15,0xdf,0x0e,
    0x10,0xcc,0x05,0x04,0x35,0x81,0xb2,0xd5,0x7a,0xd2,0xa0,0xa5,0x7b,0xb8,0x75,0xd2,
    0x35,0x0b,0x39,0x8f,0x1b,0x44,0x0e,0xce,0x66,0x87,0x1b,0x64,0xac,0xe1,0xca,0x67,
    0xb4,0xce,0x33,0xdb,0x89,0xfe,0xd8,0x8e,0xcd,0x58,0x92,0x41,0x50,0x40,0xcb,0x08,
    0xe1,0x15,0xee,0xf4,0x64,0xfe,0x1c,0xee,0x25,0xe7,0x21,0xe6,0x6c,0xc6,0xa6,0x2e,
    0x52,0x23,0xa7,0x20,0xd2,0xd7,0x28,0x07,0x23,0x14,0x24,0x3d,0x45,0xa5,0xc7,0x90,
    0xdb,0x77,0xdd,0xea,0x38,0x59,0x89,0x32,0xbc,0x00,0x3a,0x6d,0x61,0x4e,0xdb,0x29
}

local crypt_crc = {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
}

-- The probe payload is static as it has proven to be unecessary to forge a new
-- one every time. The data used includes the following parameters:
-- cmd = 2, password = 0, header len = 20, data len = 16, totlen = 36
-- static 2 byte status request id (time(NULL) in the original protocol)
local static_probe_id = 0x33CF
local static_probe_payload = "\x49\xde\xdf\xd0\x65\xc9\x21\xc4\x90\x0d\xbf\x23\xa2\xc8\x8b\x65\x7d\x43\x15\x9b\x30\xc2\xe2\x23\xd2\x13\xe3\x29\xad\xe8\x63\xff\x17\x31\x33\x50"

-- Returns a string interpretation of the server authentication scheme.
-- @param auth the server authentication scheme code
-- @return string string interpretation of the server authentication scheme
local auth_str = function(auth)
    if auth == "0" then
        return "none"
    elseif auth == "1" then
        return "pw"
    elseif auth == "2" then
        return "user/pw"
    else
        return auth
    end
end

-- Formats an uptime string containing a number of seconds.
-- E.g. "3670" -> "1h:1m"
-- @param uptime number of seconds of uptime
-- @return uptime_formatted formatted uptime string (hours and minutes)
local uptime_str = function(uptime)
    local uptime_num = tonumber(uptime)
    if not uptime_num then
        return uptime
    end

    local h = math.floor(uptime_num/3600)
    local m = math.floor((uptime_num - h*3600)/60)

    return h .. "h:" .. m .. "m"
end

-- Decrypts the Ventrilo UDP status response header segment.
-- @param str the Ventrilo UDP status response
-- @return id status request id as sent by us
-- @return len length of the data segment of the response
-- @return totlen total length of data segments of all response packets
-- @return pck response packet number (starts with 0)
-- @return totpck total number of response packets to expect
-- @return key key for decrypting the data segment of this response packet
-- @return crc_sum the crc checksum of the full response data segment
local dec_head = function(str)
    local head = { string.byte(str, 1, 20) }

    head[1], head[2] = head[2], head[1]
    local a1 = head[1]
    if a1 == 0 then
        return table.concat(head)
    end
    local a2 = head[2]

    for i = 3,20 do
        head[i] = bit.band(head[i] - (crypt_head[a2 + 1] + ((i - 3) % 5)), 0xFF)
        a2 = bit.band(a2 + a1, 0xFF)
    end

    for i = 3,19,2 do
        head[i], head[i + 1] = head[i + 1], head[i]
    end

    local id = head[7] + bit.lshift(head[8], 8)
    local totlen = head[9] + bit.lshift(head[10], 8)
    local len = head[11] + bit.lshift(head[12], 8)
    local totpck = head[13] + bit.lshift(head[14], 8)
    local pck = head[15] + bit.lshift(head[16], 8)
    local key = head[17] + bit.lshift(head[18], 8)
    local crc_sum = head[19] + bit.lshift(head[20], 8)

    return id, len, totlen, pck, totpck, key, crc_sum
end

-- Decrypts the Ventrilo UDP status response data segment.
-- @param str the Ventrilo UDP status response
-- @param len length of the data segment of this response packet
-- @param key key for decrypting the data segment
local dec_data = function(str, len, key)
    -- skip the header (first 20 bytes)
    local data = { string.byte(str, 21, 20 + len) }

    a1 = bit.band(key, 0xFF)
    if a1 == 0 then
        return table.concat(data)
    end
    a2 = bit.rshift(key, 8)

    for i = 1,len do
        data[i] = bit.band(data[i] - (crypt_data[a2 + 1] + ((i - 1) % 72)), 0xFF)
        a2 = bit.band(a2 + a1, 0xFF)
    end

    return string.char(table.unpack(data))
end

-- Convenient wrapper for string.find(...). Returns the position of the end of
-- the match, or the previous starting position if no match was found. Also
-- returns the first capture, or "n/a" if one was not found.
-- @param str the string to search
-- @param pattern the pattern to apply for the search
-- @param pos the starting position of the search
-- @return newpos position of the end of the match, or pos if no match found
-- @return cap the first capture, or "n/a" if one was not found
local str_find = function(str, pattern, pos)
    local _, newpos, cap = string.find(str, pattern, pos)
    return newpos or pos, cap or "n/a"
end

-- Calculates the CRC checksum used for checking the integrity of the received
-- status response data segment.
-- @param data data to calculate the checksum of
-- @return 2 byte CRC checksum as seen in Ventrilo UDP status headers
local crc = function(data)
    local sum = 0
    for i = 1,#data do
        sum = bit.band(bit.bxor(crypt_crc[bit.rshift(sum, 8) + 1],
            data:byte(i), bit.lshift(sum, 8)), 0xFFFF)
    end
    return sum
end

-- Parses the status response data segment and constructs an output table.
-- @param Ventrilo UDP status response data segment
-- @return info output table representing Ventrilo UDP status response info
local o_table = function(data)
    local info = stdnse.output_table()
    local pos

    pos, info.name = str_find(data, "NAME: ([^\n]*)", 0)
    pos, info.phonetic = str_find(data, "PHONETIC: ([^\n]*)", pos)
    pos, info.comment = str_find(data, "COMMENT: ([^\n]*)", pos)
    pos, info.auth = str_find(data, "AUTH: ([^\n]*)", pos)
    pos, info.maxclients = str_find(data, "MAXCLIENTS: ([^\n]*)", pos)
    pos, info.voicecodec = str_find(data, "VOICECODEC: ([^\n]*)", pos)
    pos, info.voiceformat = str_find(data, "VOICEFORMAT: ([^\n]*)", pos)
    pos, info.uptime = str_find(data, "UPTIME: ([^\n]*)", pos)
    pos, info.platform = str_find(data, "PLATFORM: ([^\n]*)", pos)
    pos, info.version = str_find(data, "VERSION: ([^\n]*)", pos)

    -- channels
    pos, info.channelcount = str_find(data, "CHANNELCOUNT: ([^\n]*)", pos)
    pos, info.channelfields = str_find(data, "CHANNELFIELDS: ([^\n]*)", pos)

    -- construct channel fields as a nice list instead of the raw data
    local channelfields = {}
    for channelfield in string.gmatch(info.channelfields, "[^,\n]+") do
        channelfields[#channelfields + 1] = channelfield
    end
    info.channelfields = channelfields

    -- parse and add channels
    info.channels = stdnse.output_table()
    -- add top level lobby channel (CID = 0)
    info.channels["0"] = stdnse.output_table()
    info.channels["0"].NAME = "<top level lobby>"
    info.channels["0"].CID = "0"
    while string.sub(data, pos + 2, pos + 10) == "CHANNEL: " do
        local channel = stdnse.output_table()
        for _, channelfield in ipairs(info.channelfields) do
            pos, channel[channelfield] = str_find(data, channelfield .. "=([^,\n]*)", pos)
        end
        if channel.CID then
            info.channels[channel.CID] = channel
        end
    end

    -- clients
    pos, info.clientcount = str_find(data, "CLIENTCOUNT: ([^\n]*)", pos)
    pos, info.clientfields = str_find(data, "CLIENTFIELDS: ([^\n]*)", pos)

    -- construct client fields as a nice list instead of the raw data
    local clientfields = {}
    for clientfield in string.gmatch(info.clientfields, "[^,\n]+") do
        clientfields[#clientfields + 1] = clientfield
    end
    info.clientfields = clientfields

    -- parse and add clients
    while string.sub(data, pos + 2, pos + 9) == "CLIENT: " do
        local client = stdnse.output_table()
        for _, clientfield in ipairs(info.clientfields) do
            pos, client[clientfield] = str_find(data, clientfield .. "=([^,\n]*)", pos)
        end
        if client.CID then
            if not info.channels[client.CID] then
                -- weird clients with unrecognized CID are put in the -1 channel
                if not info.channels["-1"] then
                    -- add channel for weird clients with unrecognized CIDs
                    info.channels["-1"] = stdnse.output_table()
                    info.channels["-1"].NAME = "<clients with unrecognized CIDs>"
                    info.channels["-1"].CID = "-1"
                    info.channels["-1"].clients = {}
                end
                table.insert(info.channels["-1"].clients, client)
            elseif not info.channels[client.CID].clients then
                -- channel had no clients, create table for the 1st client
                info.channels[client.CID].clients = {}
                table.insert(info.channels[client.CID].clients, client)
            else
                table.insert(info.channels[client.CID].clients, client)
            end
        end
    end

    return info
end

-- Constructs an output string from an output table for use in normal output.
-- @param info output table
-- @return output_string output string
local o_str = function(info)
    local buf = strbuf.new()
    buf = buf .. "\nname: "
    buf = buf .. info.name
    buf = buf .. "\nphonetic: "
    buf = buf .. info.phonetic
    buf = buf .. "\ncomment: "
    buf = buf .. info.comment
    buf = buf .. "\nauth: "
    buf = buf .. auth_str(info.auth)
    buf = buf .. "\nmax. clients: "
    buf = buf .. info.maxclients
    buf = buf .. "\nvoice codec: "
    buf = buf .. info.voicecodec
    buf = buf .. "\nvoice format: "
    buf = buf .. info.voiceformat
    buf = buf .. "\nuptime: "
    buf = buf .. uptime_str(info.uptime)
    buf = buf .. "\nplatform: "
    buf = buf .. info.platform
    buf = buf .. "\nversion: "
    buf = buf .. info.version
    buf = buf .. "\nchannel count: "
    buf = buf .. info.channelcount
    buf = buf .. "\nchannel fields: "
    for i, channelfield in ipairs(info.channelfields) do
        buf = buf .. channelfield
        if i ~= #info.channelfields then
            buf = buf .. ", "
        end
    end
    buf = buf .. "\nclient count: "
    buf = buf .. info.clientcount
    buf = buf .. "\nclient fields: "
    for i, clientfield in ipairs(info.clientfields) do
        buf = buf .. clientfield
        if i ~= #info.clientfields then
            buf = buf .. ", "
        end
    end
    buf = buf .. "\nchannels:"
    for i, channel in pairs(info.channels) do
        buf = buf .. "\n"
        buf = buf .. channel.NAME
        buf = buf .. " ("
        for j, channelfield in ipairs(info.channelfields) do
            if channelfield ~= "NAME" and channelfield ~= "n/a" then
                buf = buf .. channelfield
                buf = buf .. ": "
                buf = buf .. (channel[channelfield] or "n/a")
                if j ~= #info.channelfields then
                    buf = buf .. ", "
                end
            end
        end
        buf = buf .. "): "
        if not channel.clients then
            buf = buf .. "<empty>"
        else
            for j, client in ipairs(channel.clients) do
                buf = buf .. "\n  "
                buf = buf .. client.NAME
                buf = buf .. " ("
                for k, clientfield in ipairs(info.clientfields) do
                    if clientfield ~= "NAME" and clientfield ~= "CID" then
                        buf = buf .. clientfield
                        buf = buf .. ": "
                        buf = buf .. client[clientfield]
                        if k ~= #info.clientfields then
                            buf = buf .. ", "
                        end
                    end
                end
            end
        end
    end

    return strbuf.dump(buf, "")
end

portrule = shortport.version_port_or_service({3784}, "ventrilo", {"tcp", "udp"})

action = function(host, port)
    local mutex = nmap.mutex("ventrilo-info:" .. host.ip .. ":" .. port.number)
    mutex("lock")

    if host.registry["ventrilo-info"] == nil then
        host.registry["ventrilo-info"] = {}
    end
    -- Maybe the script already ran for this port number on another protocol
    local r = host.registry["ventrilo-info"][port.number]
    if r == nil then
        r = {}
        host.registry["ventrilo-info"][port.number] = r

        local socket = nmap.new_socket()
        socket:set_timeout(2000)

        local cleanup = function()
            socket:close()
            mutex("done")
        end
        local try = nmap.new_try(cleanup)

        local udpport = { number = port.number, protocol = "udp" }
        try(socket:connect(host.ip, udpport))

        local status, response
        -- try a couple of times on timeout, the service seems to not
        -- respond if multiple requests come within a short timeframe
        for _ = 1,3 do
            try(socket:send(static_probe_payload))
            status, response = socket:receive()
            if status then
                nmap.set_port_state(host, udpport, "open")
                break
            end
        end
        if not status then
            -- 3 timeouts, no response
            cleanup()
            return
        end

        -- received the first packet, process it and others if they come
        local fulldata = {}
        local fulldatalen = 0
        local curlen = 0
        local head_crc_sum
        while true do
            -- decrypt received header and extract relevant information
            local id, len, totlen, pck, totpck, key, crc_sum = dec_head(response)

            if id == static_probe_id then
                curlen = curlen + len
                head_crc_sum = crc_sum

                -- check for an invalid response
                if #response < 20 or pck >= totpck or
                    len > 492 or curlen > totlen then
                    stdnse.print_debug("Invalid response. Aborting script.")
                    cleanup()
                    return
                end

                -- keep track of the length of fulldata (# isn't applicable)
                if fulldata[pck + 1] == nil then
                    fulldatalen = fulldatalen + 1
                end
                -- accumulate UDP packets that may not necessarily come in proper
                -- order; arrange them by packet id
                fulldata[pck + 1] = dec_data(response, len, key)
            end

            -- check for invalid states in communication
            if (fulldatalen > totpck) or (curlen > totlen)
                or (fulldatalen == totpck and curlen ~= totlen)
                or (curlen == totlen and fulldatalen ~= totpck) then
                stdnse.print_debug("Invalid state (fulldatalen = " .. fulldatalen ..
                    "; totpck = " .. totpck .. "; curlen = " .. curlen ..
                    "; totlen = " .. totlen .. "). Aborting script.")
                cleanup()
                return
            end

            -- check for valid end of communication
            if fulldatalen == totpck and curlen == totlen then
                break
            end

            -- receive another packet
            status, response = socket:receive()
            if not status then
                stdnse.print_debug("Response packets stopped coming midway. Aborting script.")
                cleanup()
                return
            end
        end

        socket:close()

        -- concatenate received data into a single string for further use
        local fulldata_str = table.concat(fulldata)

        -- check for an invalid checksum on the response data sections (no headers)
        local fulldata_crc_sum = crc(fulldata_str)
        if fulldata_crc_sum ~= head_crc_sum then
            stdnse.print_debug("Invalid CRC sum, received = %04X, calculated = %04X", head_crc_sum, fulldata_crc_sum)
            cleanup()
            return
        end

        -- parse the received data string into an output table
        r.info = o_table(fulldata_str)
    end

    mutex("done")

    -- If the registry is empty the port was probed but Ventrilo wasn't detected
    if next(r) == nil then
        return
    end

    port.version.name = "ventrilo"
    port.version.name_confidence = 10
    port.version.product = "Ventrilo"
    port.version.version = r.info.version
    port.version.ostype = r.info.platform
    port.version.extrainfo = "; name: ".. r.info.name
    if port.protocol == "tcp" then
        port.version.extrainfo = "voice port" .. port.version.extrainfo
    else
        port.version.extrainfo = "status port" .. port.version.extrainfo
    end
    port.version.extrainfo = port.version.extrainfo .. "; uptime: " .. uptime_str(r.info.uptime)
    port.version.extrainfo = port.version.extrainfo .. "; auth: " .. auth_str(r.info.auth)

    nmap.set_port_version(host, port, "hardmatched")

    -- an output table for XML output and a custom string for normal output
    return r.info, o_str(r.info)
end
