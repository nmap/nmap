---
-- A library providing functions for doing SSLv2 communications
--
--
-- @author Bertrand Bonnefoy-Claudet
-- @author Daniel Miller

local stdnse = require "stdnse"
local bin = require "bin"
local bit = require "bit"
local table = require "table"
local nmap = require "nmap"
local sslcert = require "sslcert"
_ENV = stdnse.module("sslv2", stdnse.seeall)

SSL_MESSAGE_TYPES = {
  ERROR = 0,
  CLIENT_HELLO = 1,
  CLIENT_MASTER_KEY = 2,
  CLIENT_FINISHED = 3,
  SERVER_HELLO = 4,
  SERVER_VERIFY = 5,
  SERVER_FINISHED = 6,
  REQUEST_CERTIFICATE = 7,
  CLIENT_CERTIFICATE = 8,
}

SSL_ERRORS = {
  [1] = "SSL_PE_NO_CIPHER",
  [2] = "SSL_PE_NO_CERTIFICATE",
  [3] = "SSL_PE_BAD_CERTIFICATE",
  [4] = "SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE",
}

SSL_CERT_TYPES = {
  X509_CERTIFICATE = 1,
}

-- (cut down) table of codes with their corresponding ciphers.
-- inspired by Wireshark's 'epan/dissectors/packet-ssl-utils.h'

--- SSLv2 ciphers, keyed by cipher code as a string of 3 bytes.
--
-- @class table
-- @name SSL_CIPHERS
-- @field str The cipher name as a string
-- @field key_length The length of the cipher's key
-- @field encrypted_key_length How much of the key is encrypted in the handshake (effective key strength)
SSL_CIPHERS = {
  ["\x01\x00\x80"] = {
    str = "SSL2_RC4_128_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 16,
  },
  ["\x02\x00\x80"] = {
    str = "SSL2_RC4_128_EXPORT40_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 5,
  },
  ["\x03\x00\x80"] = {
    str = "SSL2_RC2_128_CBC_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 16,
  },
  ["\x04\x00\x80"] = {
    str = "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 5,
  },
  ["\x05\x00\x80"] = {
    str = "SSL2_IDEA_128_CBC_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 16,
  },
  ["\x06\x00\x40"] = {
    str = "SSL2_DES_64_CBC_WITH_MD5",
    key_length = 8,
    encrypted_key_length = 8,
  },
  ["\x07\x00\xc0"] = {
    str = "SSL2_DES_192_EDE3_CBC_WITH_MD5",
    key_length = 24,
    encrypted_key_length = 24,
  },
  ["\x00\x00\x00"] = {
    str = "SSL2_NULL_WITH_MD5",
    key_length = 0,
    encrypted_key_length = 0,
  },
  ["\x08\x00\x80"] = {
    str = "SSL2_RC4_64_WITH_MD5",
    key_length = 16,
    encrypted_key_length = 8,
  },
}

--- Another table of ciphers
--
-- Unlike SSL_CIPHERS, this one is keyed by cipher name and the values are the
-- cipher code as a 3-byte string.
-- @class table
-- @name SSL_CIPHER_CODES
SSL_CIPHER_CODES = {}
for k, v in pairs(SSL_CIPHERS) do
  SSL_CIPHER_CODES[v.str] = k
end

local SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER = 32767
local SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER = 16383

local function parse_record_header_1_2(header_1_2)
  local _, b0, b1 = bin.unpack(">CC", header_1_2)
  local msb = bit.band(b0, 0x80) == 0x80
  local header_length
  local record_length
  if msb then
    header_length = 2
    record_length = bit.bor(bit.lshift(bit.band(b0, 0x7f), 8), b1)
  else
    header_length = 3
    record_length = bit.bor(bit.lshift(bit.band(b0, 0x3f), 8), b1)
  end
  return header_length, record_length
end

-- 2 bytes of length minimum
local SSL_MIN_HEADER = 2

local function read_header(buffer, i)
  i = i or 1
  -- Ensure we have enough data for the header.
  if #buffer - i + 1 < SSL_MIN_HEADER then
    return i, nil
  end

  local len
  i, len = bin.unpack(">S", buffer, i)
  local msb = bit.band(len, 0x8000) == 0x8000
  local header_length, record_length, padding_length, is_escape
  if msb then
    header_length = 2
    record_length = bit.band(len, 0x7fff)
    padding_length = 0
  else
    header_length = 3
    if #buffer - i + 1 < 1 then
      -- don't have enough for the message_type. Back up.
      return i - SSL_MIN_HEADER, nil
    end
    record_length = bit.band(len, 0x3fff)
    is_escape = not not bit.band(len, 0x4000)
    i, padding_length = bin.unpack("C", buffer, i)
  end

  return i, {
    record_length = record_length,
    is_escape = is_escape,
    padding_length = padding_length,
  }
end

---
-- Read a SSLv2 record
-- @param buffer   The read buffer
-- @param i        The position in the buffer to start reading
-- @return The current position in the buffer
-- @return The record that was read, as a table
function record_read(buffer, i)
  local i, h = read_header(buffer, i)

  if #buffer - i + 1 < h.record_length or not h then
    return i, nil
  end

  i, h.message_type = bin.unpack("C", buffer, i)

  if h.message_type == SSL_MESSAGE_TYPES.SERVER_HELLO then
    local j, SID_hit, certificate_type, ssl_version, certificate_len, ciphers_len, connection_id_len = bin.unpack(">CCSSSS", buffer, i)
    local j, certificate = bin.unpack("A" .. certificate_len, buffer, j)
    local ciphers_end = j + ciphers_len
    local ciphers = {}
    while j < ciphers_end do
      local cipher
      j, cipher = bin.unpack("A3", buffer, j)
      local cipher_name = SSL_CIPHERS[cipher] and SSL_CIPHERS[cipher].str or ("0x" .. stdnse.tohex(cipher))
      ciphers[#ciphers+1] = cipher_name
    end
    local j, connection_id = bin.unpack("A" .. connection_id_len, buffer, j)

    h.body = {
      cert_type = certificate_type,
      cert = certificate,
      ciphers = ciphers,
      connection_id = connection_id,
    }
    i = j
  elseif h.message_type == SSL_MESSAGE_TYPES.ERROR and h.record_length == 3 then
    local j, err = bin.unpack(">S", buffer, i)
    h.body = {
      error = SSL_ERRORS[err] or err
    }
    i = j
  else
    -- TODO: Other message types?
    h.message_type = "encrypted"
    local j, data = bin.unpack("A"..h.record_length, buffer, i)
    h.body = {
      data = data
    }
    i = j
  end
  return i, h
end

--- Wrap a payload in an SSLv2 record header
--
--@param payload The padded payload to send
--@param pad_length The length of the padding. If the payload is not padded, set to 0
--@return An SSLv2 record containing the payload
function ssl_record (payload, pad_length)
  local length = #payload
  assert(
    length < (pad_length == 0 and SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER or SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER),
    "SSL record too long")
  assert(pad_length < 256, "SSL record padding too long")
  if pad_length > 0 then
    return bin.pack(">SCA", length, pad_length, payload)
  else
    return bin.pack(">SA", bit.bor(length, 0x8000), payload)
  end
end

---
-- Build a client_hello message
--
-- The <code>ciphers</code> parameter can contain cipher names or raw 3-byte
-- cipher codes.
-- @param ciphers Table of cipher names
-- @return The client_hello record as a string
function client_hello (ciphers)
  local cipher_codes = {}

  for _, c in ipairs(ciphers) do
    local ck = SSL_CIPHER_CODES[c] or c
    assert(#ck == 3, "Unknown cipher")
    cipher_codes[#cipher_codes+1] = ck
  end

  local challenge = stdnse.generate_random_string(16)

  local ssl_v2_hello = bin.pack(">CSSSSAA",
    1, -- MSG-CLIENT-HELLO
    2, -- version: SSL 2.0
    #cipher_codes * 3, -- cipher spec length
    0, -- session ID length
    #challenge, -- challenge length
    table.concat(cipher_codes),
    challenge
    )

  return ssl_record(ssl_v2_hello, 0)
end

function client_master_secret(cipher_name, clear_key, encrypted_key, key_arg)
  local key_arg = key_arg or ""
  local ck = SSL_CIPHER_CODES[cipher_name] or cipher_name
  assert(#ck == 3, "Unknown cipher in client_master_secret")
  return ssl_record( bin.pack(">CASSSAAA",
    SSL_MESSAGE_TYPES.CLIENT_MASTER_KEY,
    ck,
    #clear_key,
    #encrypted_key,
    #key_arg,
    clear_key,
    encrypted_key,
    key_arg
    ), 0)
end

local function read_atleast(s, n)
  local buf = {}
  local count = 0
  while count < n do
    local status, data = s:receive_bytes(n - count)
    if not status then
      return status, data, table.concat(buf)
    end
    buf[#buf+1] = data
    count = count + #data
  end
  return true, table.concat(buf)
end

--- Get an entire record into a buffer
--
--  Caller is responsible for closing the socket if necessary.
-- @param sock The socket to read additional data from
-- @param buffer The string buffer holding any previously-read data
--               (default: "")
-- @param i The position in the buffer where the record should start
--          (default: 1)
-- @return status Socket status
-- @return Buffer containing at least 1 record if status is true
-- @return Error text if there was an error
function record_buffer(sock, buffer, i)
  buffer = buffer or ""
  i = i or 1
  if #buffer - i + 1 < SSL_MIN_HEADER then
    local status, resp, rem = read_atleast(sock, SSL_MIN_HEADER - (#buffer - i + 1))
    if not status then
      return false, buffer .. rem, resp
    end
    buffer = buffer .. resp
  end
  local i, h = read_header(buffer, i)
  if not h then
    return false, buffer, "Couldn't read a SSLv2 header"
  end
  if (#buffer - i + 1) < h.record_length then
    local status, resp = read_atleast(sock, h.record_length - (#buffer - i + 1))
    if not status then
      return false, buffer, resp
    end
    buffer = buffer .. resp
  end
  return true, buffer
end

function test_sslv2 (host, port)
  local timeout = stdnse.get_timeout(host, 10000, 5000)

  -- Create socket.
  local status, socket, err
  local starttls = sslcert.getPrepareTLSWithoutReconnect(port)
  if starttls then
    status, socket = starttls(host, port)
    if not status then
      stdnse.debug(1, "Can't connect using STARTTLS: %s", socket)
      return nil
    end
  else
    socket = nmap.new_socket()
    socket:set_timeout(timeout)
    status, err = socket:connect(host, port)
    if not status then
      stdnse.debug(1, "Can't connect: %s", err)
      return nil
    end
  end

  socket:set_timeout(timeout)

  local ssl_v2_hello = client_hello(stdnse.keys(SSL_CIPHER_CODES))

  socket:send(ssl_v2_hello)

  local status, record = record_buffer(socket)
  socket:close();
  if not status then
    return nil
  end

  local _, message = record_read(record)

  -- some sanity checks:
  -- is it SSLv2?
  if not message or not message.body then
    return
  end
  -- is response a server hello?
  if (message.message_type ~= SSL_MESSAGE_TYPES.SERVER_HELLO) then
    return
  end
  ---- is certificate in X.509 format?
  --if (message.body.cert_type ~= 1) then
  --  return
  --end

  return message.body.ciphers
end

return _ENV;
