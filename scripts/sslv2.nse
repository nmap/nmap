local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local stdnse = require "stdnse"
local sslcert = require "sslcert"

description = [[
Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it
supports.
]]

---
--@output
-- 443/tcp open   https   syn-ack
-- | sslv2:
-- |   SSLv2 supported
-- |   ciphers:
-- |     SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |     SSL2_IDEA_128_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_WITH_MD5
-- |     SSL2_RC4_128_WITH_MD5
-- |     SSL2_DES_64_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
-- |_    SSL2_RC4_128_EXPORT40_WITH_MD5
--@xmloutput
--<elem>SSLv2 supported</elem>
--<table key="ciphers">
--  <elem>SSL2_DES_192_EDE3_CBC_WITH_MD5</elem>
--  <elem>SSL2_IDEA_128_CBC_WITH_MD5</elem>
--  <elem>SSL2_RC2_128_CBC_WITH_MD5</elem>
--  <elem>SSL2_RC4_128_WITH_MD5</elem>
--  <elem>SSL2_DES_64_CBC_WITH_MD5</elem>
--  <elem>SSL2_RC2_128_CBC_EXPORT40_WITH_MD5</elem>
--  <elem>SSL2_RC4_128_EXPORT40_WITH_MD5</elem>
--</table>


author = "Matthew Boyle"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}


portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local ssl_ciphers = {
  -- (cut down) table of codes with their corresponding ciphers.
  -- inspired by Wireshark's 'epan/dissectors/packet-ssl-utils.h'
  ["\x00\x00\x00"] = "SSL2_NULL_WITH_MD5",
  ["\x01\x00\x80"] = "SSL2_RC4_128_WITH_MD5",
  ["\x02\x00\x80"] = "SSL2_RC4_128_EXPORT40_WITH_MD5",
  ["\x03\x00\x80"] = "SSL2_RC2_128_CBC_WITH_MD5",
  ["\x04\x00\x80"] = "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
  ["\x05\x00\x80"] = "SSL2_IDEA_128_CBC_WITH_MD5",
  ["\x06\x00\x40"] = "SSL2_DES_64_CBC_WITH_MD5",
  ["\x07\x00\xc0"] = "SSL2_DES_192_EDE3_CBC_WITH_MD5",
  ["\x08\x00\x80"] = "SSL2_RC4_64_WITH_MD5",
}

--Invert a one-to-one mapping
local function invert(t)
  local out = {}
  for k, v in pairs(t) do
    out[v] = k
  end
  return out
end

local cipher_codes = invert(ssl_ciphers)

local ciphers = function(cipher_list)

  -- returns names of ciphers supported by the server

  local seen = {}
  local available_ciphers = {}

  for idx = 1, #cipher_list, 3 do
    local _, cipher = bin.unpack("A3", cipher_list, idx)
    local cipher_name = ssl_ciphers[cipher] or ("0x" .. stdnse.tohex(cipher))

    -- Check for duplicate ciphers
    if not seen[cipher] then
      table.insert(available_ciphers, cipher_name)
      seen[cipher] = true
    end
  end

  return available_ciphers
end

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

local function read_ssl_record(sock)
  local status, header_1_2 = sock:receive_buf(match.numbytes(2), true)
  if not status then
    return status
  end

  local header_length, record_length = parse_record_header_1_2(header_1_2)
  local padding_length
  if header_length == 2 then
    padding_length = 0
  else
    local status, header_3 = sock:receive_buf(match.numbytes(1), true)
    if not status then
      return status
    end
    local _
    _, padding_length = bin.unpack(">C", header_3)
  end

  local status, payload = sock:receive_buf(match.numbytes(record_length), true)

  return status, payload, padding_length
end

action = function(host, port)
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

  -- build client hello packet (contents inspired by
  -- http://mail.nessus.org/pipermail/plugins-writers/2004-October/msg00041.html )
  local cipher_list = (
    cipher_codes.SSL2_DES_192_EDE3_CBC_WITH_MD5 ..
    cipher_codes.SSL2_IDEA_128_CBC_WITH_MD5 ..
    cipher_codes.SSL2_RC2_128_CBC_WITH_MD5 ..
    cipher_codes.SSL2_RC4_128_WITH_MD5 ..
    cipher_codes.SSL2_RC4_64_WITH_MD5 ..
    cipher_codes.SSL2_DES_64_CBC_WITH_MD5 ..
    cipher_codes.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5 ..
    cipher_codes.SSL2_RC4_128_EXPORT40_WITH_MD5 ..
    cipher_codes.SSL2_NULL_WITH_MD5
    )
  -- Random
  local challenge = "\xe4\xbd\x00\x00\xa4\x41\xb6\x74\x71\x2b\x27\x95\x44\xc0\x3d\xc0"
  local ssl_v2_hello = bin.pack(">CSSSSAA",
    1, -- MSG-CLIENT-HELLO
    2, -- version: SSL 2.0
    #cipher_list, -- cipher spec length
    0, -- session ID length
    #challenge, -- challenge length
    cipher_list,
    challenge
    )
  -- Prepend length plus MSB
  ssl_v2_hello = bin.pack(">SA", #ssl_v2_hello + 0x8000, ssl_v2_hello)

  socket:send(ssl_v2_hello)

  local status, server_hello = read_ssl_record(socket)
  socket:close();
  if not status then
    return nil
  end

  -- split up server hello into components
  local idx, message_type, SID_hit, certificate_type, ssl_version, certificate_len, ciphers_len, connection_ID_len = bin.unpack(">CCCSSSS", server_hello)
  -- some sanity checks:
  -- is it SSLv2?
  if (ssl_version ~= 2) then
    return
  end
  -- is response a server hello?
  if (message_type ~= 4) then
    return
  end
  -- is certificate in X.509 format?
  if (certificate_type ~= 1) then
    return
  end

  local idx, certificate = bin.unpack("A" .. certificate_len, server_hello, idx)
  local idx, cipher_list = bin.unpack("A" .. ciphers_len, server_hello, idx)
  local idx, connection_ID = bin.unpack("A" .. connection_ID_len, server_hello, idx)

  -- get a list of ciphers offered
  local available_ciphers = ciphers_len > 0 and ciphers(cipher_list) or "none"

  return {
    "SSLv2 supported",
    ciphers = available_ciphers
  }

end
