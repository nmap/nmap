local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local bin = require "bin"
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
  [0x010080] = "SSL2_RC4_128_WITH_MD5",
  [0x020080] = "SSL2_RC4_128_EXPORT40_WITH_MD5",
  [0x030080] = "SSL2_RC2_128_CBC_WITH_MD5",
  [0x040080] = "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
  [0x050080] = "SSL2_IDEA_128_CBC_WITH_MD5",
  [0x060040] = "SSL2_DES_64_CBC_WITH_MD5",
  [0x0700c0] = "SSL2_DES_192_EDE3_CBC_WITH_MD5",
  [0x080080] = "SSL2_RC4_64_WITH_MD5",
}

local ciphers = function(cipher_list)

  -- returns names of ciphers supported by the server

  local seen = {}
  local available_ciphers = {}

  for idx = 1, #cipher_list, 3 do
    local _, cipher_high, cipher_low = bin.unpack(">CS", cipher_list, idx)
    local cipher = cipher_high * 0x10000 + cipher_low
    local cipher_name = ssl_ciphers[cipher] or string.format("0x%06x", cipher)

    -- Check for duplicate ciphers
    if not seen[cipher] then
      table.insert(available_ciphers, cipher_name)
      seen[cipher] = true
    end
  end

  return available_ciphers
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
  local ssl_v2_hello = "\x80\x31" -- length 49
  .. "\x01" -- MSG-CLIENT-HELLO
  .. "\x00\x02" -- version: SSL 2.0
  .. "\x00\x18" -- cipher spec length (24)
  .. "\x00\x00" -- session ID length (0)
  .. "\x00\x10" -- challenge length (16)
  .. "\x07\x00\xc0" -- SSL2_DES_192_EDE3_CBC_WITH_MD5
  .. "\x05\x00\x80" -- SSL2_IDEA_128_CBC_WITH_MD5
  .. "\x03\x00\x80" -- SSL2_RC2_128_CBC_WITH_MD5
  .. "\x01\x00\x80" -- SSL2_RC4_128_WITH_MD5
  .. "\x08\x00\x80" -- SSL2_RC4_64_WITH_MD5
  .. "\x06\x00\x40" -- SSL2_DES_64_CBC_WITH_MD5
  .. "\x04\x00\x80" -- SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
  .. "\x02\x00\x80" -- SSL2_RC4_128_EXPORT40_WITH_MD5
  .. "\xe4\xbd\x00\x00\xa4\x41\xb6\x74\x71\x2b\x27\x95\x44\xc0\x3d\xc0" -- challenge

  socket:send(ssl_v2_hello)

  local status, server_hello = socket:receive_bytes(2)

  if (not status) then
    socket:close()
    return
  end

  local idx, server_hello_len = bin.unpack(">S", server_hello)
  -- length record doesn't include its own length, and is "broken".
  server_hello_len = server_hello_len - (128 * 256) + 2

  -- the hello needs to be at least 13 bytes long to be of any use
  if (server_hello_len < 13) then
    socket:close()
    stdnse.debug(1, "Server Hello too short")
    return
  end
  --try to get entire hello, if we don't already
  if (#server_hello < server_hello_len) then
    local status, tmp = socket:receive_bytes(server_hello_len - #server_hello)

    if (not status) then
      socket:close()
      return
    end

    server_hello = server_hello .. tmp
  end

  socket:close()

  -- split up server hello into components
  local idx, message_type, SID_hit, certificate_type, ssl_version, certificate_len, ciphers_len, connection_ID_len = bin.unpack(">CCCSSSS", server_hello, idx)
  -- some sanity checks:
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

  -- actually run some tests:
  local o = stdnse.output_table()
  if (ssl_version == 2) then
    table.insert(o, "SSLv2 supported")
    o["ciphers"] = available_ciphers
  end

  return o
end
