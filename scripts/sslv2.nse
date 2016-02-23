local nmap = require "nmap"
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

-- Read at least "n" bytes from a socket "s" given as argument.
local function read_atleast(s, n)
  local strings = {}
  local count = 0
  while count < n do
    local status, data = s:receive_bytes(n - count)
    table.insert(strings, data)
    count = count + #data
    if not status then
      return status, table.concat(strings)
    end
  end
  return true, table.concat(strings)
end

-- Return a function that reads exactly "n" bytes from a socket.
--
-- The function remains attached to the socket given to build it and keeps a buffer of
-- extra received bytes so that they will be returned when necessary.
local function socket_reader(socket)
  local available = ""
  return function(n)
    local status, received = read_atleast(socket, n - #available)
    local total = available .. received
    available = total:sub(n + 1)
    return status, total:sub(1, n)
  end
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

local function read_ssl_record(socket_read)
  local status, header_1_2 = socket_read(2)
  if not status then
    return status
  end

  local header_length, record_length = parse_record_header_1_2(header_1_2)
  local padding_length
  if header_length == 2 then
    padding_length = 0
  else
    local status, header_3 = socket_read(1)
    if not status then
      return status
    end
    _, padding_length = bin.unpack(">C", header_3)
  end

  local status, payload = socket_read(record_length)
  if not status then
    return status
  end

  return true, payload, padding_length
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

  if #available_ciphers == 0 then
    setmetatable(available_ciphers, {
        __tostring = function(t)
          return "none"
        end
      })
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

  local socket_read = socket_reader(socket)

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

  local status, server_hello = read_ssl_record(socket_read)
  socket:close();
  if not status then
    return
  end

  -- split up server hello into components
  local idx, message_type, SID_hit, certificate_type, ssl_version, certificate_len, ciphers_len, connection_ID_len = bin.unpack(">CCCSSSS", server_hello)
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
  local available_ciphers = ciphers(cipher_list)

  -- actually run some tests:
  local o = stdnse.output_table()
  if (ssl_version == 2) then
    table.insert(o, "SSLv2 supported")
    o["ciphers"] = available_ciphers
  end

  return o
end
