local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local stdnse = require "stdnse"
local sslcert = require "sslcert"

description = [[
Determines whether the server supports SSLv2 and discovers which ciphers it supports.
]]
author = "Matthew Boyle, Bertrand Bonnefoy-Claudet <bertrand@cryptosense.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

-- @output
-- 443/tcp open  https
-- | sslv2:
-- |   sslv2_supported: yes
-- |   ciphers:
-- |     SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |     SSL2_IDEA_128_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_WITH_MD5
-- |     SSL2_RC4_128_WITH_MD5
-- |     SSL2_DES_64_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
-- |_    SSL2_RC4_128_EXPORT40_WITH_MD5
--
-- @xmloutput
-- <elem key="sslv2_supported">yes</elem>
-- <table key="ciphers">
--   <table>
--     <elem key="value">0700c0</elem>
--     <elem key="name">SSL2_DES_192_EDE3_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">050080</elem>
--     <elem key="name">SSL2_IDEA_128_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">030080</elem>
--     <elem key="name">SSL2_RC2_128_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">010080</elem>
--     <elem key="name">SSL2_RC4_128_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">060040</elem>
--     <elem key="name">SSL2_DES_64_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">040080</elem>
--     <elem key="name">SSL2_RC2_128_CBC_EXPORT40_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">020080</elem>
--     <elem key="name">SSL2_RC4_128_EXPORT40_WITH_MD5</elem>
--   </table>
-- </table>

local SSL_MT = {
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

local SSL_CK = {
  RC4_128_WITH_MD5 = "\x01\x00\x80",
  RC4_128_EXPORT40_WITH_MD5 = "\x02\x00\x80",
  RC2_128_CBC_WITH_MD5 = "\x03\x00\x80",
  RC2_128_CBC_EXPORT40_WITH_MD5 = "\x04\x00\x80",
  IDEA_128_CBC_WITH_MD5 = "\x05\x00\x80",
  DES_64_CBC_WITH_MD5 = "\x06\x00\x40",
  DES_192_EDE3_CBC_WITH_MD5 = "\x07\x00\xC0",

  -- from OpenSSL
  NULL_WITH_MD5 = "\x00\x00\x00",
  RC4_64_WITH_MD5 = "\x08\x00\x80",
}

local SSL_CT = {
  X509_CERTIFICATE = 1,
}

local SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER = 32767
local SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER = 16383

local CIPHER_INFO = {
  ["\x01\x00\x80"] = {
    str = "SSL2_RC4_128_WITH_MD5",
  },
  ["\x02\x00\x80"] = {
    str = "SSL2_RC4_128_EXPORT40_WITH_MD5",
  },
  ["\x03\x00\x80"] = {
    str = "SSL2_RC2_128_CBC_WITH_MD5",
  },
  ["\x04\x00\x80"] = {
    str = "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
  },
  ["\x05\x00\x80"] = {
    str = "SSL2_IDEA_128_CBC_WITH_MD5",
  },
  ["\x06\x00\x40"] = {
    str = "SSL2_DES_64_CBC_WITH_MD5",
  },
  ["\x07\x00\xc0"] = {
    str = "SSL2_DES_192_EDE3_CBC_WITH_MD5",
  },
  ["\x00\x00\x00"] = {
    str = "SSL2_NULL_WITH_MD5",
  },
  ["\x08\x00\x80"] = {
    str = "SSL2_RC4_64_WITH_MD5",
  },
}

local CLIENT_HELLO_EXAMPLE =
  "\x01" -- MSG-CLIENT-HELLO
  .. "\x00\x02" -- version: SSL 2.0
  .. "\x00\x1b" -- cipher spec length
  .. "\x00\x00" -- session ID length
  .. "\x00\x10" -- challenge length
  .. SSL_CK.DES_192_EDE3_CBC_WITH_MD5
  .. SSL_CK.IDEA_128_CBC_WITH_MD5
  .. SSL_CK.RC2_128_CBC_WITH_MD5
  .. SSL_CK.RC4_128_WITH_MD5
  .. SSL_CK.RC4_64_WITH_MD5
  .. SSL_CK.DES_64_CBC_WITH_MD5
  .. SSL_CK.RC2_128_CBC_EXPORT40_WITH_MD5
  .. SSL_CK.RC4_128_EXPORT40_WITH_MD5
  .. SSL_CK.NULL_WITH_MD5
  .. "\xe4\xbd\x00\x00\xa4\x41\xb6\x74\x71\x2b\x27\x95\x44\xc0\x3d\xc0" -- challenge

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Create a socket ready to begin an SSL negociation.
local function get_socket(host, port)
  local timeout = stdnse.get_timeout(host, 10000, 5000)
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
  return socket
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

local function ssl_record(payload)
  local length = #payload
  if length > SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER then
    return  -- 3-byte header not supported yet
  end
  local length_field = bin.pack(">S", bit.bor(length, 0x8000))
  return length_field .. payload
end

-- Determine whether SSLv2 is supported by the target host and what ciphers if offers.
--
-- The first return value is a boolean representing SSLv2 support.  If it is "true", the
-- second return value is a list of supported ciphers.
local function test_sslv2(host, port)
  local socket = get_socket(host, port)
  if not socket then
    return false
  end
  local socket_read = socket_reader(socket)

  socket:send(ssl_record(CLIENT_HELLO_EXAMPLE))
  local status, server_hello = read_ssl_record(socket_read)
  socket:close();
  if not status then
    return false
  end

  -- split up server hello into components
  local idx, message_type, SID_hit, certificate_type, ssl_version, certificate_len, ciphers_len, connection_ID_len = bin.unpack(">CCCSSSS", server_hello)

  if message_type ~= SSL_MT.SERVER_HELLO then
    return true, {}
  end
  if certificate_type ~= SSL_CT.X509_CERTIFICATE then
    return true, {}
  end

  local idx, certificate = bin.unpack("A" .. certificate_len, server_hello, idx)
  local idx, cipher_specs = bin.unpack("A" .. ciphers_len, server_hello, idx)

  local ciphers = {}
  for pos = 1, #cipher_specs, 3 do
    table.insert(ciphers, cipher_specs:sub(pos, pos + 2))
  end
  return ssl_version == 2, ciphers
end

local function registry_set(host, port, offered_ciphers)
  if not host.registry.sslv2 then
    host.registry.sslv2 = {}
  end
  host.registry.sslv2[port.number] = offered_ciphers
end

local function format_ciphers(ciphers)
  local seen = {}
  local available_ciphers = {}

  for _, cipher in ipairs(ciphers) do
    local cipher_name = CIPHER_INFO[cipher].str

    -- Check for duplicate ciphers
    if not seen[cipher] then
      local cipher_info = {name = cipher_name, value = stdnse.tohex(cipher)}
      setmetatable(cipher_info, {
        __tostring = function (t)
          return t.name
        end
      })
      table.insert(available_ciphers, cipher_info)
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

function action(host, port)
  local output = stdnse.output_table()

  local sslv2_supported, offered_ciphers = test_sslv2(host, port)
  if sslv2_supported then
    output.sslv2_supported = "yes"
  else
    return
  end
  registry_set(host, port, offered_ciphers)
  output.ciphers = format_ciphers(offered_ciphers)

  return output
end
