local nmap = require "nmap"
local shortport = require "shortport"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local vulns = require "vulns"

description = [[
Determines whether the server supports SSLv2, what ciphers it supports and tests for
CVE-2015-3197, CVE-2016-0703 and CVE-2016-0800 (DROWN)
]]
author = "Bertrand Bonnefoy-Claudet <bertrand@cryptosense.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"sslv2"}
categories = {"default", "safe"}

---
-- @output
-- 443/tcp open  https
-- | sslv2-drown:
-- |   ciphers:
-- |     SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |     SSL2_IDEA_128_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_WITH_MD5
-- |     SSL2_RC4_128_WITH_MD5
-- |     SSL2_DES_64_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
-- |     SSL2_RC4_128_EXPORT40_WITH_MD5
-- |   forced_ciphers:
-- |     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
-- |     SSL2_DES_64_CBC_WITH_MD5
-- |     SSL2_RC4_128_EXPORT40_WITH_MD5
-- |     SSL2_IDEA_128_CBC_WITH_MD5
-- |     SSL2_RC4_128_WITH_MD5
-- |     SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |     SSL2_RC2_128_CBC_WITH_MD5
-- |   vulns:
-- |     CVE-2016-0800:
-- |       title: OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)
-- |       state: VULNERABLE
-- |       ids:
-- |         CVE:CVE-2016-0800
-- |       description:
-- |               The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
-- |       other products, requires a server to send a ServerVerify message before establishing
-- |       that a client possesses certain plaintext RSA data, which makes it easier for remote
-- |       attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
-- |       oracle, aka a "DROWN" attack.
-- |
-- |       refs:
-- |         https://www.openssl.org/news/secadv/20160301.txt
-- |_        https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800
--
-- @xmloutput
-- <elem>SSLv2 supported</elem>
-- <table key="ciphers">
--   <elem>SSL2_DES_192_EDE3_CBC_WITH_MD5</elem>
--   <elem>SSL2_IDEA_128_CBC_WITH_MD5</elem>
--   <elem>SSL2_RC2_128_CBC_WITH_MD5</elem>
--   <elem>SSL2_RC4_128_WITH_MD5</elem>
--   <elem>SSL2_DES_64_CBC_WITH_MD5</elem>
--   <elem>SSL2_RC2_128_CBC_EXPORT40_WITH_MD5</elem>
--   <elem>SSL2_RC4_128_EXPORT40_WITH_MD5</elem>
-- </table>
-- @xmloutput
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
-- <table key="forced_ciphers">
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
--     <elem key="value">0700c0</elem>
--     <elem key="name">SSL2_DES_192_EDE3_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">020080</elem>
--     <elem key="name">SSL2_RC4_128_EXPORT40_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">060040</elem>
--     <elem key="name">SSL2_DES_64_CBC_WITH_MD5</elem>
--   </table>
--   <table>
--     <elem key="value">040080</elem>
--     <elem key="name">SSL2_RC2_128_CBC_EXPORT40_WITH_MD5</elem>
--   </table>
-- </table>
-- <table key="vulns">
--   <table key="CVE-2016-0800">
--     <elem key="title">OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)</elem>
--     <elem key="state">VULNERABLE</elem>
--     <table key="ids">
--       <elem>CVE:CVE-2016-0800</elem>
--     </table>
--     <table key="description">
--       <elem>
--         The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before
--         1.0.2g and other products, requires a server to send a ServerVerify
--         message before establishing that a client possesses certain plaintext
--         RSA data, which makes it easier for remote attackers to decrypt TLS
--         ciphertext data by leveraging a Bleichenbacher RSA padding oracle, aka
--         a "DROWN" attack.
--       </elem>
--     </table>
--     <table key="refs">
--       <elem>https://www.openssl.org/news/secadv/20160301.txt</elem>
--       <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800</elem>
--     </table>
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

-- Those ciphers are weak enough to enable a "General DROWN" attack.
local GENERAL_DROWN_CIPHERS = {
  [SSL_CK.RC2_128_CBC_EXPORT40_WITH_MD5] = true,
  [SSL_CK.RC4_128_EXPORT40_WITH_MD5] = true,
  [SSL_CK.DES_64_CBC_WITH_MD5] = true,
}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Return whether all values of "t1" are also values in "t2".
local function values_in(t1, t2)
  local set = {}
  for _, e in pairs(t2) do
    set[e] = true
  end
  for _, e in pairs(t1) do
    if not set[e] then
      return false
    end
  end
  return true
end

-- Create a string from repeating "length" times the given pattern.
local function make_string(length, pattern)
  local string = {}
  for i=1, length do
    string[i] = "\x00"
  end
  return table.concat(string)
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

local function client_master_secret(cipher_kind, clear_key, encrypted_key, key_arg)
  local key_arg = key_arg or ""
  return
    bin.pack(">C", SSL_MT.CLIENT_MASTER_KEY)
    .. cipher_kind
    .. bin.pack(">S", #clear_key)
    .. bin.pack(">S", #encrypted_key)
    .. bin.pack(">S", #key_arg)
    .. clear_key
    .. encrypted_key
    .. key_arg
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

local function try_force_cipher(host, port, cipher)
  local socket = get_socket(host, port)
  if not socket then
    return false
  end
  local socket_read = socket_reader(socket)

  socket:send(ssl_record(CLIENT_HELLO_EXAMPLE))
  local status, server_hello = read_ssl_record(socket_read)
  if not status then
    socket:close()
    return false
  end

  local key_length = CIPHER_INFO[cipher].key_length
  local encrypted_key_length = CIPHER_INFO[cipher].encrypted_key_length

  local dummy_key = make_string(key_length, "\x00")
  local clear_key = dummy_key:sub(1, key_length - encrypted_key_length)
  local encrypted_key = dummy_key:sub(key_length - encrypted_key_length + 1)

  local dummy_client_master_key = client_master_secret(cipher, clear_key, encrypted_key)
  socket:send(ssl_record(dummy_client_master_key))
  local status, message = read_ssl_record(socket_read)
  socket:close()
  if not status then
    return false
  end

  -- Treat an error as a failure to force the cipher.
  if #message == 3 then
    return false
  end

  return true
end

local function has_extra_clear_bug(host, port, cipher)
  local socket = get_socket(host, port)
  if not socket then
    return
  end
  local socket_read = socket_reader(socket)
  socket:send(ssl_record(CLIENT_HELLO_EXAMPLE))
  local status, server_hello = read_ssl_record(socket_read)
  if not status then
    socket:close()
    return
  end

  local key_length = CIPHER_INFO[cipher].key_length
  local encrypted_key_length = CIPHER_INFO[cipher].encrypted_key_length

  -- The length of clear_key is intentionally wrong to highlight the bug.
  local clear_key = make_string(key_length - encrypted_key_length + 1, "\x00")
  local encrypted_key = make_string(encrypted_key_length, "\x00")

  local dummy_client_master_key = client_master_secret(cipher, clear_key, encrypted_key)
  socket:send(ssl_record(dummy_client_master_key))
  local status, message = read_ssl_record(socket_read)
  socket:close()
  if not status then
    return
  end

  -- Treat an error as the absence of the bug.
  if #message == 3 then
    return false
  end

  return true
end

local function registry_get(host, port)
  if host.registry.sslv2 then
    return host.registry.sslv2[port.number]
  end
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
  local report = vulns.Report:new("sslv2-drown", host, port)
  local cve_2015_3197 = {
    title = "OpenSSL: SSLv2 doesn't block disabled ciphers",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2015-3197',
    },
    risk_factor = "Low",
    description = [[
      ssl/s2_srvr.c in OpenSSL 1.0.1 before 1.0.1r and 1.0.2 before 1.0.2f does not
      prevent use of disabled ciphers, which makes it easier for man-in-the-middle
      attackers to defeat cryptographic protection mechanisms by performing computations
      on SSLv2 traffic, related to the get_client_master_key and get_client_hello
      functions.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3197",
      "https://www.openssl.org/news/secadv/20160128.txt",
    },
  }
  local cve_2016_0703 = {
    title = "OpenSSL: Divide-and-conquer session key recovery in SSLv2",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2016-0703',
    },
    risk_factor = "High",
    description = [[
      The get_client_master_key function in s2_srvr.c in the SSLv2 implementation in
      OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
      1.0.2a accepts a nonzero CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an arbitrary
      cipher, which allows man-in-the-middle attackers to determine the MASTER-KEY value
      and decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding oracle, a
      related issue to CVE-2016-0800.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0703",
      "https://www.openssl.org/news/secadv/20160301.txt",
    },
  }
  local cve_2016_0800 = {
    title = "OpenSSL: Cross-protocol attack on TLS using SSLv2 (DROWN)",
    state = vulns.STATE.NOT_VULN,
    IDS = {
      CVE = 'CVE-2016-0800',
    },
    risk_factor = "High",
    description = [[
      The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and
      other products, requires a server to send a ServerVerify message before establishing
      that a client possesses certain plaintext RSA data, which makes it easier for remote
      attackers to decrypt TLS ciphertext data by leveraging a Bleichenbacher RSA padding
      oracle, aka a "DROWN" attack.
    ]],
    references = {
      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0800",
      "https://www.openssl.org/news/secadv/20160301.txt",
    },
  }
  report:add_vulns(cve_2015_3197)
  report:add_vulns(cve_2016_0703)
  report:add_vulns(cve_2016_0800)

  local offered_ciphers = registry_get(host, port)
  if not offered_ciphers then -- when the sslv2 was not previously run
		local sslv2_supported
		sslv2_supported, offered_ciphers = test_sslv2(host, port)
		if not sslv2_supported then
			output.vulns = report:make_output()
			return output
		end
  end
  output.ciphers = format_ciphers(offered_ciphers)

  -- CVE-2015-3197
  local forced_ciphers = {}
  for _, cipher in pairs(SSL_CK) do
    if try_force_cipher(host, port, cipher) then
      table.insert(forced_ciphers, cipher)
    end
  end
  output.forced_ciphers = format_ciphers(forced_ciphers)
  if not values_in(forced_ciphers, offered_ciphers) then
    cve_2015_3197.state = vulns.STATE.VULN
  end

  -- CVE-2016-0703
  for _, cipher in pairs(forced_ciphers) do
    local result = has_extra_clear_bug(host, port, cipher)
    if result == true then
      cve_2016_0703.state = vulns.STATE.VULN
      break
    end
  end

  -- CVE-2016-0800
  local has_weak_ciphers = false
  for _, cipher in pairs(forced_ciphers) do
    if GENERAL_DROWN_CIPHERS[cipher] then
      has_weak_ciphers = true
      break
    end
  end
  if has_weak_ciphers or output.cve_2016_0703 == "yes" then
    cve_2016_0800.state = vulns.STATE.VULN
  end

  output.vulns = report:make_output()
  return output
end
