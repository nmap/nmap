local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local sslcert = require "sslcert"
local tls = require "tls"

description = [[
Enumerates a TLS server's supported application-layer protocols using the ALPN protocol.

Repeated queries are sent to determine which of the registered protocols are supported.

For more information, see:
* https://tools.ietf.org/html/rfc7301
]]

---
-- @usage
-- nmap --script=tls-alpn <targets>
--
--@output
-- 443/tcp open  https
-- | tls-alpn:
-- |   h2
-- |   spdy/3
-- |_  http/1.1
--
-- @xmloutput
-- <elem>h2</elem>
-- <elem>spdy/3</elem>
-- <elem>http/1.1</elem>


author = "Daniel Miller"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "default"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port)
end


local ALPN_NAME = "application_layer_protocol_negotiation"

--- Function that sends a client hello packet with the TLS ALPN extension to the
-- target host and returns the response
--@args host The target host table.
--@args port The target port table.
--@return status true if response, false else.
--@return response if status is true.
local client_hello = function(host, port, protos)
  local sock, status, response, err, cli_h

  cli_h = tls.client_hello({
    ["extensions"] = {
      [ALPN_NAME] = tls.EXTENSION_HELPERS[ALPN_NAME](protos)
    },
  })

  -- Connect to the target server
  local status, err
  local sock
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then
      stdnse.debug1("Connection to server failed: %s", sock)
      return false
    end
  else
    sock = nmap.new_socket()
    status, err = sock:connect(host, port)
    if not status then
      stdnse.debug1("Connection to server failed: %s", err)
      return false
    end
  end

  sock:set_timeout(5000)

  -- Send Client Hello to the target server
  status, err = sock:send(cli_h)
  if not status then
    stdnse.debug1("Couldn't send: %s", err)
    sock:close()
    return false
  end

  -- Read response
  status, response, err = tls.record_buffer(sock)
  if not status then
    stdnse.debug1("Couldn't receive: %s", err)
    sock:close()
    return false
  end

  return true, response
end

--- Function that checks for the returned protocols to a ALPN extension request.
--@args response Response to parse.
--@return results List of found protocols.
local check_alpn = function(response)
  local i, record = tls.record_read(response, 1)
  if record == nil then
    stdnse.debug1("Unknown response from server")
    return nil
  end

  if record.type == "handshake" and record.body[1].type == "server_hello" then
    if record.body[1].extensions == nil then
      stdnse.debug1("Server does not support TLS ALPN extension.")
      return nil
    end
    local results = {}
    local alpndata = record.body[1].extensions[ALPN_NAME]
    if alpndata == nil then
      stdnse.debug1("Server does not support TLS ALPN extension.")
      return nil
    end
    -- Parse data
    alpndata = string.unpack(">s2", alpndata, 1)
    i = 1
    while i <= #alpndata do
      if i > 1 then
        stdnse.debug1("Server sent multiple protocols but RFC only permits 1")
      end
      local protocol
      protocol, i = string.unpack(">s1", alpndata, i)
      table.insert(results, protocol)
    end

    if next(results) then
      return results
    else
      stdnse.debug1("Server supports TLS ALPN extension, but no protocols were offered.")
      return nil
    end
  else
    stdnse.debug1("Server response was not server_hello")
    return nil
  end
end

local function find_and_remove(t, value)
  for i, v in ipairs(t) do
    if v == value then
      table.remove(t, i)
      return true
    end
  end
  return false
end

action = function(host, port)
  local alpn_protos = {
    -- IANA-registered names
    "http/1.1",
    "spdy/1",
    "spdy/2",
    "spdy/3",
    "stun.turn",
    "stun.nat-discovery",
    "h2",
    "h2c", -- should never be negotiated over TLS
    "webrtc",
    "c-webrtc",
    "ftp",
    "imap",
    "pop3",
    "managesieve",
    -- Other sources
    "grpc-exp", -- gRPC, see grpc.io
  }

  local chosen = {}
  while next(alpn_protos) do
    -- Send crafted client hello
    local status, response = client_hello(host, port, alpn_protos)
    if status and response then
      -- Analyze response
      local result = check_alpn(response)
      if not result then
        stdnse.debug1("None of %d protocols chosen", #alpn_protos)
        break
      end
      for i, p in ipairs(result) do
        if i > 1 then
          stdnse.verbose1("Server violates RFC: sent additional protocol %s", p)
        end
        chosen[#chosen+1] = p
        if not find_and_remove(alpn_protos, p) then
          stdnse.debug1("Chosen ALPN protocol %s was not offered", p)
          if stdnse.contains(chosen, p) then
            stdnse.debug1("Server is forcing %s", p)
            break
          end
        end
      end
    else
      stdnse.debug1("Client hello failed with %d protocols", #alpn_protos)
      break
    end
  end
  if next(chosen) then
    return chosen
  end
end
