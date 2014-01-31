local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local nmap = require "nmap"
local os = require "os"
local string = require "string"
local sslcert = require "sslcert"
local tls = require "tls"

description = [[
Retrieves a target host's time and date from its TLS ServerHello response.


In many TLS implementations, the first four bytes of server randomness
are a Unix timestamp.

Original idea by Jacob Appelbaum and his TeaTime and tlsdate tools:
* https://github.com/ioerror/TeaTime
* https://github.com/ioerror/tlsdate
]]

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end


---
-- @usage
-- nmap <target> --script=ssl-date
--
-- @output
-- PORT    STATE SERVICE REASON
-- 5222/tcp open  xmpp-client syn-ack
-- |_ssl-date: 2012-08-02T18:29:31Z; +4s from local time.
--
-- @xmloutput
-- <elem key="date">2012-08-02T18:29:31+00:00</elem>
-- <elem key="delta">4</elem>

--
-- most of the code snatched from tls-nextprotoneg until we decide if we want a separate library
--

--- Function that sends a client hello packet
-- target host and returns the response
--@args host The target host table.
--@args port The target port table.
--@return status true if response, false else.
--@return response if status is true.
local client_hello = function(host, port)
  local sock, status, response, err, cli_h

  -- Craft Client Hello
  cli_h = tls.client_hello({
    ["protocol"] = "TLSv1.0",
    ["ciphers"] = {
      "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
      "TLS_RSA_WITH_RC4_128_MD5",
    },
    ["compressors"] = {"NULL"},
  })

  -- Connect to the target server
  local specialized_function = sslcert.getPrepareTLSWithoutReconnect(port)

  if not specialized_function then
    sock = nmap.new_socket()
    sock:set_timeout(5000)
    status, err = sock:connect(host, port)
    if not status then
      sock:close()
      stdnse.print_debug("Can't send: %s", err)
      return false
    end
  else
    status,sock = specialized_function(host,port)
    if not status then
      return false
    end
  end


  -- Send Client Hello to the target server
  status, err = sock:send(cli_h)
  if not status then
    stdnse.print_debug("Couldn't send: %s", err)
    sock:close()
    return false
  end

  -- Read response
  status, response, err = tls.record_buffer(sock)
  if not status then
    stdnse.print_debug("Couldn't receive: %s", err)
    sock:close()
    return false
  end

  return true, response
end

-- extract time from ServerHello response
local extract_time = function(response)
  local i, record = tls.record_read(response, 0)
  if record == nil then
    stdnse.print_debug("%s: Unknown response from server", SCRIPT_NAME)
    return nil
  end

  if record.type == "handshake" then
    for _, body in ipairs(record.body) do
      if body.type == "server_hello" then
        return true, body.time
      end
    end
  end
  stdnse.print_debug("%s: Server response was not server_hello", SCRIPT_NAME)
  return nil
end

action = function(host, port)
  local status, response

  -- Send crafted client hello
  status, response = client_hello(host, port)
  local now = os.time()
  if status and response then
    -- extract time from response
    local result
    status, result = extract_time(response)
    if status then
      local output = {
        date = stdnse.format_timestamp(result, 0),
        delta = os.difftime(result, now),
      }
      return output, string.format("%s; %s from local time.", output.date,
        stdnse.format_difftime(os.date("!*t",result),os.date("!*t", now)))
    end
  end
end
