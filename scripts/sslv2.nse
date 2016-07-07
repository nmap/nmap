local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local sslv2 = require "sslv2"

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

  local ssl_v2_hello = sslv2.client_hello(stdnse.keys(sslv2.SSL_CIPHER_CODES))

  socket:send(ssl_v2_hello)

  local status, record = sslv2.record_buffer(socket)
  socket:close();
  if not status then
    return nil
  end

  local _, message = sslv2.record_read(record)

  -- some sanity checks:
  -- is it SSLv2?
  if not message or not message.body then
    return
  end
  -- is response a server hello?
  if (message.message_type ~= sslv2.SSL_MESSAGE_TYPES.SERVER_HELLO) then
    return
  end
  ---- is certificate in X.509 format?
  --if (message.body.cert_type ~= 1) then
  --  return
  --end

  return {
    "SSLv2 supported",
    ciphers = #message.body.ciphers > 0 and message.body.ciphers or "none"
  }

end
