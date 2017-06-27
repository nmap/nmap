local comm = require 'comm'
local string = require 'string'
local stdnse = require 'stdnse'
local shortport = require 'shortport'

description = [[
Check if the Secure Socket Tunneling Protocol is supported. This is
accomplished by trying to establish the HTTPS layer which is used to
carry SSTP traffic as described in:
    - http://msdn.microsoft.com/en-us/library/cc247364.aspx

Current SSTP server implementations:
    - Microsoft Windows (Server 2008/Server 2012)
    - MikroTik RouterOS
    - SEIL (http://www.seil.jp)
]]

--SSTP specification:
--    _ http://msdn.microsoft.com/en-us/library/cc247338.aspx
--
--Info about the default URI (ServerUri):
--    - http://support.microsoft.com/kb/947054
--
--SSTP Remote Access Step-by-Step Guide: Deployment:
--    - http://technet.microsoft.com/de-de/library/cc731352(v=ws.10).aspx
--
--SSTP enabled hosts (for testing purposes):
--    - http://billing.purevpn.com/sstp-manual-setup-hostname-list.php

author = "Niklaus Schiess <nschiess@adversec.com>"
categories = {'discovery', 'default', 'safe'}

---
--@output
-- 443/tcp open  https
-- |_sstp-discover: SSTP is supported.
--@xmloutput
-- true

-- SSTP negotiation response (Windows)
--
-- HTTP/1.1 200
-- Content-Length: 18446744073709551615
-- Server: Microsoft-HTTPAPI/2.0
-- Date: Fri, 01 Nov 2013 00:00:00 GMT

-- SSTP negotiation response (Mikrotik RouterOS)
--
-- HTTP/1.1 200
-- Content-Length: 18446744073709551615
-- Server: MikroTik-SSTP
-- Date: Fri, 01 Nov 2013 00:00:00 GMT

portrule = function(host, port)
  return shortport.http(host, port) and shortport.ssl(host, port)
end

-- The SSTPCORRELATIONID GUID is optional and client-generated.
-- The last 5 bytes are "Nmap!"
local request =
'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n' ..
'Host: %s\r\n' ..
'SSTPCORRELATIONID: {5a433238-8781-11e3-b2e4-4e6d617021}\r\n' ..
'Content-Length: 18446744073709551615\r\n\r\n'

action = function(host, port)
  local socket, response = comm.tryssl(host,port,
    string.format(request, host.targetname or host.ip),
    { timeout=3000, lines=4 })
  if not socket then
    stdnse.debug1("Problem establishing connection: %s", response)
    return nil
  end
  socket:close()

  if string.match(response, 'HTTP/1.1 200') then
    return true, 'SSTP is supported.'
  end
  return nil
end
