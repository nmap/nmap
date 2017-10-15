local comm = require "comm"
local os = require "os"
local datetime = require "datetime"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote IMAP services with NTLM
authentication enabled.

Sending an IMAP NTLM authentication request with null credentials will
cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 143,993 --script imap-ntlm-info <target>
--
-- @output
-- 143/tcp   open     imap
-- | imap-ntlm-info:
-- |   Target_Name: ACTIVEIMAP
-- |   NetBIOS_Domain_Name: ACTIVEIMAP
-- |   NetBIOS_Computer_Name: IMAP-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: imap-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">ACTIVEIMAP</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVEIMAP</elem>
-- <elem key="NetBIOS_Computer_Name">IMAP-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">imap-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">6.1.7601</elem>


author = "Justin Cacak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


local ntlm_auth_blob = base64.enc( select(2,
  smbauth.get_security_blob(nil, nil, nil, nil, nil, nil, nil,
    0x00000001 + -- Negotiate Unicode
    0x00000002 + -- Negotiate OEM strings
    0x00000004 + -- Request Target
    0x00000200 + -- Negotiate NTLM
    0x00008000 + -- Negotiate Always Sign
    0x00080000 + -- Negotiate NTLM2 Key
    0x20000000 + -- Negotiate 128
    0x80000000 -- Negotiate 56
    ))
  )

portrule = shortport.port_or_service({ 143, 993 }, { "imap", "imaps" })

action = function(host, port)

  local output = stdnse.output_table()

  local starttls = sslcert.isPortSupported(port)
  local socket
  if starttls then
    local status
    status, socket = starttls(host, port)
    if not status then
      -- could be socket problems, but more likely STARTTLS not supported.
      stdnse.debug1("starttls error: %s", socket)
      socket = nil
    end
  end
  if not socket then
    local line, bopt, first_line
    socket, line, bopt, first_line = comm.tryssl(host, port, "" , {recv_before=true})
    if not socket then
      stdnse.debug1("connection error: %s", line)
      return nil
    end
  end

  socket:send("000b AUTHENTICATE NTLM\r\n")
  local status, response = socket:receive()
  if not status then
    stdnse.debug1("Socket receive failed: %s", response)
    return nil
  end
  if not response then
    stdnse.debug1("No response to AUTHENTICATE NTLM")
    return nil
  end

  socket:send(ntlm_auth_blob .. "\r\n")
  status, response = socket:receive()
  if not status then
    stdnse.debug1("Socket receive failed: %s", response)
    return nil
  end
  if not response then
    stdnse.debug1("No response to NTLM challenge")
    return nil
  end

  local recvtime = os.time()
  socket:close()

  if string.match(response, "^A%d%d%d%d ") then
    stdnse.debug2("NTLM auth not supported.")
    return nil
  end

  -- Continue only if a + response is returned
  local response_decoded = string.match(response, "+ (.*)")
  if not response_decoded then
    stdnse.debug1("Unexpected response to NTLM challenge: %s", response)
    return nil
  end

  local response_decoded = base64.dec(response_decoded)

  -- Continue only if NTLMSSP response is returned
  if not string.match(response_decoded, "^NTLMSSP") then
    stdnse.debug1("Unexpected response to NTLM challenge: %s", response)
    return nil
  end

  -- Leverage smbauth.get_host_info_from_security_blob() for decoding
  local ntlm_decoded = smbauth.get_host_info_from_security_blob(response_decoded)

  if ntlm_decoded.timestamp then
    -- 64-bit number of 100ns clicks since 1/1/1601
    local unixstamp = ntlm_decoded.timestamp // 10000000 - 11644473600
    datetime.record_skew(host, unixstamp, recvtime)
  end

  -- Target Name will always be returned under any implementation
  output.Target_Name = ntlm_decoded.target_realm

  -- Display information returned & ignore responses with null values
  if ntlm_decoded.netbios_domain_name and #ntlm_decoded.netbios_domain_name > 0 then
    output.NetBIOS_Domain_Name = ntlm_decoded.netbios_domain_name
  end

  if ntlm_decoded.netbios_computer_name and #ntlm_decoded.netbios_computer_name > 0 then
    output.NetBIOS_Computer_Name = ntlm_decoded.netbios_computer_name
  end

  if ntlm_decoded.dns_domain_name and #ntlm_decoded.dns_domain_name > 0 then
    output.DNS_Domain_Name = ntlm_decoded.dns_domain_name
  end

  if ntlm_decoded.fqdn and #ntlm_decoded.fqdn > 0 then
    output.DNS_Computer_Name = ntlm_decoded.fqdn
  end

  if ntlm_decoded.dns_forest_name and #ntlm_decoded.dns_forest_name > 0 then
    output.DNS_Tree_Name = ntlm_decoded.dns_forest_name
  end

  if ntlm_decoded.os_major_version then
    output.Product_Version = string.format("%d.%d.%d",
      ntlm_decoded.os_major_version, ntlm_decoded.os_minor_version, ntlm_decoded.os_build)
  end

  return output

end
