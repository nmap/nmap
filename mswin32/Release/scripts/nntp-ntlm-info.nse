local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote NNTP services with NTLM
authentication enabled.

Sending an MS-NNTP NTLM authentication request with null credentials will
cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 119,433,563 --script nntp-ntlm-info <target>
--
-- @output
-- 119/tcp   open     nntp
-- | nntp-ntlm-info:
-- |   Target_Name: ACTIVENNTP
-- |   NetBIOS_Domain_Name: ACTIVENNTP
-- |   NetBIOS_Computer_Name: NNTP-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: nntp-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">ACTIVENNTP</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVENNTP</elem>
-- <elem key="NetBIOS_Computer_Name">NNTP-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">nntp-test2.somedomain.com</elem>
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


portrule = shortport.port_or_service({ 119, 433, 563 }, { "nntp", "snews" })

action = function(host, port)

  local output = stdnse.output_table()

  -- Negotiate connection protocol
  local socket, line, bopt, first_line = comm.tryssl(host, port, "" , {timeout=10000, recv_before=true})
  if not socket then
    return
  end

  -- Do not attempt to upgrade to a TLS connection if already over TLS
  if not shortport.ssl(host,port) then
    -- Attempt to upgrade to a TLS connection if supported (may not be advertised)
    -- Various implementations *require* this before accepting authentication requests
    socket:send("STARTTLS\r\n")
    local status, response = socket:receive()
    if not status then
      return
    end
    -- Upgrade the connection if STARTTLS permitted, else continue without
    if string.match(response, "382 .*") then
      status, response = socket:reconnect_ssl()
      if not status then
        return
      end
    end
  end

  socket:send("AUTHINFO GENERIC NTLM\r\n")
  local status, response = socket:receive()
  -- If server supports NTLM authentication then continue
  if string.match(response, "381 .*") then
    socket:send("AUTHINFO GENERIC " .. ntlm_auth_blob .."\r\n")
    status, response = socket:receive()
    if not response then
      return
    end
  end

  socket:close()

  -- Continue only if a 381 response is returned
  local response_decoded = string.match(response, "381 (.*)")
  if not response_decoded then
    return nil
  end

  local response_decoded = base64.dec(response_decoded)

  -- Continue only if NTLMSSP response is returned
  if not string.match(response_decoded, "^NTLMSSP") then
    return nil
  end

  -- Leverage smbauth.get_host_info_from_security_blob() for decoding
  local ntlm_decoded = smbauth.get_host_info_from_security_blob(response_decoded)

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
