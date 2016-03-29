local comm = require "comm"
local bin = require "bin"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote POP3 services with NTLM
authentication enabled.

Sending a POP3 NTLM authentication request with null credentials will
cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 110,995 --script pop3-ntlm-info <target>
--
-- @output
-- 110/tcp   open     pop3
-- | pop3-ntlm-info:
-- |   Target_Name: ACTIVEPOP3
-- |   NetBIOS_Domain_Name: ACTIVEPOP3
-- |   NetBIOS_Computer_Name: POP3-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: pop3-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">ACTIVEPOP3</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVEPOP3</elem>
-- <elem key="NetBIOS_Computer_Name">POP3-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">pop3-test2.somedomain.com</elem>
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

portrule = shortport.port_or_service({ 110, 995 }, { "pop3", "pop3s" })

action = function(host, port)

  local output = stdnse.output_table()

  -- Negotiate connection protocol
  local socket, line, bopt, first_line = comm.tryssl(host, port, "" , {recv_before=true})
  if not socket then
    return
  end

  -- Do not attempt to upgrade to a TLS connection if already over TLS
  if not shortport.ssl(host,port) then
    -- Attempt to upgrade to a TLS connection if supported (may not be advertised)
    -- Various implementations *require* this before accepting authentication requests
    socket:send("STLS\r\n")
    local status, response = socket:receive()
    if not status then
      return
    end
    -- Upgrade the connection if STARTTLS permitted, else continue without
    if string.match(response, ".*OK.*") then
      status, response = socket:reconnect_ssl()
      if not status then
        return
      end
    end
  end

  socket:send("AUTH NTLM\r\n")
  local status, response = socket:receive()
  if not response then
    return
  end

  socket:send(ntlm_auth_blob .. "\r\n")
  status, response = socket:receive()
  if not response then
    return
  end

  socket:close()

  -- Continue only if a + response is returned
  if not string.match(response, "+ .*") then
    return
  end

  local response_decoded = base64.dec(string.match(response, "+ (.*)"))

  -- Continue only if NTLMSSP response is returned
  if not string.match(response_decoded, "(NTLMSSP.*)") then
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
