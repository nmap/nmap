local datetime = require "datetime"
local os = require "os"
local bin = require "bin"
local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote Microsoft Telnet services with NTLM
authentication enabled.

Sending a MS-TNAP NTLM authentication request with null credentials will cause the
remote service to respond with a NTLMSSP message disclosing information to include
NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 23 --script telnet-ntlm-info <target>
--
-- @output
-- 23/tcp   open     telnet
-- | telnet-ntlm-info:
-- |   Target_Name: ACTIVETELNET
-- |   NetBIOS_Domain_Name: ACTIVETELNET
-- |   NetBIOS_Computer_Name: HOST-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: host-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 5.1.2600
--
--@xmloutput
-- <elem key="Target_Name">ACTIVETELNET</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVETELNET</elem>
-- <elem key="NetBIOS_Computer_Name">HOST-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">host-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">5.1.2600</elem>


author = "Justin Cacak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


local _, ntlm_auth_blob = smbauth.get_security_blob(
  nil, nil, nil, nil, nil, nil, nil,
  0x00000001 + -- Negotiate Unicode
  0x00000002 + -- Negotiate OEM strings
  0x00000004 + -- Request Target
  0x00000200 + -- Negotiate NTLM
  0x00008000 + -- Negotiate Always Sign
  0x00080000 + -- Negotiate NTLM2 Key
  0x20000000 + -- Negotiate 128
  0x80000000 -- Negotiate 56
  )

--
-- Create MS-TNAP Login Packet (Option Command IS)
-- Ref: http://msdn.microsoft.com/en-us/library/cc247789.aspx
local tnap_login_packet = bin.pack("<CCCCCCCIIACC",
  0xff, -- IAC
  0xfa, -- Sub-option (250)
  0x25, -- Subcommand: auth option
  0x00, -- Auth Cmd: IS (0)
  0x0f, -- Auth Type: NTLM (15)
  0x00, -- Who: Mask client to server (0)
  0x00, -- Command: NTLM_NEGOTIATE (0)
  #ntlm_auth_blob, -- NTLM_DataSize (4 bytes, little-endian)
  0x00000002, -- NTLM_BufferType (4 bytes, little-endian)
  ntlm_auth_blob,
  0xff, 0xf0 -- Sub-option End
  )

portrule = shortport.port_or_service(23, "telnet")

action = function(host, port)

  local output = stdnse.output_table()

  local socket, response, early_resp = comm.opencon(host, port, tnap_login_packet, {recv_before=true})

  if not socket then
    return nil
  end

  local recvtime = os.time()
  socket:close()

  -- Continue only if NTLMSSP response is returned.
  -- Verify that the response is terminated with Sub-option End values as various
  -- non Microsoft telnet implementations support NTLM but do not return valid data.
  local data = string.match(response, "(NTLMSSP.*)\xff\xf0")
  if not data then
    return nil
  end

  -- Leverage smbauth.get_host_info_from_security_blob() for decoding
  local ntlm_decoded = smbauth.get_host_info_from_security_blob(data)

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
