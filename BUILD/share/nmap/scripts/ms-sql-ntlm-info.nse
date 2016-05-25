local bin = require "bin"
local mssql = require "mssql"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote Microsoft SQL services with NTLM
authentication enabled.

Sending a MS-TDS NTLM authentication request with an invalid domain and null
credentials will cause the remote service to respond with a NTLMSSP message
disclosing information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 1433 --script ms-sql-ntlm-info <target>
--
-- @output
-- 1433/tcp   open     ms-sql-s
-- | ms-sql-ntlm-info:
-- |   Target_Name: ACTIVESQL
-- |   NetBIOS_Domain_Name: ACTIVESQL
-- |   NetBIOS_Computer_Name: DB-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: db-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">ACTIVESQL</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVESQL</elem>
-- <elem key="NetBIOS_Computer_Name">DB-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">db-test2.somedomain.com</elem>
-- <elem key="DNS_Tree_Name">somedomain.com</elem>
-- <elem key="Product_Version">6.1.7601</elem>


author = "Justin Cacak"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service(1433, "ms-sql-s")

action = function(host, port)

  local output = stdnse.output_table()

  local tdsstream = mssql.TDSStream:new()
  local status, result = tdsstream:Connect(host, port)
  if not status then
    return nil
  end

  local lp = mssql.LoginPacket:new()
  lp:SetUsername("")
  lp:SetPassword("")
  lp:SetDatabase("")
  lp:SetServer(stdnse.get_hostname(host))
  -- Setting domain forces NTLM authentication
  lp:SetDomain(".")

  status, result = tdsstream:Send( lp:ToString() )
  if not status then
    tdsstream:Disconnect()
    return nil
  end

  local status, response, errorDetail = tdsstream:Receive()
  tdsstream:Disconnect()

  local pos, ttype = bin.unpack("C", response)
  if ttype ~= mssql.TokenType.NTLMSSP_CHALLENGE then
    return nil
  end

  local pos, data = bin.unpack("<P", response, pos)
  if not string.match(data, "^NTLMSSP") then
    return nil
  end

  -- Leverage smbauth.get_host_info_from_security_blob() for decoding
  local ntlm_decoded = smbauth.get_host_info_from_security_blob(data)

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
