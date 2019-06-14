local datetime = require "datetime"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local smbauth = require "smbauth"
local string = require "string"
local rdp = require "rdp"

description = [[
This script enumerates information from remote RDP services with CredSSP
(NLA) authentication enabled.

Sending an incomplete CredSSP (NTLM) authentication request with null credentials
will cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]

---
-- @usage
-- nmap -p 3389 --script rdp-ntlm-info <target>
--
-- @output
-- 3389/tcp open     ms-wbt-server syn-ack ttl 128 Microsoft Terminal Services
-- | rdp-ntlm-info:
-- |   Target_Name: W2016
-- |   NetBIOS_Domain_Name: W2016
-- |   NetBIOS_Computer_Name: W16GA-SRV01
-- |   DNS_Domain_Name: W2016.lab
-- |   DNS_Computer_Name: W16GA-SRV01.W2016.lab
-- |   DNS_Tree_Name: W2016.lab
-- |   Product_Version: 10.0.14393
-- |_  System_Time: 2019-06-13T10:38:35+00:00
--
--@xmloutput
-- <elem key="Target_Name">W2016</elem>
-- <elem key="NetBIOS_Domain_Name">W2016</elem>
-- <elem key="NetBIOS_Computer_Name">W16GA-SRV01</elem>
-- <elem key="DNS_Domain_Name">W2016.lab</elem>
-- <elem key="DNS_Computer_Name">W16GA-SRV01.W2016.lab</elem>
-- <elem key="DNS_Tree_Name">W2016.lab</elem>
-- <elem key="Product_Version">10.0.14393</elem>
-- <elem key="System_Time">2019-06-13T10:38:35+00:00</elem>



author = "Tom Sellers"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

action = function(host, port)

  local comm = rdp.Comm:new(host, port)
  if ( not(comm:connect()) ) then
    return nil
  end

  local requested_protocol = rdp.PROTOCOL_SSL | rdp.PROTOCOL_HYBRID | rdp.PROTOCOL_HYBRID_EX
  local cr = rdp.Request.ConnectionRequest:new(requested_protocol)
  local status, _ = comm:exch(cr)
  if ( not(status) ) then
    comm:close()
    return
  end

  -- This script could include code to detect which security protocols the
  -- target claims that it accepts however that's less than useful because
  -- 1. Windows XP doesn't provide that layer of the packet
  -- 2. Even when configured for RDP Security only, Windows Server 2008
  --    will still let you connect over TLS and start the CredSSP nego.

  local _, response, recvtime
  status, _ = comm.socket:reconnect_ssl()
  if status then
    stdnse.debug1("Sending NTLM NEGOTIATE..")

    -- NTLMSSP Negotiate request mimicking a Windows 10 client
    local NTLM_NEGOTIATE_BLOB = stdnse.fromhex(
      "30 37 A0 03 02 01 60 A1 30 30 2E 30 2C A0 2A 04 28" ..
      "4e 54 4c 4d 53 53 50 00" .. -- Identifier - NTLMSSP
      "01 00 00 00" ..  -- Type: NTLMSSP Negotiate - 01
      "B7 82 08 E2 " .. -- Flags (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
      "00 00 " ..       -- DomainNameLen
      "00 00" ..        -- DomainNameMaxLen
      "00 00 00 00" ..  -- DomainNameBufferOffset
      "00 00 " ..       -- WorkstationLen
      "00 00" ..        -- WorkstationMaxLen
      "00 00 00 00" ..  -- WorkstationBufferOffset
      "0A" ..           -- ProductMajorVersion = 10
      "00 " ..          -- ProductMinorVersion = 0
      "63 45 " ..       -- ProductBuild = 0x4563 = 17763
      "00 00 00" ..     -- Reserved
      "0F"              -- NTLMRevision = 5 = NTLMSSP_REVISION_W2K3
    )

    -- Not using comm:exch here since that performs some processing on the
    -- packet that isn't appropriate in this case.
    status, response = comm:send(NTLM_NEGOTIATE_BLOB)
    if ( not(status) ) then
      return false, response
    end

    status, response = comm:recv()
    if status then
      recvtime = os.time()
    end
  else
    comm:close()
    stdnse.debug1("Unable to establish a TLS connection which is required to negotiation CredSSP.")
    return
  end

  if response == nil then
    return
  end

  -- Continue only if NTLMSSP response is returned
  local start = response:find("NTLMSSP")
  if not start then
    return nil
  end
  response = response:sub(start)

  local ntlm_decoded = smbauth.get_host_info_from_security_blob(response)

  local output = stdnse.output_table()

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
    local product_ver = string.format("%d.%d.%d",
    ntlm_decoded.os_major_version, ntlm_decoded.os_minor_version, ntlm_decoded.os_build)
    output.Product_Version = product_ver
  end

  if ntlm_decoded.timestamp and ntlm_decoded.timestamp > 0 then
    -- 64-bit number of 100ns clicks since 1/1/1601
    local unixstamp = ntlm_decoded.timestamp // 10000000 - 11644473600
    datetime.record_skew(host, unixstamp, recvtime)
    local sys_time =  datetime.format_timestamp( unixstamp, 0)
    output.System_Time = sys_time
  end

  return output
end
