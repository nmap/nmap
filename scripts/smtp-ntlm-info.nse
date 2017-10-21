local datetime = require "datetime"
local os = require "os"
local smtp = require "smtp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"


description = [[
This script enumerates information from remote SMTP services with NTLM
authentication enabled.

Sending a SMTP NTLM authentication request with null credentials will
cause the remote service to respond with a NTLMSSP message disclosing
information to include NetBIOS, DNS, and OS build version.
]]


---
-- @usage
-- nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com <target>
--
-- @output
-- 25/tcp   open     smtp
-- | smtp-ntlm-info:
-- |   Target_Name: ACTIVESMTP
-- |   NetBIOS_Domain_Name: ACTIVESMTP
-- |   NetBIOS_Computer_Name: SMTP-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: smtp-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">ACTIVESMTP</elem>
-- <elem key="NetBIOS_Domain_Name">ACTIVESMTP</elem>
-- <elem key="NetBIOS_Computer_Name">SMTP-TEST2</elem>
-- <elem key="DNS_Domain_Name">somedomain.com</elem>
-- <elem key="DNS_Computer_Name">smtp-test2.somedomain.com</elem>
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

portrule = shortport.port_or_service({ 25, 465, 587 }, { "smtp", "smtps", "submission" })

local function do_connect(host, port, domain)
  local options = {
    recv_before = true,
    ssl = true,
  }

  local socket, response = smtp.connect(host, port, options)
  if not socket then
    return
  end

  -- Required to send EHLO
  local status, response = smtp.ehlo(socket, domain)
  if not status then
    return
  end

  return socket
end

action = function(host, port)

  local output = stdnse.output_table()

  -- Select domain name.  Typically has no implication for this purpose.
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or smtp.get_domain(host)

  local socket = do_connect(host, port, domain)
  if not socket then
    return nil
  end

  -- Per RFC, do not attempt to upgrade to a TLS connection if already over TLS
  if not shortport.ssl(host, port) then
    -- After EHLO, attempt to upgrade to a TLS connection (may not be advertised)
    -- Various implementations *require* this before accepting authentication requests
    local status, response = smtp.starttls(socket)
    if status then
      -- Read line after upgrading the connection or timeout trying.
      -- This may induce a delay, however, appears required under rare conditions
      -- since reconnect_ssl does not support recv_before.
      -- -- commenting this out, not needed in testing, but may crop up sometime.
      --status, response = socket:receive_lines(1)
      -- Per RFC, must EHLO again after connection upgrade
      status, response = smtp.ehlo(socket, domain)
    else
      -- STARTTLS failed, which means smtp.lua sent QUIT and shut down the
      -- connection. Try again without SSL
      socket = do_connect(host, port, domain)
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
  local recvtime = os.time()

  socket:close()

  -- Continue only if a 334 response code is returned
  local response_decoded = string.match(response, "^334 (.*)")
  if not response_decoded then
    return
  end

  response_decoded = base64.dec(response_decoded)

  -- Continue only if NTLMSSP response is returned
  if not string.match(response_decoded, "^NTLMSSP") then
    return nil
  end

  local ntlm_decoded = smbauth.get_host_info_from_security_blob(response_decoded)

  if ntlm_decoded.timestamp and ntlm_decoded.timestamp > 0 then
    stdnse.debug1("timestamp is %s", ntlm_decoded.timestamp)
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
