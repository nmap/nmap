local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"
local table = require "table"

description = [[
Detects SAP Netweaver Portal instances that allow anonymous access to the
 KM unit navigation page. This page leaks file names, ldap users, etc.

SAP Netweaver Portal with the Knowledge Management Unit enable allows unauthenticated
users to list file system directories through the URL '/irj/go/km/navigation?Uri=/'.

This issue has been reported and won't be fixed.

References:
* https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm
]]

---
-- @usage nmap -p 80 --script http-sap-netweaver-leak <target>
-- @usage nmap -sV --script http-sap-netweaver-leak <target>
--
-- @output 
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | http-sap-netweaver-leak:
-- |   VULNERABLE:
-- |   Anonymous access to SAP Netweaver Portal
-- |     State: VULNERABLE (Exploitable)
-- |             SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information
-- |             including file system structure, LDAP users, emails and other information.
-- |
-- |     Disclosure date: 2018-02-1
-- |     Check results:
-- |       Visit /irj/go/km/navigation?Uri=/ to access this SAP instance.
-- |     Extra information:
-- |       &#x7e;system
-- |       discussiongroups
-- |       documents
-- |       Entry&#x20;Points
-- |       etc
-- |       Reporting
-- |     References:
-- |_      https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm
--
-- @xmloutput
-- <table key="NMAP-1">
-- <elem key="title">Anonymous access to SAP Netweaver Portal</elem>
-- <elem key="state">VULNERABLE (Exploitable)</elem>
-- <table key="description">
-- <el em>SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information&#xa;
-- including file system structure, LDAP users, emails and other information.&#xa;</elem>
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="day">1</elem>
-- <elem key="year">2018</elem>
-- <elem key="month">02</elem>
-- </table>
-- </table>
-- <elem key="disclosure">2018-02-1</elem>
-- <table key="check_results">
-- <elem>Visit /irj/go/km/navigation?Uri=/ to access this SAP instance.</elem>
-- </table>
-- <table key="extra_info">
-- <elem>&amp;#x7e;system</elem>
-- </table>
-- <table key="refs">
-- <elem>https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm</elem>
-- </table>
-- </table>
-- </script>
---

author = "Francisco Leon <@arphanetx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local evil_path = "/irj/go/km/navigation?Uri=/"

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = 'Anonymous access to SAP Netweaver Portal',
    state = vulns.STATE.NOT_VULN,
    description = [[
SAP Netweaver Portal with the Knowledge Management Unit allows attackers to obtain system information
including file system structure, LDAP users, emails and other information.
    ]],
    references = {
      'https://help.sap.com/saphelp_nw73ehp1/helpdata/en/4a/5c004250995a6ae10000000a42189b/frameset.htm',
    },
    dates = {
      disclosure = {year = '2018', month = '02', day = '1'},
    },
  }

  local status_404, result_404, _= http.identify_404(host,port)
  if (status_404 and result_404 == 200 ) then
    stdnse.debug1("Exiting due to ambiguous response from web server on %s%:s.All URIs return status 200", host.ip, port.number)
    return nil
  end

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local output_table = stdnse.output_table()
  local options = {header={}, no_cache=true, bypass_cache=true}

  --We need a valid User Agent for SAP Netweaver Portal servers
  options['header']['User-Agent'] = "Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1;"
                                  ..".NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0"

  local response = http.get(host, port, evil_path, options)
  if response and response.status == 200 then
    if string.find(response.body,'logon') then
      stdnse.debug1("String 'logon' was found in this page. Exiting.")
      return vuln_report:make_output(vuln)
    else
      local files = {}
      for file in string.gmatch(response.body, "[Cc][Ll][Aa][Ss][Ss][=][\"]urTxtStd[\"]>([^$<]*.)</[Ss][Pp][Aa][Nn]>") do
        table.insert(files, file)
      end
      if #files>0 then
        vuln.state = vulns.STATE.EXPLOIT
	vuln.extra_info = files
	vuln.check_results = string.format("Visit %s to obtain more information about the files.", evil_path)
      end
      return vuln_report:make_output(vuln)
    end
  else
    stdnse.debug1("SAP Netweaver Portal not found.")
    return vuln_report:make_output(vuln)
  end
  
end
