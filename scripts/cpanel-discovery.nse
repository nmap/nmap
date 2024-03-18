local shortport =  require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
cPanel is web hosting control panel software. cPanel Default TCP port is 2082 (http) and 2083 (https). WHM Default TCP port is 2086 (http) and 2087 (https).
]]

---
-- @usage
-- nmap -p 2082,2083,2086,2087 --script cpanel-discovery <target>
--
-- @output
--PORT     STATE SERVICE
--2082/tcp open  infowave
--| cpanel-discovery: 
--|_    cPanel/WHM detected!
--2083/tcp open  radsec
--2086/tcp open  gnunet
--| cpanel-discovery: 
--|_    cPanel/WHM detected!
--2087/tcp open  eli

-- @args cpanel-discovery.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service({2082,2083,2086,2087}, {"infowave", "radsec", "gnunet", "eli"}, "tcp")

action = function(host, port)
  local cPanel_response = {}

  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local http_response = http.get(host, port, path)

  if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
    return
  end

  local cPanel_session = string.match(http_response.rawbody, "cpsession=")
  local WHM_session = string.match(http_response.rawbody, "whostmgrsession=")
  local cPanel_title = string.match(http_response.rawbody, "cPanel Login")
  local WHM_title = string.match(http_response.rawbody, "WHM Login")

  if cPanel_session or not WHM_session or not cPanel_title or not WHM_title then
    table.insert(cPanel_response, {"cPanel/WHM detected!"})
    return stdnse.format_output(true, cPanel_response)
  end
end
