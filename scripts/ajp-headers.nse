local ajp = require "ajp"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs a HEAD or GET request against either the root directory or any
optional directory of an Apache JServ Protocol server and returns the server response headers.
]]

---
-- @usage
-- nmap -p 8009 <ip> --script ajp-headers
--
-- @output
-- PORT     STATE SERVICE
-- 8009/tcp open  ajp13
-- | ajp-headers:
-- |   X-Powered-By: JSP/2.2
-- |   Set-Cookie: JSESSIONID=goTHax+8ktEcZsBldANHBAuf.undefined; Path=/helloworld
-- |   Content-Type: text/html;charset=ISO-8859-1
-- |_  Content-Length: 149
--
-- @args ajp-headers.path The path to request, such as <code>/index.php</code>. Default <code>/</code>.


portrule = shortport.port_or_service(8009, 'ajp13', 'tcp')

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local arg_path   = stdnse.get_script_args(SCRIPT_NAME .. '.path') or "/"

action = function(host, port)
  local method
  local helper = ajp.Helper:new(host, port)
  helper:connect()

  local status, response = helper:get(arg_path)
  helper:close()

  if ( not(status) ) then
    return stdnse.format_output(false, "Failed to retrieve server headers")
  end
  return stdnse.format_output(true, response.rawheaders)
end
