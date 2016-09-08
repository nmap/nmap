local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description =  [[
Determines if a ASP.NET application has debugging enabled using a HTTP DEBUG request.

The HTTP DEBUG verb is used within ASP.NET applications to start/stop remote
debugging sessions. The script sends a 'stop-debug' command to determine the
application's current configuration state but access to RPC services is required
 to interact with the debugging session. The request does not change the
application debugging configuration.
]]

---
-- @usage nmap --script http-debug <target>
-- @usage nmap --script http-debug --script-args http-aspnet-debug.path=/path <target>
--
-- @args http-debug.path Path to URI. Default: /
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-aspnet-debug:
-- |_  status: DEBUG is enabled
--
-- @xmloutput
-- <elem key="status">DEBUG is enabled</elem>
---

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery" }

portrule = shortport.http

local function generate_http_debug_req(host, port, path)
  local status = false
  local options = {header={}}
  options["header"]["Command"] = "stop-debug"
  options["redirect_ok"] = 2

  -- send DEBUG request with stop-debug command
  local req = http.generic_request(host, port, "DEBUG", path, options)

  stdnse.debug1("Response body: %s", req.body )
  if req.body:match("OK") then
    status = true
  end
  return status
end

action = function(host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local status = generate_http_debug_req(host, port, path)
  if status then
    output.status = "DEBUG is enabled"
    return output
  end
end
