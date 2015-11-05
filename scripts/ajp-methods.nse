local ajp = require "ajp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Discovers which options are supported by the AJP (Apache JServ
Protocol) server by sending an OPTIONS request and lists potentially
risky methods.

In this script, "potentially risky" methods are anything except GET,
HEAD, POST, and OPTIONS. If the script reports potentially risky
methods, they may not all be security risks, but you should check to
make sure. This page lists the dangers of some common methods:

http://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
]]

---
-- @usage
-- nmap -p 8009 <ip> --script ajp-methods
--
-- @output
-- PORT     STATE SERVICE
-- 8009/tcp open  ajp13
-- | ajp-methods:
-- |   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
-- |   Potentially risky methods: PUT DELETE TRACE
-- |_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
--
-- @args ajp-methods.path the path to check or <code>/<code> if none was given
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe"}


portrule = shortport.port_or_service(8009, 'ajp13', 'tcp')

local arg_url = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
local UNINTERESTING_METHODS = { "GET", "HEAD", "POST", "OPTIONS" }

local function filter_out(t, filter)
  local result = {}
  for _, e in ipairs(t) do
    if ( not(stdnse.contains(filter, e)) ) then
      result[#result + 1] = e
    end
  end
  return result
end

action = function(host, port)

  local helper = ajp.Helper:new(host, port)
  if ( not(helper:connect()) ) then
    return stdnse.format_output(false, "Failed to connect to server")
  end

  local status, response = helper:options(arg_url)
  helper:close()
  if ( not(status) or response.status ~= 200 or
    not(response.headers) or not(response.headers['allow']) ) then
    return "Failed to get a valid response for the OPTION request"
  end

  local methods = stdnse.strsplit(",%s", response.headers['allow'])

  local output = {}
  table.insert(output, ("Supported methods: %s"):format(stdnse.strjoin(" ", methods)))

  local interesting = filter_out(methods, UNINTERESTING_METHODS)
  if ( #interesting > 0 ) then
    table.insert(output, "Potentially risky methods: " .. stdnse.strjoin(" ", interesting))
    table.insert(output, "See https://nmap.org/nsedoc/scripts/ajp-methods.html")
  end
  return stdnse.format_output(true, output)
end
