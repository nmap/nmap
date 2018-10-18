local ajp = require "ajp"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Requests a URI over the Apache JServ Protocol and displays the result
(or stores it in a file). Different AJP methods such as; GET, HEAD,
TRACE, PUT or DELETE may be used.

The Apache JServ Protocol is commonly used by web servers to communicate with
back-end Java application server containers.
]]

---
-- @usage
-- nmap -p 8009 <ip> --script ajp-request
--
-- @output
-- PORT     STATE SERVICE
-- 8009/tcp open  ajp13
-- | ajp-request:
-- | <!DOCTYPE HTML>
-- | <html>
-- | <head>
-- | <title>JSP Test</title>
-- |
-- | </head>
-- | <body>
-- | <h2>Hello, World.</h2>
-- | Fri May 04 02:09:40 UTC 2012
-- | </body>
-- |_</html>
--
-- @args method AJP method to be used when requesting the URI (default: GET)
-- @args path the path part of the URI to request
-- @args filename the name of the file where the results should be stored
-- @args username the username to use to access protected resources
-- @args password the password to use to access protected resources
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(8009, 'ajp13', 'tcp')

local arg_method   = stdnse.get_script_args(SCRIPT_NAME .. ".method") or "GET"
local arg_path     = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
local arg_file     = stdnse.get_script_args(SCRIPT_NAME .. ".filename")
local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local helper = ajp.Helper:new(host, port)
  if ( not(helper:connect()) ) then
    return fail("Failed to connect to AJP server")
  end

  local valid_methods = {
    ["GET"]    = true,
    ["HEAD"]   = true,
    ["TRACE"]  = true,
    ["PUT"]    = true,
    ["DELETE"] = true,
    ["OPTIONS"]= true,
  }

  local method = arg_method:upper()
  if ( not(valid_methods[method]) ) then
    return fail(("Method not supported: %s"):format(arg_method))
  end

  local options = { auth = { username = arg_username, password = arg_password } }
  local status, response = helper:request(arg_method, arg_path, nil, nil, options)
  if ( not(status) ) then
    return fail("Failed to retrieve response for request")
  end
  helper:close()

  if ( response ) then
    local output = response.status_line .. "\n" ..
      table.concat(response.rawheaders, "\n") ..
      (response.body and "\n\n" .. response.body or "")
    if ( arg_file ) then
      local f = io.open(arg_file, "w")
      if ( not(f) ) then
        return fail(("Failed to open file %s for writing"):format(arg_file))
      end
      f:write(output)
      f:close()
      return ("Response was written to file: %s"):format(arg_file)
    else
      return "\n" .. output
    end
  end
end

