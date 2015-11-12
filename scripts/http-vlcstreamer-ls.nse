local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Connects to a VLC Streamer helper service and lists directory contents. The
VLC Streamer helper service is used by the iOS VLC Streamer application to
enable streaming of multimedia content from the remote server to the device.
]]

---
-- @usage
-- nmap -p 54340 --script http-vlcstreamer-ls <ip>
--
-- @output
-- PORT      STATE SERVICE
-- 54340/tcp open  unknown
-- | http-vlcstreamer-ls:
-- |   /Applications
-- |   /Developer
-- |   /Library
-- |   /Network
-- |   /Pictures
-- |   /System
-- |   /User Guides And Information
-- |   /Users
-- |   /Volumes
-- |   /bin
-- |   /bundles
-- |   /cores
-- |   /dev
-- |   /etc
-- |   /home
-- |   /mach_kernel
-- |   /net
-- |   /opt
-- |   /private
-- |   /sbin
-- |   /tmp
-- |   /usr
-- |_  /var
--
-- @args http-vlcstreamer-ls.dir directory to list (default: /)
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(54340, "vlcstreamer", "tcp")

local arg_dir = stdnse.get_script_args(SCRIPT_NAME .. ".dir") or "/"

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)

  local response = http.get(host, port, ("/secure?command=browse&dir=%s"):format(arg_dir))

  if ( response.status ~= 200 or not(response.body) or 0 == #response.body ) then
    if ( response.status == 401 ) then
      return fail("Server requires authentication")
    else
      return
    end
  end

  local status, parsed = json.parse(response.body)
  if ( not(status) ) then
    return fail("Failed to parse response")
  end

  if ( parsed.errorMessage ) then
    return fail(parsed.errorMessage)
  end

  local output = {}
  for _, entry in pairs(parsed.files or {}) do
    table.insert(output,entry.path)
  end
  table.sort(output, function(a,b) return a<b end)
  return stdnse.format_output(true, output)
end
