local comm = require "comm"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local target = require "target"
local url = require "url"

description =  [[
Determines if the web server leaks its internal IP address when sending
an HTTP/1.0 request without a Host header.

Some misconfigured web servers leak their internal IP address in the response
headers when returning a redirect response. This is a known issue for some
versions of Microsoft IIS, but affects other web servers as well.

If script argument <code>newtargets</code> is set, the script will
add the found IP address as a new target into the scan queue. (See
the documentation for NSE library <code>target</code> for details.)
]]

---
-- @usage nmap --script http-internal-ip-disclosure <target>
-- @usage nmap --script http-internal-ip-disclosure --script-args http-internal-ip-disclosure.path=/mypath <target>
--
-- @args http-internal-ip-disclosure.path Path (or a table of paths) to probe
--                                        Default: /
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-internal-ip-disclosure:
-- |_  Internal IP Leaked: 10.0.0.2
--
-- @xmloutput
-- <elem key="Internal IP Leaked">10.0.0.2</elem>
--
-- @see ssl-cert-intaddr.nse

author = {"Josh Amishav-Zlatin", "nnposter"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery", "safe" }

portrule = shortport.http

action = function(host, port)
  local patharg = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  if type(patharg) ~= "table" then
    patharg = {patharg}
  end
  local paths = stdnse.output_table()
  for _, path in ipairs(patharg) do
    paths[path] = 1
  end
  paths["/images"] = 1

  local socket
  local bopt = nil
  local try = nmap.new_try(function () socket:close() end)
  for path in pairs(paths) do
    local req = "GET " .. path .. " HTTP/1.0\r\n\r\n"
    local resp = nil
    if not bopt then
      socket, resp, bopt = comm.tryssl(host, port, req)
      if not socket then return end
    else
      try(socket:connect(host, port, bopt))
      try(socket:send(req))
    end
    resp = stdnse.make_buffer(socket, "\r?\n\r?\n", resp)()
    socket:close()
    if not resp then return end

    local loc = resp:lower():match("\nlocation:[ \t]+(%S+)")
    local lochost = url.parse(loc or "").host
    if lochost and lochost ~= "" then
      -- remove any IPv6 enclosure
      lochost = lochost:gsub("^%[(.*)%]$", "%1")

      if ipOps.isPrivate(lochost) and ipOps.compare_ip(lochost, "ne", host.ip) then
        if target.ALLOW_NEW_TARGETS then
          target.add(lochost)
        end
        local output = stdnse.output_table()
        output["Internal IP Leaked"] = lochost
        return output
      end
    end
  end
end
