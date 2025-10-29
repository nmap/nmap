local comm = require "comm"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tableaux = require "tableaux"
local url = require "url"

description =  [[
Determines if the web server leaks its internal IP address when sending an HTTP/1.0 request without a Host header.

Some misconfigured web servers leak their internal IP address in the response
headers when returning a redirect response. This is a known issue for some
versions of Microsoft IIS, but affects other web servers as well.
]]

---
-- @usage nmap --script http-internal-ip-disclosure <target>
-- @usage nmap --script http-internal-ip-disclosure --script-args http-internal-ip-disclosure.path=/path <target>
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

author = "Josh Amishav-Zlatin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "vuln", "discovery", "safe" }

portrule = shortport.http

local function add_unique (tbl, val)
  if not tableaux.contains(tbl, val) then
    table.insert(tbl, val)
  end
end

action = function(host, port)
  local patharg = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  if type(patharg) ~= "table" then
    patharg = {patharg}
  end
  local paths = {}
  for _, path in ipairs(patharg) do
    add_unique(paths, path)
  end
  add_unique(paths, "/images")

  local socket
  local bopt = nil
  for _, path in ipairs(paths) do
    local req = "GET " .. path .. " HTTP/1.0\r\n\r\n"
    local resp
    if not bopt then
      socket, resp, bopt = comm.tryssl(host, port, req)
      if not socket then return end
    else
      if not (socket:connect(host, port, bopt)
          and socket:send(req)) then
        socket:close()
        return
      end
      resp = ""
    end
    local findhead = function (s)
                       return s:find("\r?\n\r?\n")
                     end
    if not findhead(resp) then
      local status, head = socket:receive_buf(findhead, true)
      if not status then return end
      resp = resp .. head
    end
    socket:close()

    local loc = resp:lower():match("\nlocation:[ \t]+(%S+)")
    local lochost = url.parse(loc or "").host
    if not lochost or lochost == "" then return end
    -- remove any IPv6 enclosure
    lochost = lochost:gsub("^%[(.*)%]$", "%1")

    if ipOps.isPrivate(lochost) and ipOps.compare_ip(lochost, "ne", host.ip) then
      local output = stdnse.output_table()
      output["Internal IP Leaked"] = lochost
      return output
    end
  end
end
