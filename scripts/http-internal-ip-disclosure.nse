local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ipOps = require "ipOps"

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
-- @args http-internal-ip-disclosure.path Path to URI. Default: /
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

local function generateHttpV1_0Req(host, port, path)
  local redirectIP, privateIP
  local socket = nmap.new_socket()
  socket:connect(host, port)

  local cmd = "GET " .. path .. " HTTP/1.0\r\n\r\n"
  socket:send(cmd)

  while true do
    local status, lines = socket:receive_lines(1)
    if not status then
      break
    end

    -- Check if the response contains a location header
    if lines:match("Location") then
      local locTarget = lines:match("Location: [%a%p%d]+")
      -- Check if the redirect location contains an IP address
      redirectIP = locTarget:match("[%d%.]+")
      if redirectIP then
        privateIP = ipOps.isPrivate(redirectIP)
      end

      stdnse.debug1("Location: %s", locTarget )
      stdnse.debug1("Internal IP: %s", redirectIP )
    end
  end

  socket:close()

  -- Only report if the internal IP leaked is different then the target IP
  if privateIP and redirectIP ~= host.ip then
    return redirectIP
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local IP = generateHttpV1_0Req(host, port, path)

  -- Check /images which is often vulnerable on some unpatched IIS servers
  if not IP and path ~= "/images" then
    path = "/images"
    IP = generateHttpV1_0Req(host, port, path)
  end

  if IP then
    output["Internal IP Leaked"] = IP
    return output
  end
end
