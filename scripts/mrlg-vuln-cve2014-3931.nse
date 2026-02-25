description = [[
Detects Multi-Router Looking Glass (MRLG) instances vulnerable to CVE-2014-3931.
Supports detection of legacy and suffix-labeled versions (e.g., 5.4.1+ad1, 5.0.0-beta).
Disclaimer use at your own risk and always verify result.
]]

author = "https://www.linkedin.com/in/abraham-surf"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery"}

local shortport = require "shortport"
local http = require "http"

portrule = shortport.http

action = function(host, port)
  local path = "/cgi-bin/mrlg.cgi"
  local response = http.get(host, port, path)

  if not response or not response.body then
    return "MRLG not detected: no response or empty body"
  end

  if response.status ~= 200 and response.status ~= 301 and response.status ~= 302 then
    return "MRLG not detected: unexpected HTTP status " .. response.status
  end

  local body = response.body:lower()

  -- Flexible version pattern matcher
  local match = body:match("multi%-router looking glass version%s*(%d+%.%d+%.%d+)")
              or body:match("multi%-router looking glass version%s*(%d+%.%d+)")

  if match then
    local detected = match
    local numeric = tonumber(detected:match("^%d+%.%d+")) or 0

    if body:match(detected .. "%+") or body:match(detected .. "[%-_%w]*") then
      -- Handles cases like "5.4.1+ad1", "5.1.0-rc", etc.
      detected = detected .. "+ (suffix)"
    end

    if detected:match("^5%.5%.0") then
      return "Not vulnerable: version " .. detected .. " detected"
    else
      return "Vulnerable to CVE-2014-3931\nDetected version: " .. detected
    end
  end

  if body:match("looking glass") then
    return "MRLG detected: version string not found or nonstandard format"
  end

  return "MRLG not detected: no matching indicators"
end