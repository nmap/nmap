local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local nmap = require "nmap"
local url = require "url"
local U = require "lpeg-utility"


description = [[
Check for HTTP services that redirect to the HTTPS on the same port.
]]

author = {"Daniel Miller"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version"}

portrule = function (host, port)
  if (port.version and port.version.service_tunnel == "ssl") then
    -- If we already know it's SSL, bail.
    return false
  end
  -- Otherwise, match HTTP services
  -- always respecting version_intensity
  return (shortport.http(host, port) and nmap.version_intensity() >= 7)
end

action = function (host, port)
  local responses = {}
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    -- Probes sent, replies received, but no match.
    -- Loop through the probes most likely to receive HTTP responses
    for _, p in ipairs({"GetRequest", "HTTPOptions", "FourOhFourRequest", "NULL"}) do
      responses[#responses+1] = U.get_response(port.version.service_fp, p)
    end
  end
  if #responses == 0 then
    -- Have to send the probe ourselves.
    local socket, result, proto = comm.tryssl(host, port, "GET / HTTP/1.0\r\n\r\n")

    if (not socket) then
      return nil
    end
    socket:close()
    if proto == "ssl" then
      -- Unlikely, but we could have negotiated SSL already.
      port.version.service_tunnel = "ssl"
      nmap.set_port_version(host, port, "softmatched")
      return nil
    end
    responses[1] = result
  end

  for _, result in ipairs(responses) do
    -- Match HTTP redirects, status 3XX
    if string.match(result, "^HTTP/1.[01] 3%d%d") then

      local location = string.match(result, "\n[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[ \t]*(.-)\r?\n")
      if location then
        local parsed = url.parse(location)
        -- Check for a redirect to the same port, but with HTTPS scheme.
        if parsed.scheme == 'https' and tonumber(parsed.port or 443) == port.number and (
            -- ensure it's not some other machine
            parsed.ascii_host == host.ip or
            parsed.ascii_host == host.targetname or
            parsed.ascii_host == host.name or
            parsed.host == "" or parsed.host == nil
            ) then
          port.version.service_tunnel = "ssl"
          nmap.set_port_version(host, port, "softmatched")
          return nil
        end
      end
    end
  end
end
