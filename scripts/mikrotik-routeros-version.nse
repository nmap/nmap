description = [[
Detects MikroTik RouterOS version from devices running the Winbox service on port 8291.

This script attempts to send a specific payload to elicit a response containing the version information.

The provided payload can be used for all RouterOs versions until 6.49.17. Though version 7.1+ are not supported
]]

author = "deauther890"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- @usage
-- nmap --script -p 8291 mikrotik-routeros-version.nse <target>

-- @output

-- | mikrotik_version: ..index.............1430403512 640615 roteros.dll 5.26
-- | 1520199794 31008 advtool.dll 5.26
-- | 261985863 35262 dhcp.dll 5.26
-- | 3904059021 38356 hotspot.dll 5.26
-- | 4071503750 39436 ipv6.dll 5.26
-- | 1891635056 38558 mpls.dll 5.26
-- | 1284780005 29026 ntp.dll 5.26
-- | 3570177358 3..4543 pim.dll 5.26
-- | 3555507173 41773 ppp.dll 5.26
-- | 2623738336 31016 rb.dll 5.26
-- | 21858348 53708 roting4.dll 5.26
-- | 3194766853 44168 secure.dll 5.26
-- |_2890365236 4849 system.dll 5.26

-- To-Do:
-- Find the payload for version 7.1+

local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

portrule = shortport.portnumber(8291, "tcp")

Driver = {
  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.s = nmap.new_socket()
    self.s:set_timeout(self.options['timeout'] or 5000)
    return self.s:connect(self.host, self.port, "tcp")
  end,

  send_payload = function(self, payload)
    local try = nmap.new_try(function() return false end)
    try(self.s:send(payload))
    return try(self.s:receive_bytes(1024))
  end,

  disconnect = function(self)
    if self.s then
      self.s:close()
    end
  end,
}

action = function(host, port)
  local options = { timeout = 5000 }
  local driver = Driver:new(host, port, options)

  local success, result
  success, result = driver:connect()

  if not success then
    return "Connection failed"
  end

  local payload = "\x13\x02index\x00\x00\x00\x00\x00\x00\x00\xff\xed\x00\x00\x00\x00\x00"

  stdnse.debug1("Sending payload to " .. host.ip)
  success, result = pcall(driver.send_payload, driver, payload)

  driver:disconnect()

  if not success then
    return "Failed to send payload or receive response."
  end

  stdnse.debug1("Received response: " .. (result and stdnse.tohex(result) or "nil"))

  if result and #result > 0 then
    local decoded_result = string.gsub(result, "[^%g%s]", ".")
    return decoded_result
  else
    return "No response from the target."
  end
end
