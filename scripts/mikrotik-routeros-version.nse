description = [[
Detects MikroTik RouterOS version from devices running the Winbox service on port 8291.

This script attempts to send a specific payload to elicit a response containing the version information.

The provided payload can be used for all RouterOs versions until 6.49.17. Though version 7.1+ are not supported
]]

author = {"deauther890", "Daniel Miller"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "version", "discovery", "safe"}

---@usage
-- nmap -p 8291 --script mikrotik-routeros-version <target>

---@output
--| mikrotik-routeros-version:
--|   index:
--| advtool.dll  6.49.7
--| secure.dll   6.49.7
--| dhcp.dll     6.49.7
--| ppp.dll      6.49.7
--| roting4.dll  6.49.7
--| mpls.dll     6.49.7
--| hotspot.dll  6.49.7
--| wlan6.dll    6.49.7
--| roteros.dll  6.49.7
--| system.dll   6.49.7
--|
--|   list:
--| advtool.jg  6.49.7
--| secure.jg   6.49.7
--| dhcp.jg     6.49.7
--| ppp.jg      6.49.7
--| roting4.jg  6.49.7
--| mpls.jg     6.49.7
--| hotspot.jg  6.49.7
--| wlan6.jg    6.49.7
--|_roteros.jg  6.49.7

---@xmloutput
--<table key="index">
--  <table></table>
--  <table>
--    <elem>advtool.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>secure.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>dhcp.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>ppp.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>roting4.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>mpls.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>hotspot.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>wlan6.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>roteros.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>system.dll</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <elem key="current_row">12</elem>
--</table>
--<table key="list">
--  <table></table>
--  <table>
--    <elem>advtool.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>secure.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>dhcp.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>ppp.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>roting4.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>mpls.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>hotspot.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>wlan6.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <table>
--    <elem>roteros.jg</elem>
--    <elem>6.49.7</elem>
--  </table>
--  <elem key="current_row">11</elem>
--</table>

local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local match = require "match"
local tab = require "tab"
local table = require "table"

portrule = shortport.version_port_or_service(8291, "winbox", "tcp")

Driver = {
  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.s = nmap.new_socket()
    self.s:set_timeout(stdnse.get_timeout(self.host))
    return self.s:connect(self.host, self.port, "tcp")
  end,

  send_payload = function(self, payload)
    local try = nmap.new_try(function() return false end)
    try(self.s:send(payload))
    local head = try(self.s:receive_buf(match.numbytes(20), true))
    stdnse.debug1("header: %s", stdnse.tohex(head))
    -- response length is 2 bytes at position 15
    local len = string.unpack(">i2", head, 15)
    if len < 0 then
      -- clear out the receive buffer
      try(self.s:receive_buf(".*", true))
      return nil
    end
    local body = try(self.s:receive_buf(match.numbytes(len), true))
    -- Sometimes extra bytes are added indicating how many bytes remain
    local junk
    body, junk = body:gsub(".%\xff", "")
    if junk <= 0 then
      return body
    end
    -- Grab the remainder, since junk bytes took up some.
    return body .. try(self.s:receive_buf(match.numbytes(junk * 2), true))
  end,

  disconnect = function(self)
    if self.s then
      self.s:close()
    end
  end,
}

action = function(host, port)
  local driver = Driver:new(host, port)

  local success, result
  local output = stdnse.output_table()
  local version

  local attempts = {
    {
      name = "index",
      payload = "\x13\x02index\x00\x00\x00\x00\x00\x00\x00\xff\xed\x00\x00\x00\x00\x00",
      pattern = "(%w+%.dll) ([%d.]+)",
    },
    {
      name = "list",
      payload = "\x13\x02list\x00\x00\x00\x00\x00\x00\x00\x00\xff\xed\x00\x00\x00\x00\x00",
      pattern = 'name: "([^"]+)", unique: "[^"]+", version: "([^"]+)"',
    },
  }
  for _, att in ipairs(attempts) do
    success, result = driver:connect()

    if success then

      stdnse.debug1("Sending payload")
      success, result = pcall(driver.send_payload, driver, att.payload)
      driver:disconnect()

      if success and result then
        stdnse.debug1("Received response: %s", stdnse.tohex(result:sub(1,30)))
        local t = tab.new()
        local decoded = false
        tab.nextrow(t)
        string.gsub(result, att.pattern, function(dll, ver)
            decoded = true
            version = ver
            tab.addrow(t, dll, ver)
          end)
        if decoded then
          output[att.name] = t
        end
      end
    end
  end

  if not version then
    return nil
  end

  port.version.name = "winbox"
  port.version.name_confidence = 10
  port.version.product = "MikroTik WinBox"
  port.version.ostype = ("RouterOS %s"):format(version)
  table.insert(port.version.cpe, ("cpe:/o:mikrotik:routeros:%s"):format(version))
  table.insert(port.version.cpe, "cpe:/a:mikrotik:winbox")
  nmap.set_port_version(host, port)
  return output
end
