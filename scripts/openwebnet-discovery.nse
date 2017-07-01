local stdnse = require "stdnse"
local shortport = require "shortport"
local comm = require "comm"
local string = require "string"

description = [[
OpenWebNet is a communications protocol developed by Bticino since 2000.
Retrieves device identifying information and number of connected devices.

References:
  https://www.myopen-legrandgroup.com/solution-gallery/openwebnet/
  http://www.pimyhome.org/wiki/index.php/OWN_OpenWebNet_Language_Reference
]]

---
-- @usage
-- nmap --script openwebnet-discovery
--
-- @output
--  | openwebnet-discover:
--  |   MAC address: 0-3-80-1-211-17
--  |   Kernel Version: 2.3.8
--  |   Net mask: 255.255.255.0
--  |   IP address: 192.168.200.35
--  |   Time: 19:58:33:001
--  |   Date: 24.06.2017
--  |   Device Type: F453AV
--  |   Distribution Version: 3.0.1
--  |   Firmware version: 3.0.14
--  |   Uptime: 5.3.28.38
--  |   Scenarios: 0
--  |   Lighting: 115
--  |   Automation: 13
--  |   Heating: 0
--  |   Burglar Alarm: 12
--  |_  Door Entry System: 0

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(20000, "openwebnet")

local device = {
  [2] = "MHServer",
  [4] = "MH200",
  [6] = "F452",
  [7] = "F452V",
  [11] = "MHServer2",
  [12] = "F453AV",
  [13] = "H4684",
  [15] = "F427 (Gateway Open-KNX)",
  [16] = "F453",
  [23] = "H4684",
  [27] = "L4686SDK",
  [44] = "MH200N",
  [51] = "F454",
  [200] = "F454 (new?)"
}

local who = {
  [0] = "Scenarios",
  [1] = "Lighting",
  [2] = "Automation",
  [3] = "Power Management",
  [4] = "Heating",
  [5] = "Burglar Alarm",
  [6] = "Door Entry System",
  [7] = "Multimedia",
  [9] = "Auxiliary",
  [13] = "Device Communication",
  [14] = "Light+shutters actuators lock",
  [15] = "CEN",
  [16] = "Sound System",
  [17] = "Scenario Programming",
  [18] = "Energy Management",
  [24] = "Lighting Management",
  [25] = "CEN plus",
  [1000] = "Diagnostic",
  [1001] = "Automation Diagnostic",
  [1004] = "Heating Diagnostic",
  [1008] = "Door Entry System Diagnostic",
  [1013] = "Device Diagnostic"
}

local device_dimensions = {
  ["Time"] = "*#13**0##",
  ["Date"] = "*#13**1##",
  ["IP address"]	= "*#13**10##",
  ["Net mask"] = "*#13**11##",
  ["MAC address"]	= "*#13**12##",
  ["Device Type"]	= "*#13**15##",
  ["Firmware version"] = "*#13**16##",
  ["Uptime"] = "*#13**19##",
  ["Kernel Version"] = "*#13**23##",
  ["Distribution Version"] = "*#13**24##"
}

local ACK = "*#*1##"
local NACK = "*#*0##"

-- Initiates a socket connection
-- Returns the socket and error message
local function get_socket(host, port, request)

  local sd, response, early_resp = comm.opencon(host, port, request)

  if sd == nil then
    return nil, "Socket connection error."
  end

  if not response then
    return nil, "Poor internet connection or no response."
  end

  if response == NACK then
    return nil, "Received a negative ACK as response."
  end

  return sd, nil
end

local function get_response(sd, request)

  local res = {}
  local status, data

  sd:send(request)

  repeat
    status, data = sd:receive_buf("##", true)
    if status and data ~= ACK then
      table.insert(res, data)
    end
    if data == ACK then
      break
    end

    -- If response is NACK, it means the request method is not supported
    if data == NACK then
      res = {}
    end
  until not status

  return res
end

local function format_dimensions(res)

  if res["Time"] then
    res["Time"] = string.gsub(res["Time"], "%.", ":")
  end

  if res["Date"] then
    res["Date"] = string.match(res["Date"],"%.(%d.+)$")
  end

  if res["Device Type"] then
    res["Device Type"] = device[ tonumber( res["Device Type"] ) ]
  end

  if res["MAC address"] then
    res["MAC address"] = string.gsub(res["MAC address"], "%.", "-")
  end

  return res

end

action = function(host, port)

  local output = stdnse.output_table()

  local sd, err = get_socket(host, port, ACK)

  -- Socket connection creation failed
  if sd == nil then
    return err
  end

  -- Fetching list of dimensions of a device
  for _, v in pairs(device_dimensions) do

    stdnse.debug("Fetching " .. _)

    local res = get_response(sd, v)

    -- Extracts substring from the result
    -- Ex:
    --  Request - *#13**16##
    --  Response - *#13**16*3*0*14##
    --  Trimmed Output - 3*0*14##

    output[_] = string.gsub(
                  string.sub(
                    string.gsub(
                      res[1], string.gsub(
                        string.sub(v,1,-3) .. "*","*","%%*"
                      ), ""), 1, -3
                  ), "*", ".")

  end

  -- Format the output based on dimension
  output = format_dimensions(output)

  -- Fetching list of each device
  for _ = 0, 6 do

    stdnse.debug("Fetching the list of " .. who[_] .. " devices.")

    local res = get_response(sd, "*##*#" .. _ .. "*0##")
    output[who[_]] = #res

  end

  return output
end
