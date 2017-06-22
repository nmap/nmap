local stdnse = require "stdnse"
local shortport = require "shortport"
local comm = require "comm"
local string = require "string"

description = [[
OpenWebNet is a communications protocol developed by Bticino since 2000.
Retrieves the Gateway and device type. Retrieves the count and addresses
of lights, multimedia and many other services running on server/servers.
]]

---
-- @usage
-- nmap --script openwebnet-discovery
--
-- @output
-- | openwebnet-discovery:
-- |   Gateway: *#*1##*#13**15*12##*#1##
-- |   Heating: 1
-- |   Power Management: 1
-- |   Multimedia: 1
-- |   Device: F453AV
-- |   Automation: 3
-- |   Door Entry System: 2
-- |   Burglar Alarm: 1
-- |_  Lighting: 114
--

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
  [15] = "=15 - CEN",
  [16] = "Sound System",
  [17] = "Scenario Programming",
  [18] = "Energy Management",
  [24] = "Lighting Management",
  [25] = "=25 - CEN plus",
  [1000] = "Diagnostic",
  [1001] = "Automation Diagnostic",
  [1004] = "Heating Diagnostic",
  [1008] = "Door Entry System Diagnostic",
  [1013] = "Device Diagnostic"
}

-- Initiates a socket connection and returns the received data.
local function get_socket(host, port, request)

  local sd, response, early_resp = comm.opencon(host, port, request)

  if sd == nil then
    return nil, nil, "Socket connection error."
  end

  if not response then
    return nil, nil, "Poor internet connection or no response."
  end

  if response == "*#*0##" then
    return nil, nil, "Received a negative ACK as response."
  end

  -- Request for fetching Gateway address
  sd:send(request)

  local status, data = sd:receive_buf("*#*1##", false)

  if not status then
    return nil, nil, data
  end
  -- Ignore if the response is EOF which is of length 3
  -- Gateway length will be greater than 3
  if #data > 3 then
    -- Appending the delimiters to the data received for showing output
    data = "*#*1##" .. data .. "1##"
    return sd, data, nil
  end
end

-- Removes *#*1## from the beginning and ending
local function trim_begin_and_end(gateway)
  local trim_begin = string.sub(gateway, 7)
  local trim_end = string.sub(trim_begin, 1, -6)
  return trim_end
end

-- Returns table after appending the delimiter
-- The return table contains the list of devices
local function custom_split(delimiter, resultant)
  -- Trim at the end point to check for multiple entries
  local fields = stdnse.strsplit(delimiter, resultant)

  local results = {}
  for _,v in pairs(fields) do
    if #v > 0 then
      table.insert(results, v .. delimiter)
    end
  end

  return results
end

action = function(host, port)

  local output = stdnse.output_table()

  local sd, gateway, err = get_socket(host, port, "*#13**15##")

  -- Socket connection creation failed
  if sd == nil then
    return err
  end

  output["Gateway"] = gateway

  local resultant = trim_begin_and_end(gateway)
  local results = custom_split("##", resultant)

  for _, v in pairs(results) do
    -- Retrieving the device ID from Gateway
    -- Its WHO value is equal to 13
    local device_id = string.match(v,"(%d+)##$")
    if device_id == nil then
      -- Do nothing, ignore the failed case
    elseif tonumber(device_id) > 0 then
      output["Device"] = device[tonumber(device_id)]
    end
  end

  -- Fetching list of each device
  for _, v in pairs(who) do

    stdnse.debug("Fetching the list of " .. v .. " devices.")

    local sd, data, err = get_socket(host, port, "*##*#" .. _ .. "*0##")

    if sd then
      resultant = trim_begin_and_end(data)
      results = custom_split("##", resultant)

      -- Count of number of available services
      if #results > 0 then
        output[v] = #results
      end

    end
  end

  return output
end
