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
-- Version: 0.1, Updated on 21/06/2017

author = "Rewanth Cool"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(20000, "openwebnet")

local device = {}
device[2] =	"MHServer"
device[4] =	 "MH200"
device[6] =	 "F452"
device[7] =	 "F452V"
device[11] =  "MHServer2"
device[12] =	"F453AV"
device[13] =	"H4684"
device[15] =	"F427 (Gateway Open-KNX)"
device[16] =	"F453"
device[23] =	"H4684"
device[27] =	"L4686SDK"
device[44] =	"MH200N"
device[51] =	"F454"
device[200] =	"F454 (new?)"

local who = {}
who[0] = "Scenarios"
who[1] =	"Lighting"
who[2] =	"Automation"
who[3] =	"Power Management"
who[4] =	"Heating"
who[5] =	"Burglar Alarm"
who[6] =	"Door Entry System"
who[7] =	"Multimedia"
who[9] =	"Auxiliary"
who[13] =	"Device Communication"
who[14] =	"Light+shutters actuators lock"
who[15] =	"WHO=15 - CEN"
who[16] =	"Sound System"
who[17] =	"Scenario Programming"
who[18] =	"Energy Management"
who[24] =	"Lighting Management"
who[25] =	"WHO=25 - CEN plus"
who[1000] =	"Diagnostic"
who[1001] =	"Automation Diagnostic"
who[1004] =	"Heating Diagnostic"
who[1008] =	"Door Entry System Diagnostic"
who[1013] =	"Device Diagnostic"

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

  stdnse.sleep(2)

  -- Request for fetching Gateway address
  sd:send(request)

  local status, data = sd:receive_buf("*#*1##", false)
  if data == "EOF" then
    return nil, nil, "Received EOF with no response."
  end

  if data == "TIMEOUT" then
    return nil, nil, "Timeout occurred."
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

  local output = {}

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
    -- Check if timeout happended
    -- Add it to the corresponding key
    if err == "Timeout occurred." then
      output[v] = err

    -- Socket connection creation failed
    -- Ignore this case and continue the loop interation
    -- to fetch results of other services
    elseif sd == nil then
      -- Do nothing
      -- return err

    -- If there is no error, perform operations
    else
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
