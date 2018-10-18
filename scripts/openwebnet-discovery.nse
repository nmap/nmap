local datetime = require "datetime"
local stdnse = require "stdnse"
local shortport = require "shortport"
local comm = require "comm"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
OpenWebNet is a communications protocol developed by Bticino since 2000.
Retrieves device identifying information and number of connected devices.

References:
* https://www.myopen-legrandgroup.com/solution-gallery/openwebnet/
* http://www.pimyhome.org/wiki/index.php/OWN_OpenWebNet_Language_Reference
]]

---
-- @usage
-- nmap --script openwebnet-discovery
--
-- @output
--  | openwebnet-discover:
--  |   IP Address: 192.168.200.35
--  |   Net Mask: 255.255.255.0
--  |   MAC Address: 00:03:50:01:d3:11
--  |   Device Type: F453AV
--  |   Firmware Version: 3.0.14
--  |   Uptime: 12d9h42m1s
--  |   Date and Time: 4-07-2017T19:17:27
--  |   Kernel Version: 2.3.8
--  |   Distribution Version: 3.0.1
--  |   Lighting: 115
--  |   Automation: 15
--  |_  Burglar Alarm: 12
--
-- @xmloutput
--  <elem key="IP Address">192.168.200.35</elem>
--  <elem key="Net Mask">255.255.255.0</elem>
--  <elem key="MAC Address">00:03:50:01:d3:11</elem>
--  <elem key="Device Type">F453AV</elem>
--  <elem key="Firmware Version">3.0.14</elem>
--  <elem key="Uptime">12d9h42m1s</elem>
--  <elem key="Date and Time">4-07-2017T19:17:27</elem>
--  <elem key="Kernel Version">2.3.8</elem>
--  <elem key="Distribution Version">3.0.1</elem>
--  <elem key="Lighting">115</elem>
--  <elem key="Automation">15</elem>
--  <elem key="Burglar Alarm">12</elem>

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

local device_dimension = {
  ["Time"] = "0",
  ["Date"] = "1",
  ["IP Address"] = "10",
  ["Net Mask"] = "11",
  ["MAC Address"] = "12",
  ["Device Type"] = "15",
  ["Firmware Version"] = "16",
  ["Hardware Version"] = "17",
  ["Uptime"] = "19",
  ["Micro Version"] = "20",
  ["Date and Time"] = "22",
  ["Kernel Version"] = "23",
  ["Distribution Version"] = "24",
  ["Gateway IP address"] = "50",
  ["DNS IP address 1"] = "51",
  ["DNS IP address 2"] = "52"
}

local ACK = "*#*1##"
local NACK = "*#*0##"

-- Initiates a socket connection
-- Returns the socket and error message
local function get_socket(host, port, request)

  local sd, response, early_resp = comm.opencon(host, port, request, {recv_before=true, request_timeout=10000})

  if sd == nil then
    stdnse.debug("Socket connection error.")
    return nil, response
  end

  if not response then
    stdnse.debug("Poor internet connection or no response.")
    return nil, response
  end

  if response == NACK then
    stdnse.debug("Received a negative ACK as response.")
    return nil, response
  end

  return sd, nil
end

local function get_response(sd, request)

  local res = {}
  local status, data

  sd:send(request)

  repeat
    status, data = sd:receive_buf("##", true)

    if status == nil then
      stdnse.debug("Error: " .. data)
      if data == "TIMEOUT" then
        -- Avoids false results by capturing NACK after TIMEOUT occurred.
        status, data = sd:receive_buf("##", true)
        break
      else
        -- Captures other kind of errors like EOF
        sd:close()
        return res
      end
    end

    if status and data ~= ACK then
      table.insert(res, data)
    end
    if data == ACK then
      break
    end

    -- If response is NACK, it means the request method is not supported
    if data == NACK then
      res = nil
      break
    end
  until not status

  return res
end

local function format_dimensions(res)

  if res["Date and Time"] then
    local params = {
      "hour", "min", "sec", "msec", "dayOfWeek", "day", "month", "year"
    }

    local values = {}
    for counter, val in ipairs(stringaux.strsplit("%.%s*", res["Date and Time"])) do
      values[ params[counter] ] = val
    end

    res["Date and Time"] = datetime.format_timestamp(values)
  end

  if res["Device Type"] then
    res["Device Type"] = device[ tonumber( res["Device Type"] ) ]
  end

  if res["MAC Address"] then
    res["MAC Address"] = string.gsub(res["MAC Address"], "(%d+)(%.?)", function(num, separator)
      if separator == "." then
        return string.format("%02x:", num)
      else
        return string.format("%02x", num)
      end
    end
    )
  end

  if res["Uptime"] then
    local t = {}
    local units = {
      "d", "h", "m", "s"
    }

    for counter, v in ipairs(stringaux.strsplit("%.%s*", res["Uptime"])) do
      table.insert(t, v .. units[counter])
    end

    res["Uptime"] = table.concat(t, "")
  end

  return res

end

action = function(host, port)

  local output = stdnse.output_table()

  local sd, err = get_socket(host, port, nil)

  -- Socket connection creation failed
  if sd == nil then
    return err
  end

  -- Fetching list of dimensions of a device
  for _, device in ipairs({"IP Address", "Net Mask", "MAC Address", "Device Type", "Firmware Version", "Uptime", "Date and Time", "Kernel Version", "Distribution Version"}) do

    local head = "*#13**"
    local tail = "##"

    stdnse.debug("Fetching " .. device)

    local res = get_response(sd, head .. device_dimension[device] .. tail)

    -- Extracts substring from the result
    -- Ex:
    --  Request - *#13**16##
    --  Response - *#13**16*3*0*14##
    --  Trimmed Output - 3*0*14

    if res and next(res) then
      local regex = string.gsub(head, "*", "%%*") .. device_dimension[device] .. "%*" .."(.+)" .. tail
      local tempRes = string.match(res[1], regex)

      if tempRes then
        output[device] = string.gsub(tempRes, "*", ".")
      end
    end

  end

  -- Format the output based on dimension
  output = format_dimensions(output)

  -- Fetching list of each device
  for i = 1, 6 do

    stdnse.debug("Fetching the list of " .. who[i] .. " devices.")

    local res = get_response(sd, "*#" .. i .. "*0##")
    if res and #res > 0 then
      output[who[i]] = #res
    end

  end

  if #output > 0 then
    return output
  else
    return nil
  end
end

