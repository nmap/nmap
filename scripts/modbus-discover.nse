local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates SCADA Modbus slave ids (sids) and collects their device information.

Modbus is one of the popular SCADA protocols. This script does Modbus device
information disclosure. It tries to find legal sids (slave ids) of Modbus
devices and to get additional information about the vendor and firmware. This
script is improvement of modscan python utility written by Mark Bristow.

Information about MODBUS protocol and security issues:
* MODBUS application protocol specification:  http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b.pdf
* Defcon 16 Modscan presentation: https://www.defcon.org/images/defcon-16/dc16-presentations/defcon-16-bristow.pdf
* Modscan utility is hosted at google code: http://code.google.com/p/modscan/
]]

---
-- @usage
-- nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 <host>
--
-- @args aggressive - boolean value defines find all or just first sid
--
-- @output
-- PORT    STATE SERVICE
-- 502/tcp open  modbus
-- | modbus-discover:
-- |   sid 0x64:
-- |     Slave ID data: \xFA\xFFPM710PowerMeter
-- |     Device identification: Schneider Electric PM710 v03.110
-- |   sid 0x96:
-- |_    error: GATEWAY TARGET DEVICE FAILED TO RESPONSE
--
-- @xmloutput
-- <table key="sid 0x64">
--   <elem key="Slave ID data">\xFA\xFFPM710PowerMeter</elem>
--   <elem key="Device identification">Schneider Electric PM710 v03.110</elem>
-- </table>
-- <table key="sid 0x96">
--   <elem key="error">GATEWAY TARGET DEVICE FAILED TO RESPONSE</elem>
-- </table>

-- Version 0.2 - /12.12.10/ - script cleanup
-- Version 0.3 - /13.12.10/ - several bugfixes

author = "Alexander Rudakov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


portrule = shortport.port_or_service(502, "modbus")

local form_rsid = function(sid, functionId, data)
  local payload_len = 2
  if  ( #data > 0 ) then
    payload_len = payload_len + #data
  end
  return "\0\0\0\0\0" .. string.pack('BBB', payload_len, sid, functionId) .. data
end

discover_device_id_recursive = function(host, port, sid, start_id, objects_table)
  local rsid = form_rsid(sid, 0x2B, "\x0E\x01" .. string.pack('B', start_id))
  local status, result = comm.exchange(host, port, rsid)
  if ( status and (#result >= 8)) then
    local ret_code = string.byte(result, 8)
    if ( ret_code == 0x2B and #result >= 15 ) then
      local more_follows = string.byte(result, 12)
      local next_object_id = string.byte(result, 13)
      local number_of_objects = string.byte(result, 14)
      stdnse.debug1("more = 0x%x, next_id = 0x%x, obj_number = 0x%x", more_follows, next_object_id, number_of_objects)
      local offset = 15
      for i = start_id, (number_of_objects - 1) do
        local object_id = string.byte(result, offset)
        local object_len = string.byte(result, offset + 1)
        -- error data format --
        if object_len == nil then break end
        local object_value = string.sub(result, offset + 2, offset + 1 + object_len)
        stdnse.debug1("Object id = 0x%x, value = %s", object_id, object_value)
        table.insert(objects_table, object_id + 1, object_value)
        offset = offset + 2 + object_len
      end
      if ( more_follows == 0xFF and next_object_id ~= 0x00 ) then
        stdnse.debug1("Has more objects")
        return discover_device_id_recursive(host, port, sid, next_object_id, objects_table)
      end
    end
  end
  return objects_table
end

local discover_device_id = function(host, port, sid)
  return discover_device_id_recursive(host, port, sid, 0x0, {})
end

local extract_slave_id = function(response)
  local byte_count = string.byte(response, 9)
  if ( byte_count == nil or byte_count == 0) then return nil end
  return string.unpack("c"..byte_count, response, 10)
end

modbus_exception_codes = {
  [1]  = "ILLEGAL FUNCTION",
  [2]  = "ILLEGAL DATA ADDRESS",
  [3]  = "ILLEGAL DATA VALUE",
  [4]  = "SLAVE DEVICE FAILURE",
  [5]  = "ACKNOWLEDGE",
  [6]  = "SLAVE DEVICE BUSY",
  [8]  = "MEMORY PARITY ERROR",
  [10] = "GATEWAY PATH UNAVAILABLE",
  [11] = "GATEWAY TARGET DEVICE FAILED TO RESPOND"
}

action = function(host, port)
  -- If false, stop after first sid.
  local aggressive = stdnse.get_script_args('modbus-discover.aggressive')

  local opts = {request_timeout=2000}
  local results = stdnse.output_table()

  for sid = 1, 246 do
    stdnse.debug3("Sending command with sid = %d", sid)
    local rsid = form_rsid(sid, 0x11, "")

    local status, result = comm.exchange(host, port, rsid, opts)
    if ( status and (#result >= 8) ) then
      local ret_code = string.byte(result, 8)
      if ( ret_code == (0x11) or ret_code == (0x11 + 128) ) then
        local sid_table = stdnse.output_table()
        if ret_code == (0x11) then
          local slave_id = extract_slave_id(result)
          sid_table["Slave ID data"] = slave_id or "<unknown>"
        elseif ret_code == (0x11 + 128) then
          local exception_code = string.byte(result, 9)
          local exception_string = modbus_exception_codes[exception_code]
          if ( exception_string == nil ) then
            exception_string = ("Unknown exception (0x%x)"):format(exception_code)
          end
          sid_table["error"] = exception_string
        end

        local device_table = discover_device_id(host, port, sid)
        if ( #device_table > 0 ) then
          sid_table["Device identification"] = table.concat(device_table, " ")
        end
        if ( #sid_table > 0 ) then
          results[("sid 0x%x"):format(sid)] = sid_table
        end
        if ( not aggressive ) then break end
      end
    end
  end

  if ( #results > 0 ) then
    port.state = "open"
    port.version.name = "modbus"
    nmap.set_port_version(host, port)
    return results
  end
end
