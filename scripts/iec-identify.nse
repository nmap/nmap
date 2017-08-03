local shortport = require "shortport"
local comm = require "comm"
local stdnse = require "stdnse"
local string = require "string"
local match = require "match"

description = [[
Attempts to identify IEC 60870-5-104 ICS protocol.

After probing with a TESTFR (test frame) message, a STARTDT (start data
transfer) message is sent and general interrogation is used to gather the list
of information object addresses stored.
]]

---
-- @output
-- | iec-identify:
-- |   ASDU address: 105
-- |_  Information objects: 30
--

author = {"Aleksandr Timorin", "Daniel Miller"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(2404, "iec-104", "tcp")

local function get_asdu(socket)
  local status, data = socket:receive_buf(match.numbytes(2), true)
  if not status then
    return nil, data
  end
  if data:byte(1) ~= 0x68 then
    return nil, "Not IEC-104"
  end
  local len = data:byte(2)
  status, data = socket:receive_buf(match.numbytes(len), true)
  if not status then
    return nil, data
  end
  local apcitype = data:byte(1)
  return apcitype, data
end

action = function(host, port)

  local output = stdnse.output_table()
  local socket, err = comm.opencon(host, port)
  if not socket then
    stdnse.debug1("Connect error: %s", err)
    return nil
  end

  -- send TESTFR ACT command
  -- Test frame, like "ping"
  local TESTFR = "\x68\x04\x43\0\0\0"
  local status, err = socket:send( TESTFR )
  if not status then
    stdnse.debug1("Failed to send: %s", err)
    return nil
  end

  -- receive TESTFR answer
  local apcitype, recv = get_asdu(socket)
  if not apcitype then
    stdnse.debug1("protocol error: %s", recv)
    return nil
  end
  if apcitype ~= 0x83 then
    stdnse.print_debug(1, "Not IEC-104. TESTFR response: %#x", apcitype)
    return nil
  end

  -- send STARTDT ACT command
  local STARTDT = "\x68\x04\x07\0\0\0"
  status, err = socket:send( STARTDT )
  if not status then
    stdnse.debug1("Failed to send: %s", err)
    return nil
  end

  -- receive STARTDT answer
  apcitype, recv = get_asdu(socket)
  if not apcitype then
    stdnse.debug1("protocol error: %s", recv)
    return nil
  end
  if apcitype ~= 0x0b then
    stdnse.debug1("STARTDT ACT did not receive STARTDT CON: %#x", apcitype)
    return nil
  end

  -- May also receive ME_EI_NA_1 (End of initialization), so check for that in the buffer after sending the next part

  -- send C_IC_NA_1 command
  -- type: 0x64, C_IC_NA_1,
  -- numix: 1
  -- TNCause: 6, Act
  -- Originator address; 0
  -- ASDU address: 0xffff
  -- Information object address: 0
  -- QOI: 0x14 (20), Station interrogation (global)
  local C_IC_NA_1_broadcast = "\x68\x0e\0\0\0\0\x64\x01\x06\0\xff\xff\0\0\0\x14"
  status, err = socket:send( C_IC_NA_1_broadcast )
  if not status then
    stdnse.debug1("Failed to send: %s", err)
    return nil
  end

  local asdu_address
  local ioas = 0
  -- Have to draw the line somewhere.
  local limit = 10
  while limit > 0 do
    limit = limit - 1
    apcitype, recv = get_asdu(socket)
    if not apcitype then
      stdnse.debug1("Error in C_IC_NA_1: %s", recv)
      break
    end
    if apcitype & 0x01 == 0 then -- Type I, numbered information transfer
      -- skip 2 bytes Tx, 2 bytes Rx
      local typeid = recv:byte(5)
      if typeid == 70 then
        -- ME_EI_NA_1, End of Initialization. Skip.
      else
        local numix = recv:byte(6) & 0x7f
        local cause = recv:byte(7) & 0x3f
        asdu_address = string.unpack("<I2", recv, 9)
        stdnse.debug2("Got asdu=%d, type %d, cause %d, numix %d.", asdu_address, typeid, cause, numix)
        if typeid == 100 then
          -- C_IC_NA_1
          if cause == 7 then
            -- ActCon. Skip.
          elseif cause == 10 then
            -- ActTerm. The end!
            break
          else
            -- TODO: do something!
          end
        else
          if cause >= 20 and cause <= 36 then
            -- Inrogen, response to general interrogation
            ioas = ioas + numix
          end
        end
      end
    end
  end

  socket:close()

  if asdu_address then
    output["ASDU address"] = asdu_address
    output["Information objects"] = ioas
  else
    output = "IEC-104 endpoint did not respond to C_IC_NA_1 request"
  end

  return output
end
