local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"
local table = require "table"

description=[[
Obtains information (such as vendor and device type where available) from a
TFTP service. Software vendor information is deduced based on error messages.
]]

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "version"}

portrule = shortport.version_port_or_service(69, "tftp", "udp")

local OPCODE_RRQ   = 1
local OPCODE_DATA  = 3
local OPCODE_ERROR = 5

local responses = {
  -- match tftp m|^\0\x05\0\x02\0The IP address is not in the range of allowable addresses\.\0| p/SolarWinds tftpd/ i/IP disallowed/ o/Windows/ cpe:/a:solarwinds:tftp_server/ cpe:/o:microsoft:windows/a
  {
    2,
    "The IP address is not in the range of allowable addresses.",
    {
      ["p"] = "SolarWinds tftpd",
      ["i"] = "IP disallowed",
      ["o"] = "Windows",
      ["cpe"] = {
	"a:solarwinds:tftp_server",
	"o:microsoft:windows/a"
      }
    }
  },
  -- match tftp m|^\0\x05\0\0Invalid TFTP Opcode| p/Cisco tftpd/ cpe:/a:cisco:tftp_server/
  {
    0,
    "Invalid TFTP Opcode",
    {
      ["p"] = "Cisco tftpd",
      ["cpe"] = {
	"a:cisco:tftp_server"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x04Illegal TFTP operation\0| p/Plan 9 tftpd/ o/Plan 9/ cpe:/o:belllabs:plan_9/a
  {
    4,
    "Illegal TFTP operation",
    {
      ["p"] = "Plan 9 tftpd",
      ["o"] = "Plan 9",
      ["cpe"] = {
	"o:belllabs:plan_9/a"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x04Error: Illegal TFTP Operation\0\0\0\0\0| p/Zoom X5 ADSL modem tftpd/ d/broadband router/ cpe:/h:zoom:x5/a
  {
    4,
    "Error: Illegal TFTP Operation",
    {
      ["p"] = "Zoom X5 ADSL modem tftpd",
      ["d"] = "broadband router",
      ["cpe"] = {
	"h:zoom:x5/a"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x04Illegal operation\0$| p/Cisco router tftpd/ d/router/ o/IOS/ cpe:/a:cisco:tftp_server/ cpe:/o:cisco:ios/a
  {
    4,
    "Illegal operation",
    {
      ["p"] = "Cisco router tftpd",
      ["d"] = "router",
      ["o"] = "IOS",
      ["cpe"] = {
	"a:cisco:tftp_server",
	"o:cisco:ios/a"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x04Illegal operation error\.\0$| p/Microsoft Windows Deployment Services tftpd/ o/Windows/ cpe:/o:microsoft:windows/
  {
    4,
    "Illegal operation error.",
    {
      ["p"] = "Microsoft Windows Deployment Services tftpd",
      ["o"] = "Windows",
      ["cpe"] = {
	"o:microsoft:windows"
      }
    }
  },
  -- # version 10.9.0.25
  -- match tftp m|^\0\x05\0\x04Unknown operatation code: 0 received from [\d.]+:\d+\0| p/SolarWinds Free tftpd/ cpe:/a:solarwinds:tftp_server/
  {
    4,
    "Unknown operatation code: 0 received from",
    {
      ["p"] = "SolarWinds Free tftpd",
      ["cpe"] = {
	"a:solarwinds:tftp_server"
      }
    }
  },
  {
    1,
    "Could not find file '",
    {
      ["p"] = "SolarWinds Free tftpd",
      ["cpe"] = {
	"a:solarwinds:tftp_server"
      }
    }
  },
  -- # Brother MFC-9340CDW
  -- match tftp m|^\0\x05\0\x04illegal \(unrecognized\) tftp operation\0$| p/Brother printer tftpd/ d/printer/
  {
    4,
    "illegal (unrecognized) tftp operation",
    {
      ["p"] = "Brother printer tftpd",
      ["d"] = "printer"
    }
  },
  -- # HP IMC 7.1
  -- match tftp m|^\0\x05\0\0Not defined, see error message\(if any\)\.\0| p/HP Intelligent Management Center tftpd/ cpe:/a:hp:intelligent_management_center/
  {
    0,
    "Not defined, see error message(if any).",
    {
      ["p"] = "HP Intelligent Management Center tftpd",
      ["cpe"] = {
	"a:hp:intelligent_management_center"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x04Illegal TFTP operation\0| p/Windows 2003 Server Deployment Service/ o/Windows/ cpe:/o:microsoft:windows_server_2003/a
  {
    4,
    "Illegal TFTP operation",
    {
      ["p"] = "Windows 2003 Server Deployment Service",
      ["o"] = "Windows",
      ["cpe"] = {
	"o:microsoft:windows_server_2003/a"
      }
    }
  },
  -- match tftp m|^\0\x05\0\x01File not found\.\0$| p/Enistic zone controller tftpd/
  {
    1,
    "File not found.",
    {
      ["p"] = "Enistic zone controller tftpd"
    }
  },
}

local record_match = function(port, sw)
  if sw.p then
    port.version.product = sw.p
  end

  if sw.v then
    port.version.version = sw.v
  end

  if sw.i then
    port.version.extrainfo = sw.i
  end

  if sw.h then
    port.version.hostname = sw.h
  end

  if sw.o then
    port.version.ostype = sw.o
  end

  if sw.d then
    port.version.devicetype = sw.d
  end

  if sw.cpe then
    for _, cpe in ipairs(sw.cpe) do
      table.insert(port.version.cpe, "cpe:/" .. cpe)
    end
  end
end

local identify_software = function(pkt, port)
  -- There's not enough information in anything but an ERROR packet to deduce
  -- the software that responded, and only if it has an error message
  if pkt.opcode ~= OPCODE_ERROR or pkt.errmsg == nil then
    stdnse.debug1("Response contains no data that can be used to check software.")
    return
  end

  -- Try to match the packet against our table of responses.
  for _, res in ipairs(responses) do
    if pkt.errcode == res[1] then
      if pkt.errmsg:find(res[2]) then
	record_match(port, res[3])
	break
      end
    end
  end
end

local parse = function(buf)
  -- Every TFTP packet is at least 4 bytes.
  if #buf < 4 then
    stdnse.debug1("Packet was %d bytes, but TFTP packets are a minimum of 4 bytes.", #buf)
    return nil
  end

  local opcode, num = (">HH"):unpack(buf)
  local ret = {["opcode"] = opcode}

  if opcode == OPCODE_DATA then
    -- The block number, which must be one.
    if num ~= 1 then
      stdnse.debug1("DATA packet should have a block number of 1, not %d.", num)
      return nil
    end

    -- The data remaining in the response must be from 0 to 512 bytes in length.
    if #buf > 2 + 2 + 512 then
      stdnse.debug1("DATA packet should be 0 to 512 bytes, but is %d bytes.", #buf)
      return nil
    end

    return ret
  end

  if opcode == OPCODE_ERROR then
    -- The last byte in the packet must be zero to terminate the error message.
    if buf:byte(#buf) ~= 0 then
      stdnse.debug1("ERROR packet does not end with a zero byte.")
      return nil
    end
    ret.errcode = num

    -- Extract the error message, if there is one.
    if #buf > 2 + 2 + 1 then
      ret.errmsg = ("z"):unpack(buf, 5)
    end

    return ret
  end

  -- Any other opcode, defined or otherwise, should not be coming back from the
  -- service, so we treat it as an error.
  stdnse.debug1("Unexpected opcode %d received.", opcode)
  return nil
end

action = function(host, port)
  local output = stdnse.output_table()

  -- Generate a random, unlikely filename in a format unlikely to be rejected,
  -- specifically DOS 8.3 format.
  local name = stdnse.generate_random_string(8, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
  local extn = stdnse.generate_random_string(3, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
  local path = name .. "." .. extn

  -- Create and connect a socket.
  local socket = nmap.new_socket("udp")
  local status, err = socket:connect(host, port)
  if not status then
    socket:close()
    output.ERROR = err
    return output, output.ERROR
  end

  -- Remember the source port this socket used, for listening later.
  local status, err, lport, _, _ = socket:get_info()
  if not status then
    socket:close()
    output.ERROR = err
    return output, output.ERROR
  end

  -- Generate a Read Request.
  local req = (">Hzz"):pack(OPCODE_RRQ, path, "octet")

  -- Send the Read Request.
  socket:send(req)
  socket:close()

  -- Create a listening socket on the port from which we just sent.
  local socket = nmap.new_socket("udp")
  local status, err = socket:bind(nil, lport)
  if not status then
    socket:close()
    output.ERROR = err
    return output, output.ERROR
  end

  -- Listen for a response, but if nothing comes back we have to assume that
  -- this is not a TFTP service and exit quietly.
  --
  -- We don't have to worry about other instance of this script running on other
  -- ports of the same host confounding our results, because TFTP services
  -- should respond back to the port matching the sending script.
  --
  -- Note that due to API limitations, we can't know if the response came from
  -- the host we sent the request to, so we must assume it does.
  local status, res = socket:receive()
  socket:close()
  if not status then
    return nil
  end

  -- Parse the response.
  local pkt = parse(res)
  if not pkt then
    return nil
  end

  -- Now we are convinced that the service speaks TFTP.
  port.version.name = "tftp"

  -- Populate the service information by referencing our list of software
  -- responses.
  identify_software(pkt, port)

  nmap.set_port_version(host, port, "hardmatched")
  nmap.set_port_state(host, port, "open")

  return nil
end
