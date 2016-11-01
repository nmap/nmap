local json = require "json"
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

local load_fingerprints = function()
  -- Check if fingerprints are cached.
  if nmap.registry.tftp_fingerprints then
    stdnse.debug1("Loading cached TFTP fingerprints...")
    return nmap.registry.tftp_fingerprints
  end

  -- Load the fingerprints.
  local path = nmap.fetchfile("nselib/data/tftp-fingerprints.lua")
  stdnse.debug1("Loading TFTP fingerprint from files: %s", path)
  local env = setmetatable({fingerprints = {}}, {__index = _G});
  local file = loadfile(path, "t", env)
  if not file then
    stdnse.debug1("Couldn't load the file: %s", path)
    return nil
  end
  file()
  local fingerprints = env.fingerprints

  -- Check there are fingerprints to use
  if #fingerprints == 0 then
    stdnse.debug1("No fingerprints were loaded from file: %s", path)
    return nil
  end

  return fingerprints
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
  local status, res = socket:receive()
  if not status then
    stdnse.debug1("Failed to receive response from server: %s", res)
    return nil
  end

  local status, err, _, rhost, _ = socket:get_info()
  socket:close()
  if not status then
    stdnse.debug1("Failed to determine source of response: %s", err)
    return nil
  end

  if rhost ~= host.ip then
    stdnse.debug1("UDP response came from unexpected host: %s", rhost)
    return nil
  end

  -- Parse the response.
  local pkt = parse(res)
  if not pkt then
    return nil
  end

  -- There's not enough information in anything but an ERROR packet to deduce
  -- the software that responded, and only if it has an error message
  if pkt.opcode ~= OPCODE_ERROR or pkt.errmsg == nil then
    stdnse.debug1("Response contains no data that can be used to check software.")
    return nil
  end

  -- We're sure this is a TFTP server by this point..
  nmap.set_port_state(host, port, "open")
  port.version = port.version or {}
  port.version.service = "tftp"

  local fingerprints = load_fingerprints()
  if not fingerprints then
    return nil
  end

  -- Try to match the packet against our table of responses, falling back to
  -- encouraging the user to submit a fingerprint to Nmap.
  local sw = nil
  for _, fp in ipairs(fingerprints) do
    if pkt.errcode == fp[1] and pkt.errmsg == fp[2] then
      sw = fp[3]
      break
    end
  end

  if not sw then
    nmap.set_port_version(host, port, "hardmatched")
    pkt.script = "tftp-version"
    local pkt = json.generate(pkt)
    local msg = ("If you know the name or version of the software running on this port, please submit it to dev@nmap.org along with the following information: %s."):format(pkt)
    stdnse.verbose(msg)
    return msg
  end

  if not port.version.product and sw.p then
    port.version.product = sw.p
  end

  if not port.version.version and sw.v then
    port.version.version = sw.v
  end

  if not port.version.extrainfo and sw.i then
    port.version.extrainfo = sw.i
  end

  if not port.version.hostname and sw.h then
    port.version.hostname = sw.h
  end

  if not port.version.ostype and sw.o then
    port.version.ostype = sw.o
  end

  if not port.version.devicetype and sw.d then
    port.version.devicetype = sw.d
  end

  -- Only add CPEs if there aren't any already, to avoid doubling-up.
  port.version.cpe = port.version.cpe or {}
  if #port.version.cpe == 0 and sw.cpe then
    for _, cpe in ipairs(sw.cpe) do
     table.insert(port.version.cpe, "cpe:/" .. cpe)
    end
  end

  port.version = port.version or {}
  port.version.service = "tftp"

  nmap.set_port_version(host, port, "hardmatched")

  return nil
end
