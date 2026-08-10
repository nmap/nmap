local nmap = require "nmap"
local rand = require "rand"
local stdnse = require "stdnse"
local string = require "string"
local shortport = require "shortport"
local table = require "table"
local ipOps = require "ipOps"
local packet = require "packet"
local tftp = require "tftp"

description=[[
Obtains information (such as vendor and device type where available) from a
TFTP service by requesting a random filename. Software vendor information is
determined by matching the error message against a database of known software.
]]

---
-- @usage nmap -sU -p 69 --script tftp-version
-- @usage nmap -sV -p 69
--
-- @args tftp-version.socket Use a listening UDP socket to recieve error messages. This
--                           method is frequently blocked by client firewalls and NAT
--                           devices, so the default is to use packet capture instead.
--
-- @output
-- PORT   STATE SERVICE
-- 69/udp open  tftp
-- | tftp-version:
-- |   If you know the name or version of the software running on this port, please submit
-- it to dev@nmap.org along with the following information:
-- |     opcode: 5
-- |     errcode: 1
-- |     length: 20
-- |     rport: 69
-- |_    errmsg: can't open file
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 69/udp open  tftp    Brother printer tftpd
--
-- @output
-- 69/udp open  tftp
-- | tftp-version:
-- |   d: printer
-- |_  p: Brother printer tftpd
--
--
--@xmloutput
--<table key="If you know the name or version of the software running on this port, please
--submit it to dev@nmap.org along with the following information">
--  <elem key="opcode">5</elem>
--  <elem key="errcode">2</elem>
--  <elem key="length">21</elem>
--  <elem key="rport">14571</elem>
--  <elem key="errmsg">Access violation</elem>
--</table>
--
author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "version"}

portrule = shortport.version_port_or_service(69, "tftp", "udp")

local load_fingerprints = function()
  -- Check if fingerprints are cached.
  if nmap.registry.tftp_fingerprints ~= nil then
    stdnse.debug1("Loading cached TFTP fingerprints...")
    return nmap.registry.tftp_fingerprints
  end

  -- Load the fingerprints.
  local path = nmap.fetchfile("nselib/data/tftp-fingerprints.lua")
  stdnse.debug1("Loading TFTP fingerprint from files: %s", path)
  local file = loadfile(path, "t")
  if not file then
    stdnse.debug1("Couldn't load the file: %s", path)
    return false
  end
  local fingerprints = file()

  -- Check there are fingerprints to use
  if not fingerprints or #fingerprints == 0 then
    stdnse.debug1("No fingerprints were loaded from file: %s", path)
    return false
  end

  return fingerprints
end

local parse = function(buf, rport)
  -- Every TFTP packet is at least 4 bytes.
  if #buf < 4 then
    stdnse.debug1("Packet was %d bytes, but TFTP packets are a minimum of 4 bytes.", #buf)
    return nil
  end

  local opcode, num, pos = (">I2I2"):unpack(buf)
  local ret = stdnse.output_table()
  ret.opcode = opcode
  ret.errcode = num
  ret.length = #buf
  ret.rport = rport

  if opcode == tftp.OpCode.DATA then
    -- The block number, which must be one.
    if num ~= 1 then
      stdnse.debug1("DATA packet should have a block number of 1, not %d.", num)
    end

    -- The data remaining in the response must be from 0 to 512 bytes in length.
    if #buf > 2 + 2 + 512 then
      stdnse.debug1("DATA packet should be 0 to 512 bytes, but is %d bytes.", #buf)
    else
      ret.errmsg = buf:sub(pos)
    end

  elseif opcode == tftp.OpCode.ERROR
    -- ACK extremely unlikely, but we should be thorough.
    or opcode == tftp.OpCode.ACK then
    -- Extract the error message, if there is one.
    ret.errmsg, pos = ("z"):unpack(buf, pos)
    -- The last byte in the packet must be zero to terminate the error message.
    if pos ~= #buf + 1 then -- catch both short and long packets
      stdnse.debug1("ERROR packet does not end with a zero byte.")
    end

  elseif opcode == tftp.OpCode.RRQ or opcode == tftp.OpCode.WRQ then
    ret.errmsg, pos = ("z"):unpack(buf, pos - 2)
    if pos < #buf then
      ret.mode = ("z"):unpack(buf, pos)
    end
    if pos ~= #buf + 1 then -- catch both short and long packets
      stdnse.debug1("RRQ/WRQ packet does not contain 2 zero-terminated strings")
    end
  else
    -- Any other opcode, defined or otherwise, should not be coming back from the
    -- service, so we treat it as an error.
    stdnse.debug1("Unexpected opcode %d received.", opcode)
    return nil
  end

  return ret
end

-- This works, as does using the same socket without calling connect(), but
-- firewalls frequently block the incoming data connection since it isn't on an
-- established local:remote port pair. Better to use pcap, but we'll let users
-- try it out if they really want to.
local socket_listen = function (lhost, lport, host)
  local bind_socket = nmap.new_socket("udp")
  bind_socket:set_timeout(stdnse.get_timeout(host))
  bind_socket:bind(lhost, lport)

  local status, res = bind_socket:receive()
  if not status then
    stdnse.debug1("Failed to receive response from server: %s", res)
    return nil
  end

  local status, err, _, rhost, rport = bind_socket:get_info()
  bind_socket:close()
  if not status then
    stdnse.debug1("Failed to determine source of response: %s", err)
    return nil
  end

  return res, rhost, rport
end

local pcap_listen = function (lhost, lport, host)
  local pcap = nmap.new_socket()
  pcap:pcap_open(host.interface, 256, false,
    ("udp and dst host %s and dst port %d"):format(lhost, lport))
  pcap:set_timeout(stdnse.get_timeout(host))

  local status, length, layer2, layer3 = pcap:pcap_receive()
  if not status then
    stdnse.debug1("Failed to get a response: %s", length)
    return nil
  end

  local p = packet.Packet:new(layer3, length)
  if not p or not p.udp then
    stdnse.debug1("Error parsing packet.")
    return nil
  end
  local res = layer3:sub(p.udp_offset + 8 + 1) -- packet.lua uses 0-offsets
  local rhost = p.ip_src
  local rport = p.udp_sport
  pcap:pcap_close()
  return res, rhost, rport
end

local get_listen_func = function (use_socket)
  if use_socket then
    return socket_listen
  else
    if nmap.is_privileged() then
      return pcap_listen
    else
      stdnse.verbose("Can't use pcap; will try listening with socket.")
      return socket_listen
    end
  end
end

action = function(host, port)
  local output = stdnse.output_table()
  local listenfunc = get_listen_func(stdnse.get_script_args(SCRIPT_NAME .. '.socket'))

  -- Generate a random, unlikely filename in a format unlikely to be rejected,
  -- specifically DOS 8.3 format.
  local name = rand.random_string(8, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
  local extn = rand.random_string(3, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
  local path = name .. "." .. extn

  -- Create and connect a socket.
  local socket = nmap.new_socket("udp")
  socket:set_timeout(stdnse.get_timeout(host))
  socket:connect(host, port)
  local status, lhost, lport, rhost, rport = socket:get_info()

  -- Generate a Read Request.
  local req = (">Hzz"):pack(tftp.OpCode.RRQ, path, "octet")

  -- Send the Read Request.
  socket:sendto(host, port, req)
  socket:close()

  -- Listen for a response, but if nothing comes back we have to assume that
  -- this is not a TFTP service and exit quietly.
  --
  -- We don't have to worry about other instance of this script running on other
  -- ports of the same host confounding our results, because TFTP services
  -- should respond back to the port matching the sending script.
  local res, rhost, rport = listenfunc(lhost, lport, host)
  if not res then
    stdnse.debug1("Failed to receive response from server")
    return nil
  end
  if rhost ~= host.ip then
    stdnse.debug1("UDP response came from unexpected host: %s (expected %s)", rhost, host.ip)
    return nil
  end

  -- Parse the response.
  local pkt = parse(res, rport)
  if not pkt then
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
  for _, fp in ipairs(fingerprints[pkt.opcode]) do
    if pkt.errcode == fp.errcode and pkt.errmsg == fp.errmsg
      and not (fp.rport and pkt.rport ~= fp.rport) then
      sw = fp.product
      break
    end
  end

  if not sw then
    nmap.set_port_version(host, port, "hardmatched")
    return {["If you know the name or version of the software running on this port, please submit it to dev@nmap.org along with the following information"]= pkt}
  end

  -- Our goal is to avoid printing output when run with -sV unless it differs.
  -- When selected by name, always print output
  local emit_output = nmap.verbosity() > 0

  for _, keypair in ipairs({
      {"product", "p"},
      {"version", "v"},
      {"extrainfo", "i"},
      {"hostname", "h"},
      {"ostype", "o"},
      {"devicetype", "d"},
    }) do
    local pv = port.version[keypair[1]]
    local sv = sw[keypair[2]]
    if not pv then
      port.version[keypair[1]] = sv
    elseif sv and pv ~= sv then
      emit_output = true
    end
  end

  -- Only add CPEs if they aren't there already, to avoid doubling-up.
  if sw.cpe then
    local seen = {}
    if port.version.cpe then
      for _, cpe in ipairs(port.version.cpe) do
        seen[cpe] = 1
      end
      for _, cpe in ipairs(sw.cpe) do
        if not seen[cpe] then
          table.insert(port.version.cpe, cpe)
        end
      end
    else
      port.version.cpe = {table.unpack(sw.cpe)}
    end
  end

  nmap.set_port_version(host, port, "hardmatched")

  if emit_output then
    return sw
  end
end
