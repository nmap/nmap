local io = require "io"
local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Detects whether a host is infected with the Stuxnet worm (http://en.wikipedia.org/wiki/Stuxnet).

An executable version of the Stuxnet infection will be downloaded if a format
for the filename is given on the command line.
]]

---
-- @usage
-- nmap --script stuxnet-detect -p 445 <host>
--
-- @args stuxnet-detect.save Path to save Stuxnet executable under, with
--       <code>%h</code> replaced by the host's IP address, and <code>%v</code>
--       replaced by the version of Stuxnet.
--
-- @output
-- PORT    STATE SERVICE      REASON
-- 445/tcp open  microsoft-ds syn-ack
--
-- Host script results:
-- |_stuxnet-detect: INFECTED (version 4c:04:00:00:01:00:00:00)

author = "Mak Kolybabi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}


local STUXNET_PATHS = {"\\\\browser", "\\\\ntsvcs", "\\\\pipe\\browser", "\\\\pipe\\ntsvcs"}
local STUXNET_UUID = "\xe1\x04\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
local STUXNET_VERSION = 0x01

local RPC_GET_VERSION = 0x00
local RPC_GET_EXECUTABLE = 0x04

local function check_infected(host, path, save)
  local file, result, session, status, version

  -- Create an SMB session.
  status, session = msrpc.start_smb(host, path)
  if not status then
    stdnse.debug1("Failed to establish session on %s.", path)
    return false, nil
  end

  -- Bind to the Stuxnet service.
  status, result = msrpc.bind(session, STUXNET_UUID, STUXNET_VERSION, nil)
  if not status or result["ack_result"] ~= 0 then
    stdnse.debug1("Failed to bind to Stuxnet service.")
    msrpc.stop_smb(session)
    return false, nil
  end

  -- Request version of Stuxnet infection.
  status, result = msrpc.call_function(session, RPC_GET_VERSION, "")
  if not status then
    stdnse.debug1("Failed to retrieve Stuxnet version: %s", result)
    msrpc.stop_smb(session)
    return false, nil
  end
  version = stdnse.tohex(result.arguments, {separator = ":"})

  -- Request executable of Stuxnet infection.
  if save then
    local file, fmt

    status, result = msrpc.call_function(session, RPC_GET_EXECUTABLE, "")
    if not status then
      stdnse.debug1("Failed to retrieve Stuxnet executable: %s", result)
      msrpc.stop_smb(session)
      return true, version
    end

    fmt = save:gsub("%%h", host.ip)
    fmt = fmt:gsub("%%v", version)
    file = io.open(stdnse.filename_escape(fmt), "w")
    if file then
      stdnse.debug1("Wrote %d bytes to file %s.", #result.arguments, fmt)
      file:write(result.arguments)
      file:close()
    else
      stdnse.debug1("Failed to open file: %s", fmt)
    end
  end

  -- Destroy the SMB session
  msrpc.stop_smb(session)

  return true, version
end

hostrule = function(host)
  return (smb.get_port(host) ~= nil)
end

action = function(host, port)
  local _, path, result, save, status

  -- Get script arguments.
  save = stdnse.get_script_args("stuxnet-detect.save")

  -- Try to find Stuxnet on this host.
  for _, path in pairs(STUXNET_PATHS) do
    status, result = check_infected(host, path, save)
    if status then
      return "INFECTED (version " .. result .. ")"
    end
  end
end
