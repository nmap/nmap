local nmap = require "nmap"
local shortport = require "shortport"
local formulas = require "formulas"

description = [[
Detects the CCcam service (software for sharing subscription TV among
multiple receivers).

The service normally runs on port 12000. It distinguishes
itself by printing 16 random-looking bytes upon receiving a
connection.

Because the script attempts to detect "random-looking" bytes, it has a small
chance of failing to detect the service when the data do not seem random
enough.]]

categories = {"version"}

author = "David Fifield"

local NUM_TRIALS = 2

local function trial(host, port)
  local status, data, s

  s = nmap.new_socket()
  status, data = s:connect(host, port)
  if not status then
    return
  end

  status, data = s:receive_bytes(0)
  if not status then
    s:close()
    return
  end
  s:close()

  return data
end

portrule = shortport.version_port_or_service({10000, 10001, 12000, 12001, 16000, 16001}, "cccam")

function action(host, port)
  local seen = {}

  -- Try a couple of times to see that the response isn't constant. (But
  -- more trials also increase the chance that we will reject a legitimate
  -- cccam service.)
  for i = 1, NUM_TRIALS do
    local data

    data = trial(host, port)
    if not data or seen[data] or #data ~= 16 or not formulas.looksRandom(data) then
      return
    end
    seen[data] = true
  end

  port.version.name = "cccam"
  port.version.version = "CCcam DVR card sharing system"
  nmap.set_port_version(host, port)
end
