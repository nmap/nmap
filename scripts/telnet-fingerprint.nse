local stdnse = require "stdnse"
local shortport = require "shortport"
local comm = require "comm"
local nmap = require "nmap"

description = [[
Attempts to fingerprint an open telnet service based on Telnet commands sent
by the server upon connection. See RFC854 for more details.

Original idea from telnetfp by Palmers of Team TESO.

Please send new or incorrect fingerprint data to daniel@planethacker.net
]]

---
-- @usage
-- nmap --script telnet-fingerprint <target>

-- @output
-- 23/tcp open  telnet
-- | telnet-fingerprint:
-- |   Fingerprint: 255 252 1
-- |_  Match: HP JetDirect

author = "Daniel Roberson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


-- Fingerprint table. Please keep in alphabetical order!
fp_table = {}
fp_table["255 251 1"] = "APC, Windows CE"
fp_table["255 253 3"] = "Cisco"
fp_table["255 251 1 255 251 3 255 253 24 255 253 31"] = "Cisco"
fp_table["255 253 3 255 251 3 255 251 1"] = "Enterasys"
fp_table["255 251 1 255 251 3"] = "HP LaserJet"
fp_table["255 251 3 255 251 1"] = "HP Integrated Lights Out"
fp_table["255 252 1"] = "HP JetDirect"
fp_table["255 251 1 255 251 1 255 251 1 255 251 3 255 253 24 255 253 31"] = "Huawei"
fp_table["255 253 24 255 253 32 255 253 35 255 253 39"] = "Linux"
fp_table["255 253 37 255 251 1 255 251 3 255 253 39 255 253 31 255 253 0 255 251 0"] = "Microsoft Telnet Service"
fp_table["255 253 37 255 251 1 255 253 3 255 253 31 255 253 0 255 251 0"] = "Windows NT 4.0"

portrule = shortport.port_or_service(23, "telnet")

action = function(host, port)
  local fingerprint = ""
  local recvbuf = ""
  local t = {}

  local client_telnet = nmap.new_socket()
  local output = stdnse.output_table()

  local catch = function()
    client_telnet:close()
  end

  local try = nmap.new_try(catch)

  try(client_telnet:connect(host, port))
  recvbuf = try(client_telnet:receive())

  -- Extract Telnet commands from received buffer:
  --  Format: 255 <COMMAND> <VALUE>
  if recvbuf then
    for i = 1, string.len(recvbuf) do
      if string.byte(recvbuf, i) == 255 then
        t[#t + 1] = tostring(string.byte(recvbuf, i))
        t[#t + 1] = tostring(string.byte(recvbuf, i + 1))
        t[#t + 1] = tostring(string.byte(recvbuf, i + 2))
      end
    end

    fingerprint = table.concat(t, " ")

    -- Server returned no identifiable data.
    if fingerprint == "" then
      output.Fingerprint = "Unable to fingerprint device."
      client_telnet:close()
      return output
    else
      output.Fingerprint = fingerprint
    end

    -- Search table for matches 
    output.Match = "No matches found. Please submit fingerprints to daniel@planethacker.net"
    if fp_table[fingerprint] then
      output.Match = fp_table[fingerprint]
    end
  end

  client_telnet:close()

  return output
end

