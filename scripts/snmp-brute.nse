local coroutine = require "coroutine"
local creds = require "creds"
local io = require "io"
local nmap = require "nmap"
local packet = require "packet"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local string = require "string"
local unpwdb = require "unpwdb"

description = [[
Attempts to find an SNMP community string by brute force guessing.

This script opens a sending socket and a sniffing pcap socket in parallel
threads. The sending socket sends the SNMP probes with the community strings,
while the pcap socket sniffs the network for an answer to the probes. If
valid community strings are found, they are added to the creds database and
reported in the output.

The script takes the <code>snmp-brute.communitiesdb</code> argument that
allows the user to define the file that contains the community strings to
be used. If not defined, the default wordlist used to bruteforce the SNMP
community strings is <code>nselib/data/snmpcommunities.lst</code>. In case
this wordlist does not exist, the script falls back to
<code>nselib/data/passwords.lst</code>

No output is reported if no valid account is found.
]]
-- 2008-07-03 Philip Pickering, basic version
-- 2011-07-17 Gorjan Petrovski, Patrik Karlsson, optimization and creds
--            accounts, rejected use of the brute library because of
--            implementation using unconnected sockets.
-- 2011-12-29 Patrik Karlsson - Added lport to sniff_snmp_responses to fix
--                              bug preventing multiple scripts from working
--                              properly.
-- 2015-05-31 Gioacchino Mazzurco - Add IPv6 support by making the script IP
--                              version agnostic

---
-- @usage
-- nmap -sU --script snmp-brute <target> [--script-args snmp-brute.communitiesdb=<wordlist> ]
--
-- @args snmp-brute.communitiesdb The filename of a list of community strings to try.
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- | snmp-brute:
-- |   dragon - Valid credentials
-- |_  jordan - Valid credentials

author = "Philip Pickering, Gorjan Petrovski, Patrik Karlsson, Gioacchino Mazzurco"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

local communitiestable = {}

local filltable = function(filename, table)
  if #table ~= 0 then
    return true
  end

  local file = io.open(filename, "r")

  if not file then
    return false
  end

  for l in file:lines() do
    -- Comments takes up a whole line
    if not l:match("#!comment:") then
      table[#table + 1] = l
    end
  end

  file:close()

  return true
end

local closure = function(table)
  local i = 1

  return function(cmd)
    if cmd == "reset" then
      i = 1
      return
    end
    local elem = table[i]
    if elem then i = i + 1 end
    return elem
  end
end

local communities_raw = function(path)
  if not path then
    return false, "Cannot find communities list"
  end

  if not filltable(path, communitiestable) then
    return false, "Error parsing communities list"
  end

  return true, closure(communitiestable)
end

local communities = function()
  local communities_file = stdnse.get_script_args('snmp-brute.communitiesdb') or
  nmap.fetchfile("nselib/data/snmpcommunities.lst")

  if communities_file then
    stdnse.debug1("Using the %s as the communities file", communities_file)

    local status, iterator = communities_raw(communities_file)

    if not status then
      return false, iterator
    end

    local time_limit = unpwdb.timelimit()
    local count_limit = 0

    if stdnse.get_script_args("unpwdb.passlimit") then
      count_limit = tonumber(stdnse.get_script_args("unpwdb.passlimit"))
    end

    return true, unpwdb.limited_iterator(iterator, time_limit, count_limit)
  else
    stdnse.debug1("Cannot read the communities file, using the nmap username/password database instead")

    return unpwdb.passwords()
  end
end

local send_snmp_queries = function(socket, result, nextcommunity)
  local condvar = nmap.condvar(result)

  local request = snmp.buildGetRequest({}, "1.3.6.1.2.1.1.3.0")

  local payload, status, response, err
  local community = nextcommunity()

  while community do
    if result.status == false then
      --in case the sniff_snmp_responses thread was shut down
      condvar("signal")
      return
    end
    payload = snmp.encode(snmp.buildPacket(request, 0, community))
    status, err = socket:send(payload)
    if not status then
      result.status = false
      result.msg = "Could not send SNMP probe"
      condvar "signal"
      return
    end

    community = nextcommunity()
  end

  result.sent = true
  condvar("signal")
end

local sniff_snmp_responses = function(host, port, lport, result)
  local condvar = nmap.condvar(result)
  local pcap = nmap.new_socket()
  pcap:set_timeout(host.times.timeout * 1000 * 3)
  pcap:pcap_open(host.interface, 300, false, "src host ".. host.ip .." and udp and src port 161 and dst port "..lport)

  local communities = creds.Credentials:new(SCRIPT_NAME, host, port)

  -- last_run indicated whether there will be only one more receive
  local last_run = false

  -- receive even when status=false until all the probes are sent
  while true do
    local status, plen, l2, l3, _ = pcap:pcap_receive()

    if status then
      local p = packet.Packet:new(l3,#l3)
      if not p:udp_parse() then
        --shouldn't happen
        result.status = false
        result.msg = "Wrong type of packet received"
        condvar "signal"
        return
      end

      local response = p:raw(p.udp_offset + 8, #p.buf)
      local res
      _, res = snmp.decode(response)

      if type(res) == "table" then
        communities:add(nil, res[2], creds.State.VALID)
      else
        result.status = false
        result.msg = "Wrong type of SNMP response received"
        condvar "signal"
        return
      end
    else
      if last_run then
        condvar "signal"
        return
      else
        if result.sent then
          last_run = true
        end
      end
    end
  end
  pcap:close()
  condvar "signal"
  return
end

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local status, nextcommunity = communities()

  if not status then
    return fail("Failed to read the communities database")
  end

  local result = {}
  local threads = {}

  local condvar = nmap.condvar(result)

  result.sent = false --whether the probes are sent
  result.msg = "" -- Error/Status msg
  result.status = true -- Status (is everything ok)

  local socket = nmap.new_socket("udp")
  status = socket:connect(host, port)

  if ( not(status) ) then
    return fail("Failed to connect to server")
  end

  local status, _, lport = socket:get_info()
  if( not(status) ) then
    return fail("Failed to retrieve local port")
  end

  local recv_co = stdnse.new_thread(sniff_snmp_responses, host, port, lport, result)
  local send_co = stdnse.new_thread(send_snmp_queries, socket, result, nextcommunity)

  local recv_dead, send_dead
  while true do
    condvar "wait"
    recv_dead = (coroutine.status(recv_co) == "dead")
    send_dead = (coroutine.status(send_co) == "dead")
    if recv_dead then break end
  end

  socket:close()

  if result.status then
    return creds.Credentials:new(SCRIPT_NAME, host, port):getTable()
  else
    stdnse.debug1("An error occurred: "..result.msg)
  end
end

