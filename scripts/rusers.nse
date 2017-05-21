local rpc = require "rpc"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"

description = [[
Connects to rusersd RPC service and retrieves a list of logged-in users.
]]

---
--@output
--| USER     ON        FROM  SINCE                IDLE
--| LOGIN    console         2015-11-08T12:03:50  8h55m58s
--| root     console   :0    2015-11-08T12:06:49  8h55m58s
--| root     pts/2     :0.0  2015-11-08T12:07:06  2d02h51m48s
--| .telnet  /dev/pts        2016-03-14T12:07:46  24855d03h14m07s
--| .telnet  /dev/pts        2016-03-14T10:25:09  24855d03h14m07s
--| .telnet  /dev/pts        2016-03-03T10:02:15  24855d03h14m07s
--| root     pts/4           2016-03-07T09:21:14  1m48s
--| root     pts/3     ns3   2016-02-16T09:45:24  35s
--| root     pts/4     ns3   2016-02-16T09:26:01  1m48s
--|_.telnet  /dev/pts        2016-03-03T10:01:32  24855d03h14m07s
--
--@xmloutput
--<table>
--  <elem key="idle">1m49s</elem>
--  <elem key="host">ns3</elem>
--  <elem key="user">root</elem>
--  <elem key="time">2016-02-16T09:26:01</elem>
--  <elem key="tty">pts/4</elem>
--</table>
--<table>
--  <elem key="idle">24855d03h14m07s</elem>
--  <elem key="host"></elem>
--  <elem key="user">.telnet</elem>
--  <elem key="time">2016-03-03T10:01:32</elem>
--  <elem key="tty">/dev/pts</elem>
--</table>
--

author = "Daniel Miller"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

dependencies = {"rpc-grind", "rpcinfo"}
portrule = shortport.service("rusersd", {"tcp", "udp"})

-- TODO: Support version 3
rpc.RPC_version["rusersd"] = rpc.RPC_version["rusersd"] or { min=2, max=2 }

local RUSERSPROC = {
  NUM = 1,
  NAMES = 2,
  ALLNAMES = 3,
}

--- Get a RPC string, which is length-prefixed and padded with null bytes
-- @param comm an rpc.Comm object
-- @param data the data received so far
-- @param pos the current position in the data where the opaque string is
-- @param additional number of bytes to request after the string for the next
--                   field. Saves a call to GetAdditionalBytes later.
-- @return position of next field or nil on error
-- @return the string extracted or error message
-- @return the data retrieved so far
local function get_zstring (comm, data, pos, additional)
  local pos, len = rpc.Util.unmarshall_uint32(data, pos)
  local status, data = comm:GetAdditionalBytes( data, pos, len + additional )
  if not status then
    return nil, "GetAdditionalBytes failed"
  end
  local pos, rval = rpc.Util.unmarshall_opaque(len, data, pos)
  rval = string.match(rval, "^(.-)\0*$")
  return pos, rval, data
end

local function fail (err, ...)
  stdnse.debug1(err, ...)
  return nil
end

-- Extract a utmpidle structure:
-- /*
--  * This is the structure used in version 2 of the rusersd RPC service.
--  * It corresponds to the utmp structure for BSD systems.
--  */
-- struct ru_utmp {
--  char ut_line[8]; /* tty name */
--  char ut_name[8]; /* user id */
--  char ut_host[16]; /* host name, if remote */
--  long int ut_time; /* time on */
-- };
--
-- struct utmpidle {
--  struct ru_utmp ui_utmp;
--  unsigned int ui_idle;
-- };
local function rusers2_entry(comm, data, pos)
  local entry = {}
  pos, entry.tty, data = get_zstring(comm, data, pos, 4)
  if not pos then return fail(entry.tty) end

  pos, entry.user, data = get_zstring(comm, data, pos, 4)
  if not pos then return fail(entry.user) end

  pos, entry.host, data = get_zstring(comm, data, pos, 8)
  if not pos then return fail(entry.host) end

  pos, entry.time = rpc.Util.unmarshall_uint32(data, pos)
  entry.time = stdnse.format_timestamp(entry.time)

  pos, entry.idle = rpc.Util.unmarshall_uint32(data, pos)
  entry.idle = stdnse.format_time(entry.idle)

  return pos, entry, data
end

action = function(host, port)
  local comm = rpc.Comm:new("rusersd", 2)
  local status, err = comm:Connect(host, port)
  if not status then
    return fail("RPC connect error: %s", err)
  end

  local packet = comm:EncodePacket(nil, RUSERSPROC.ALLNAMES, {type = rpc.Portmap.AuthType.NULL}, nil)
  status, err = comm:SendPacket(packet)
  if not status then
    return fail("RPC send error: %s", err)
  end

  local status, data = comm:ReceivePacket()
  if not status then
    return fail("RPC receive error: %s", data)
  end

  local pos, header = comm:DecodeHeader(data, 1)
  if not header then
    return fail("RPC decode header error")
  end

  if header.type ~= rpc.Portmap.MessageType.REPLY then
    return fail("Packet was not a reply")
  end

  if header.state ~= rpc.Portmap.State.MSG_ACCEPTED then
    return fail("RPC call failed: %s", rpc.Portmap.RejectMsg[header.denied_state] or header.state)
  end

  if header.accept_state ~= rpc.Portmap.AcceptState.SUCCESS then
      return fail("RPC accepted state: %s", rpc.Portmap.AcceptMsg[header.accept_state] or header.accept_state)
  end

  status, data = comm:GetAdditionalBytes( data, pos, 4 )
  if not status then
    return fail("Failed to call GetAdditionalBytes")
  end

  local pos, num_names = rpc.Util.unmarshall_uint32(data, pos)

  local out = {}
  local out_tab = tab.new()
  tab.addrow(out_tab, "USER", "ON", "FROM", "SINCE", "IDLE")
  for i=1, num_names do
    local entry
    pos, entry, data = rusers2_entry(comm, data, pos)
    tab.addrow(out_tab, entry.user, entry.tty, entry.host, entry.time, entry.idle)
    out[#out+1] = entry
  end

  if next(out) then
    return out, "\n" .. tab.dump(out_tab)
  end

end
