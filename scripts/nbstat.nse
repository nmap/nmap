local datafiles = require "datafiles"
local netbios = require "netbios"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to retrieve the target's NetBIOS names and MAC address.

By default, the script displays the name of the computer and the logged-in
user; if the verbosity is turned up, it displays all names the system thinks it
owns.
]]

---
-- @usage
-- sudo nmap -sU --script nbstat.nse -p137 <host>
--
-- @output
-- Host script results:
-- |_ nbstat: NetBIOS name: WINDOWS2003, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:c6:da:f5 (VMware)
--
-- Host script results:
-- |  nbstat: NetBIOS name: WINDOWS2003, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:c6:da:f5 (VMware)
-- |  Names:
-- |    WINDOWS2003<00>      Flags: <unique><active>
-- |    WINDOWS2003<20>      Flags: <unique><active>
-- |    SKULLSECURITY<00>    Flags: <group><active>
-- |    SKULLSECURITY<1e>    Flags: <group><active>
-- |    SKULLSECURITY<1d>    Flags: <unique><active>
-- |_   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
--
-- @xmloutput
-- <elem key="server_name">WINDOWS2003</elem>
-- <elem key="user">&lt;unknown&gt;</elem>
-- <table key="mac">
--   <elem key="manuf">VMware</elem>
--   <elem key="address">00:0c:29:c6:da:f5</elem>
-- </table>
-- <table key="Names">
--   <table>
--     <elem key="name">WINDOWS2003</elem>
--     <elem key="suffix">0</elem>
--     <elem key="flags">1024</elem>
--   </table>
--   <table>
--     <elem key="name">SKULLSECURITY</elem>
--     <elem key="suffix">0</elem>
--     <elem key="flags">33792</elem>
--   </table>
--   <table>
--     <elem key="name">WINDOWS2003</elem>
--     <elem key="suffix">32</elem>
--     <elem key="flags">1024</elem>
--   </table>
--   <table>
--     <elem key="name">SKULLSECURITY</elem>
--     <elem key="suffix">30</elem>
--     <elem key="flags">33792</elem>
--   </table>
--   <table>
--     <elem key="name">SKULLSECURITY</elem>
--     <elem key="suffix">29</elem>
--     <elem key="flags">1024</elem>
--   </table>
--   <table>
--     <elem key="name">\x01\x02__MSBROWSE__\x02</elem>
--     <elem key="suffix">1</elem>
--     <elem key="flags">33792</elem>
--   </table>
-- </table>
-- <table key="Statistics">
--   <elem>00 0c 29 c6 da f5 00 00 00 00 00 00 00 00 00 00 00</elem>
--   <elem>00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00</elem>
--   <elem>00 00 00 00 00 00 00 00 00 00 00 00 00 00</elem>
-- </table>


author = "Brandon Enright, Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- Current version of this script was based entirely on Implementing CIFS, by
-- Christopher R. Hertel.
categories = {"default", "discovery", "safe"}


hostrule = function(host)

  -- The following is an attempt to only run this script against hosts
  -- that will probably respond to a UDP 137 probe.  One might argue
  -- that sending a single UDP packet and waiting for a response is no
  -- big deal and that it should be done for every host.  In that case
  -- simply change this rule to always return true.

  local port_t135 = nmap.get_port_state(host,
    {number=135, protocol="tcp"})
  local port_t139 = nmap.get_port_state(host,
    {number=139, protocol="tcp"})
  local port_t445 = nmap.get_port_state(host,
    {number=445, protocol="tcp"})
  local port_u137 = nmap.get_port_state(host,
    {number=137, protocol="udp"})

  return (port_t135 ~= nil and port_t135.state == "open") or
    (port_t139 ~= nil and port_t139.state == "open") or
    (port_t445 ~= nil and port_t445.state == "open") or
    (port_u137 ~= nil and
      (port_u137.state == "open" or
      port_u137.state == "open|filtered"))
end


action = function(host)

  local i
  local status
  local names, statistics
  local server_name, user_name
  local mac, prefix, manuf
  local response = {}
  local catch = function() return end
  local try = nmap.new_try(catch)


  -- Get the list of NetBIOS names
  status, names, statistics = netbios.do_nbstat(host)
  status, names, statistics = netbios.do_nbstat(host)
  status, names, statistics = netbios.do_nbstat(host)
  status, names, statistics = netbios.do_nbstat(host)
  if(status == false) then
    return stdnse.format_output(false, names)
  end

  -- Get the server name
  status, server_name = netbios.get_server_name(host, names)
  if(status == false) then
    return stdnse.format_output(false, server_name)
  end

  -- Get the logged in user
  status, user_name = netbios.get_user_name(host, names)
  if(status == false) then
    return stdnse.format_output(false, user_name)
  end

  local mac_prefixes = try(datafiles.parse_mac_prefixes())

  -- Format the Mac address in the standard way
  if(#statistics >= 6) then
    -- MAC prefixes are matched on the first three bytes, all uppercase
    prefix = string.upper(string.format("%02x%02x%02x", statistics:byte(1), statistics:byte(2), statistics:byte(3)))
    mac = {
      address = ("%02x:%02x:%02x:%02x:%02x:%02x"):format( statistics:byte(1), statistics:byte(2), statistics:byte(3), statistics:byte(4), statistics:byte(5), statistics:byte(6) ),
      manuf = mac_prefixes[prefix] or "unknown"
    }
    host.registry['nbstat'] = {
      server_name = server_name,
      mac = mac.address
    }
    -- Samba doesn't set the Mac address, and nmap-mac-prefixes shows that as Xerox
    if(mac.address == "00:00:00:00:00:00") then
      mac.address = "<unknown>"
      mac.manuf = "unknown"
    end
  else
    mac = {
      address = "<unknown>",
      manuf = "unknown"
    }
  end
  setmetatable(mac, {
    -- MAC is formatted as "00:11:22:33:44:55 (Manufacturer)"
    __tostring=function(t) return string.format("%s (%s)", t.address, t.manuf) end
  })

  -- Check if we actually got a username
  if(user_name == nil) then
    user_name = "<unknown>"
  end

  response["server_name"] = server_name
  response["user"] = user_name
  response["mac"] = mac

  local names_output = {}
  for i = 1, #names, 1 do
    local name = names[i]
    setmetatable(name, {
      __tostring = function(t)
        -- Tabular format with padding
        return string.format("%s<%02x>%sFlags: %s",
        t['name'], t['suffix'],
        string.rep(" ", 17 - #t['name']),
        netbios.flags_to_string(t['flags']))
      end
    })
    table.insert(names_output, name)
  end
  setmetatable(names_output, {
    __tostring = function(t)
      local ret = {}
      for i,v in ipairs(t) do
        table.insert(ret, tostring(v))
      end
      -- Indent Names table by 2 spaces
      return "  " .. table.concat(ret, "\n  ")
    end
  })

  response["names"] = names_output

  local statistics_output = {}
  for i = 1, #statistics, 16 do
    --Format statistics as space-separated hex bytes, 16 columns
    table.insert(statistics_output,
      stdnse.tohex(string.sub(statistics,i,i+16), {separator = " "})
    )
  end
  response["statistics"] = statistics_output

  setmetatable(response, {
    __tostring = function(t)
      -- Normal single-line result
      local ret = {string.format("NetBIOS name: %s, NetBIOS user: %s, NetBIOS MAC: %s", t.server_name, t.user, t.mac)}
      -- If verbosity is set, dump the whole list of names
      if nmap.verbosity() >= 1 then
        table.insert(ret, string.format("Names:\n%s",t.names))
        -- If super verbosity is set, print out the full statistics
        if nmap.verbosity() >= 2 then
          -- Indent Statistics table by 2 spaces
          table.insert(ret, string.format("Statistics:\n  %s",table.concat(t.statistics,"\n  ")))
        end
      end
      return table.concat(ret, "\n")
    end
  })

  return response

end
