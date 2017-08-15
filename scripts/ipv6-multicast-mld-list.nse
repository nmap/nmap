local ipOps = require "ipOps"
local coroutine = require "coroutine"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local multicast = require "multicast"

description = [[
Uses Multicast Listener Discovery to list the multicast addresses subscribed to
by IPv6 multicast listeners on the link-local scope. Addresses in the IANA IPv6
Multicast Address Space Registry have their descriptions listed.
]]

---
-- @usage
-- nmap --script=ipv6-multicast-mld-list
--
-- @output
-- Pre-scan script results:
-- | ipv6-multicast-mld-list:
-- |   fe80::9fb:25b7:1b7c:e53:
-- |     device: wlan0
-- |     mac: 38:60:77:3d:b1:ec
-- |     multicast_ips:
-- |       ff02::1:ff7c:e53          (NDP Solicited-node)
-- |       ff02::fb                  (mDNSv6)
-- |       ff02::c                   (SSDP)
-- |_      ff02::1:3                 (Link-local Multicast Name Resolution)
--
-- @args ipv6-multicast-mld-list.timeout timeout to wait for
--       responses (default: 10s)
-- @args ipv6-multicast-mld-list.interface Interface to send on (default:
--       the interface specified with -e or every available Ethernet interface
--       with an IPv6 address.)
--
-- @xmloutput
-- <table key="fe80::9fb:25b7:1b7c:e53">
--   <elem key="device">wlan0</elem>
--   <elem key="mac">38:60:77:3d:b1:ec</elem>
--   <table key="multicast_ips">
--     <table>
--       <elem key="description">NDP Solicited-node</elem>
--       <elem key="ip">ff02::1:ff7c:e53</elem>
--     </table>
--     <table>
--       <elem key="description">mDNSv6</elem>
--       <elem key="ip">ff02::fb</elem>
--     </table>
--     <table>
--       <elem key="description">SSDP</elem>
--       <elem key="ip">ff02::c</elem>
--     </table>
--     <table>
--       <elem key="description">Link-local Multicast Name Resolution</elem>
--       <elem key="ip">ff02::1:3</elem>
--     </table>
--   </table>
-- </table>

author = {"alegen", "Daniel Miller"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
-- Technically multicast, not broadcast
categories = {"broadcast", "discovery"}

-- https://www.iana.org/assignments/ipv6-multicast-addresses/link-local.csv
-- Removed "variable scope" and "Unassigned"
-- Address(s),Description,Reference,Date Registered,Last Reviewed
local link_scope = [==[
FF02:0:0:0:0:0:0:1,All Nodes Address,[RFC4291],,
FF02:0:0:0:0:0:0:2,All Routers Address,[RFC4291],,
FF02:0:0:0:0:0:0:4,DVMRP Routers,[RFC1075][Jon_Postel],,
FF02:0:0:0:0:0:0:5,OSPFIGP,[RFC2328][John_Moy],,
FF02:0:0:0:0:0:0:6,OSPFIGP Designated Routers,[RFC2328][John_Moy],,
FF02:0:0:0:0:0:0:7,ST Routers,[RFC1190][<mystery contact>],,
FF02:0:0:0:0:0:0:8,ST Hosts,[RFC1190][<mystery contact>],,
FF02:0:0:0:0:0:0:9,RIP Routers,[RFC2080],,
FF02:0:0:0:0:0:0:A,EIGRP Routers,[draft-savage-eigrp],,
FF02:0:0:0:0:0:0:B,Mobile-Agents,[Bill_Simpson],1994-11-01,
FF02:0:0:0:0:0:0:C,SSDP,[UPnP_Forum],2006-09-21,
FF02:0:0:0:0:0:0:D,All PIM Routers,[Dino_Farinacci],,
FF02:0:0:0:0:0:0:E,RSVP-ENCAPSULATION,[Bob_Braden],1996-04-01,
FF02:0:0:0:0:0:0:F,UPnP,[UPnP_Forum],2006-09-21,
FF02:0:0:0:0:0:0:10,All-BBF-Access-Nodes,[RFC6788],,
FF02:0:0:0:0:0:0:12,VRRP,[RFC5798],,
FF02:0:0:0:0:0:0:16,All MLDv2-capable routers,[RFC3810],,
FF02:0:0:0:0:0:0:1A,all-RPL-nodes,[RFC6550],,
FF02:0:0:0:0:0:0:6A,All-Snoopers,[RFC4286],,
FF02:0:0:0:0:0:0:6B,PTP-pdelay,[http://ieee1588.nist.gov/][Kang_Lee],2007-02-02,
FF02:0:0:0:0:0:0:6C,Saratoga,[Lloyd_Wood],2007-08-30,
FF02:0:0:0:0:0:0:6D,LL-MANET-Routers,[RFC5498],,
FF02:0:0:0:0:0:0:6E,IGRS,[Xiaoyu_Zhou],2009-01-20,
FF02:0:0:0:0:0:0:6F,iADT Discovery,[Paul_Suhler],2009-05-12,
FF02:0:0:0:0:0:0:FB,mDNSv6,[RFC6762],2005-10-05,
FF02:0:0:0:0:0:1:1,Link Name,[Dan_Harrington],1996-07-01,
FF02:0:0:0:0:0:1:2,All-dhcp-agents,[RFC3315],,
FF02:0:0:0:0:0:1:3,Link-local Multicast Name Resolution,[RFC4795],,
FF02:0:0:0:0:0:1:4,DTCP Announcement,[Moritz_Vieth][Hanno_Tersteegen],2004-05-01,
FF02:0:0:0:0:0:1:5,afore_vdp,[Michael_Richardson],2010-11-30,
FF02:0:0:0:0:0:1:6,Babel,[RFC6126],,
FF02::1:FF00:0000/104,Solicited-Node Address,[RFC4291],,
FF02:0:0:0:0:2:FF00::/104,Node Information Queries,[RFC4620],,
]==]

-- https://www.iana.org/assignments/ipv6-multicast-addresses/variable.csv
-- Removed "Unassigned"
local var_scope = [==[
FF0X:0:0:0:0:0:0:0,Reserved Multicast Address,[RFC4291],,
FF0X:0:0:0:0:0:0:C,SSDP,[UPnP_Forum],2006-09-21,
FF0X:0:0:0:0:0:0:FB,mDNSv6,[RFC6762],2005-10-05,
FF0X:0:0:0:0:0:0:FC,ALL_MPL_FORWARDERS,[RFC-ietf-roll-trickle-mcast-12],2013-04-10,
FF0X:0:0:0:0:0:0:FD,All CoAP Nodes,[RFC7252],2013-07-25,
FF0X:0:0:0:0:0:0:100,VMTP Managers Group,[RFC1045][Dave_Cheriton],,
FF0X:0:0:0:0:0:0:101,Network Time Protocol (NTP),[RFC1119][RFC5905][David_Mills],,
FF0X:0:0:0:0:0:0:102,SGI-Dogfight,[Andrew_Cherenson],,
FF0X:0:0:0:0:0:0:103,Rwhod,[Steve_Deering],,
FF0X:0:0:0:0:0:0:104,VNP,[Dave_Cheriton],,
FF0X:0:0:0:0:0:0:105,Artificial Horizons - Aviator,[Bruce_Factor],,
FF0X:0:0:0:0:0:0:106,NSS - Name Service Server,[Bill_Schilit],,
FF0X:0:0:0:0:0:0:107,AUDIONEWS - Audio News Multicast,[Martin_Forssen],,
FF0X:0:0:0:0:0:0:108,SUN NIS+ Information Service,[Chuck_McManis],,
FF0X:0:0:0:0:0:0:109,MTP Multicast Transport Protocol,[Susie_Armstrong],,
FF0X:0:0:0:0:0:0:10A,IETF-1-LOW-AUDIO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:10B,IETF-1-AUDIO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:10C,IETF-1-VIDEO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:10D,IETF-2-LOW-AUDIO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:10E,IETF-2-AUDIO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:10F,IETF-2-VIDEO,[Steve_Casner],,
FF0X:0:0:0:0:0:0:110,MUSIC-SERVICE,[[Guido van Rossum]],,
FF0X:0:0:0:0:0:0:111,SEANET-TELEMETRY,[[Andrew Maffei]],,
FF0X:0:0:0:0:0:0:112,SEANET-IMAGE,[[Andrew Maffei]],,
FF0X:0:0:0:0:0:0:113,MLOADD,[Bob_Braden],1996-04-01,
FF0X:0:0:0:0:0:0:114,any private experiment,[Jon_Postel],,
FF0X:0:0:0:0:0:0:115,DVMRP on MOSPF,[John_Moy],,
FF0X:0:0:0:0:0:0:116,SVRLOC,[Erik_Guttman],2001-05-01,
FF0X:0:0:0:0:0:0:117,XINGTV,[<hgxing&aol.com>],,
FF0X:0:0:0:0:0:0:118,microsoft-ds,[Arnold_M],,
FF0X:0:0:0:0:0:0:119,nbc-pro,[Bloomer],,
FF0X:0:0:0:0:0:0:11A,nbc-pfn,[Bloomer],,
FF0X:0:0:0:0:0:0:11B,lmsc-calren-1,[Yea_Uang],1994-11-01,
FF0X:0:0:0:0:0:0:11C,lmsc-calren-2,[Yea_Uang],1994-11-01,
FF0X:0:0:0:0:0:0:11D,lmsc-calren-3,[Yea_Uang],1994-11-01,
FF0X:0:0:0:0:0:0:11E,lmsc-calren-4,[Yea_Uang],1994-11-01,
FF0X:0:0:0:0:0:0:11F,ampr-info,[Rob_Janssen],1995-01-01,
FF0X:0:0:0:0:0:0:120,mtrace,[Steve_Casner],1995-01-01,
FF0X:0:0:0:0:0:0:121,RSVP-encap-1,[Bob_Braden],1996-04-01,
FF0X:0:0:0:0:0:0:122,RSVP-encap-2,[Bob_Braden],1996-04-01,
FF0X:0:0:0:0:0:0:123,SVRLOC-DA,[Erik_Guttman],2001-05-01,
FF0X:0:0:0:0:0:0:124,rln-server,[Brian_Kean],1995-08-01,
FF0X:0:0:0:0:0:0:125,proshare-mc,[Mark_Lewis],1995-10-01,
FF0X:0:0:0:0:0:0:126,dantz,[Dotty_Yackle],1996-02-01,
FF0X:0:0:0:0:0:0:127,cisco-rp-announce,[Dino_Farinacci],,
FF0X:0:0:0:0:0:0:128,cisco-rp-discovery,[Dino_Farinacci],,
FF0X:0:0:0:0:0:0:129,gatekeeper,[Jim_Toga],1996-05-01,
FF0X:0:0:0:0:0:0:12A,iberiagames,[Jose_Luis_Marocho],1996-07-01,
FF0X:0:0:0:0:0:0:12B,X Display,[John_McKernan],2003-05-01,
FF0X:0:0:0:0:0:0:12C,dof-multicast,[Bryant_Eastham],2005-04-01,2015-04-23
FF0X:0:0:0:0:0:0:12D,DvbServDisc,[Bert_van_Willigen],2005-09-16,
FF0X:0:0:0:0:0:0:12E,Ricoh-device-ctrl,[Kohki_Ohhira],2006-06-20,
FF0X:0:0:0:0:0:0:12F,Ricoh-device-ctrl,[Kohki_Ohhira],2006-06-20,
FF0X:0:0:0:0:0:0:130,UPnP,[UPnP_Forum],2006-09-21,
FF0X:0:0:0:0:0:0:131,Systech Mcast,[Dan_Jakubiec],2006-09-21,
FF0X:0:0:0:0:0:0:132,omasg,[Mark_Lipford],2006-09-21,
FF0X:0:0:0:0:0:0:133,ASAP,[RFC5352],,
FF0X:0:0:0:0:0:0:134,unserding,[Sebastian_Freundt],2009-11-30,
FF0X:0:0:0:0:0:0:135,PHILIPS-HEALTH,[Anthony_Kandaya],2010-02-26,
FF0X:0:0:0:0:0:0:136,PHILIPS-HEALTH,[Anthony_Kandaya],2010-02-26,
FF0X:0:0:0:0:0:0:137,Niagara,[Owen_Michael_James],2010-09-13,
FF0X:0:0:0:0:0:0:138,LXI-EVENT,[Tom_Fay],2011-01-31,
FF0X:0:0:0:0:0:0:139,LANCOM Discover,[Martin_Krebs],2011-05-09,
FF0X:0:0:0:0:0:0:13A,AllJoyn,[Craig_Dowell],2011-11-18,
FF0X:0:0:0:0:0:0:13B,GNUnet,[Christian_Grothoff],2011-11-22,
FF0X:0:0:0:0:0:0:13C,fos4Xdevices,[Rolf_Wojtech],2011-12-07,
FF0X:0:0:0:0:0:0:13D,USNAMES-NET-MC,[Christopher_Mettin],2013-01-24,
FF0X:0:0:0:0:0:0:13E,hp-msm-discover,[John_Flick],2013-02-28,
FF0X:0:0:0:0:0:0:13F,"SANYO DENKI CO., LTD.",[Yuuki_Hara],2014-03-20,
FF0X:0:0:0:0:0:0:140-FF0X:0:0:0:0:0:0:14F,EPSON-disc-set,[Seiko_Epson_Corp],2010-02-26,
FF0X:0:0:0:0:0:0:150,an-adj-disc,[Toerless_Eckert],2014-06-04,
FF0X:0:0:0:0:0:0:151,Canon-Device-control,[Hiroshi_Okubo],2014-08-01,
FF0X:0:0:0:0:0:0:152,TinyMessage,[Josip_Medved],2014-12-09,
FF0X:0:0:0:0:0:0:153,ZigBee NAN DS,[Yusuke_Doi],2015-08-21,
FF0X:0:0:0:0:0:0:154,ZigBee NAN DI,[Yusuke_Doi],2015-08-21,
FF0X:0:0:0:0:0:0:155,jini-announcement,[Jini Discovery and Join Specification][Peter_Grahame_Firmstone],2015-08-27,
FF0X:0:0:0:0:0:0:156,jini-request,[Jini Discovery and Join Specification][Peter_Grahame_Firmstone],2015-08-27,
FF0X:0:0:0:0:0:0:157,hbmdevices,[Stephan_Gatzka],2015-10-26,
FF0X:0:0:0:0:0:0:160-FF0X:0:0:0:0:0:0:16F,NMEA OneNet,[Steve_Spitzer],2015-06-29,
FF0X:0:0:0:0:0:0:175,all SIP servers,[Rick_van_Rein],2015-07-21,
FF0X:0:0:0:0:0:0:181,PTP-primary,[http://ieee1588.nist.gov/][Kang_Lee],2007-02-02,
FF0X:0:0:0:0:0:0:182,PTP-alternate1,[http://ieee1588.nist.gov/][Kang_Lee],2007-02-02,
FF0X:0:0:0:0:0:0:183,PTP-alternate2,[http://ieee1588.nist.gov/][Kang_Lee],2007-02-02,
FF0X:0:0:0:0:0:0:184,PTP-alternate3,[http://ieee1588.nist.gov/][Kang_Lee],2007-02-02,
FF0X:0:0:0:0:0:0:18C,All ACs multicast address,[RFC5415],,
FF0X:0:0:0:0:0:0:201,"""rwho"" Group (BSD) (unofficial)",[Jon_Postel],,
FF0X:0:0:0:0:0:0:202,SUN RPC PMAPPROC_CALLIT,[Brendan_Eic],,
FF0X:0:0:0:0:0:0:204,All C1222 Nodes,[RFC6142],2009-08-28,
FF0X:0:0:0:0:0:0:205,Hexabus,[Mathias_Dalheimer],2013-08-09,
FF0X:0:0:0:0:0:0:206,multicast chat,[Patrik_Lahti],2013-08-13,
FF0X:0:0:0:0:0:0:2C0-FF0X:0:0:0:0:0:0:2FF,Garmin Marine,[Nathan_Karstens],2015-02-19,
FF0X:0:0:0:0:0:0:300,Mbus/Ipv6,[RFC3259],,
FF0X:0:0:0:0:0:0:3486,IFSF Heartbeat,[John_Carrier],2015-06-15,
FF0X:0:0:0:0:0:0:BAC0,BACnet,[Coleman_Brumley],2010-11-22,
FF0X::1:1000/118,"Service Location, Version 2",[RFC3111],,
FF0X:0:0:0:0:0:2:0000-FF0X:0:0:0:0:0:2:7FFD,Multimedia Conference Calls,[Steve_Casner],,
FF0X:0:0:0:0:0:2:7FFE,SAPv1 Announcements,[Steve_Casner],,
FF0X:0:0:0:0:0:2:7FFF,SAPv0 Announcements (deprecated),[Steve_Casner],,
FF0X:0:0:0:0:0:2:8000-FF0X:0:0:0:0:0:2:FFFF,SAP Dynamic Assignments,[Steve_Casner],,
FF0X::DB8:0:0/96,Documentation Addresses,[RFC6676],,
]==]

local function sort_ip_ascending(a, b)
  return ipOps.compare_ip(a[0], "lt", b[0])
end

local multicast_addresses = {}
local multicast_ranges = {}
do
  local starts, ends, addr, name = string.find(link_scope, "^([^,]+),([^,]+),.-\n")
  while starts do
    if string.match(addr, "[/-]") then
      local low, high, err = ipOps.get_ips_from_range(addr)
      if not low then
        stdnse.debug1("Error parsing IP range %s: %s", addr, err)
      else
        table.insert(multicast_ranges, {low, high, name})
      end
    else
      multicast_addresses[string.lower(ipOps.expand_ip(addr))] = name
    end
    starts, ends, addr, name = string.find(link_scope, "^([^,]+),([^,]+),.-\n", ends + 1)
  end

  starts, ends, addr, name = string.find(var_scope, "^([^,]+),([^,]+),.-\n")
  while starts do
    addr = string.gsub(addr, "FF0X", "FF02")
    if string.match(addr, "[/-]") then
      local low, high, err = ipOps.get_ips_from_range(addr)
      if not low then
        stdnse.debug1("Error parsing IP range %s: %s", addr, err)
      else
        table.insert(multicast_ranges, {low, high, name})
      end
    else
      multicast_addresses[string.lower(ipOps.expand_ip(addr))] = name
    end
    starts, ends, addr, name = string.find(link_scope, "^([^,]+),([^,]+),.-\n", ends + 1)
  end

  table.sort(multicast_ranges, sort_ip_ascending)
end

local function get_interfaces()
  local if_list = nmap.list_interfaces()
  local if_ret = {}
  local arg_interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

  for _, if_nfo in pairs(if_list) do
    if (arg_interface == nil or if_nfo.device == arg_interface) -- check for correct interface
      and ipOps.ip_in_range(if_nfo.address, "fe80::/10") -- link local address
      and if_nfo.link == "ethernet" then                        -- not the loopback interface
      table.insert(if_ret, if_nfo)
    end
  end

  return if_ret
end

local function single_interface_broadcast(if_nfo, results)
  stdnse.debug2("Starting " .. SCRIPT_NAME .. " on " .. if_nfo.device)
  local condvar = nmap.condvar(results)
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. '.timeout')) or 10

  local reports = multicast.mld_query(if_nfo, timeout)
  for addr, info in pairs(multicast.mld_report_addresses(reports)) do
    if results[addr] then
      stdnse.debug1("Duplicate address found: %s, interface %s", addr, info.device)
    end
    results[addr] = info
  end

  condvar("signal")
end

---
-- Calculates the solicited-node multicast address used by NDP from a unicast
-- link-local IPv6 address.
--
-- @param ll_ip String representation of a link-local IPv6 unicast address
-- @usage
-- mcast_ip = get_sol_mcast(ll_ip)
-- @return The calculated solicited-node multicast address or <code>nil</code>
-- if the given parameter is not a valid link-local address.
--
local function get_sol_mcast (ll_ip)
  -- check if address is link-local
  local is_ll, err = ipOps.ip_in_range(ll_ip, "FE80::/10")
  if not(is_ll) then
    return nil
  end
  -- calculate multicast address
  local three_bytes = string.sub(ipOps.ip_to_str(ll_ip), 14, 16)
  local thirteen_bytes = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\00\x01\xff"
  return ipOps.str_to_ip(thirteen_bytes .. three_bytes)
end

local function sorted_keys(t)
  local ret = {}
  local k, v
  -- deliberately avoiding pairs() because of __pairs metamethod in action
  repeat
    k, v = next(t, k)
    ret[#ret+1] = k
  until k == nil
  table.sort(ret, sort_ip_ascending)
  return ret
end

prerule = function()
  if not(nmap.is_privileged()) then
    stdnse.verbose1("not running for lack of privileges.")
    return false
  end
  return true
end

action = function()
  local results = {}
  local threads = {}
  local condvar = nmap.condvar(results)

  for _, if_nfo in ipairs(get_interfaces()) do
    -- create a thread for each interface
    local co = stdnse.new_thread(single_interface_broadcast, if_nfo, results)
    threads[co] = true
  end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  local guesses = {}
  local mip_metatable = {
    __tostring = function(t)
      return ("%-25s (%s)"):format(t.ip, t.description)
    end
  }
  for target_ip, info in pairs(results) do
    table.sort(info.multicast_ips, sort_ip_ascending)
    for i=1, #info.multicast_ips do
      local ip = info.multicast_ips[i]
      local t = {ip=ip}
      local tmp = string.lower(ipOps.expand_ip(ip))
      local desc = multicast_addresses[tmp]
      if not desc then
        if ipOps.compare_ip(ip, "eq", get_sol_mcast(target_ip)) then
          desc = "NDP Solicited-node"
        else
          stdnse.debug1("Addr: %s", ip)
          for j=1, #multicast_ranges do
            if ipOps.compare_ip(ip, "le", multicast_ranges[j][2]) then
              stdnse.debug1("<= %s", multicast_ranges[j][2])
              if ipOps.compare_ip(ip, "ge", multicast_ranges[j][1]) then
                stdnse.debug1(">= %s", multicast_ranges[j][1])
                desc = multicast_ranges[j][3]
              else
                stdnse.debug1("> %s", multicast_ranges[j][2])
              end
              stdnse.debug1("done %s", multicast_ranges[j][3])
              break
            end
            stdnse.debug1("> %s", multicast_ranges[j][2])
          end
        end
      end
      t.description = desc or "unknown"
      setmetatable(t, mip_metatable)
      info.multicast_ips[i] = t
    end
  end

  setmetatable(results, {
    __pairs = function(t)
      local order = sorted_keys(t)
      return coroutine.wrap(function()
        for i,k in ipairs(order) do
          coroutine.yield(k, t[k])
        end
      end)
    end
  })
  if next(results) then
    return results
  end
end
