local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks if a target on a local Ethernet has its network card in promiscuous mode.

The techniques used are described at
http://www.securityfriday.com/promiscuous_detection_01.pdf.
]]

---
-- @output
-- Host script results:
-- |_ sniffer-detect: Likely in promiscuous mode (tests: "11111111")


author = "Marek Majkowski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive"}

-- okay, we're interested only in hosts that are on our ethernet lan
hostrule = function(host)
  if nmap.address_family() ~= 'inet' then
    stdnse.debug1("is IPv4 compatible only.")
    return false
  end
  if host.directly_connected == true and
      host.mac_addr ~= nil and
      host.mac_addr_src ~= nil and
      host.interface ~= nil then
    local iface = nmap.get_interface_info(host.interface)
    if iface and iface.link == 'ethernet' then
      return true
    end
  end
  return false
end

local function check (layer2)
  return string.sub(layer2, 0, 12)
end


do_test = function(dnet, pcap, host, test)
  local status, length, layer2, layer3
  local i = 0

  -- ARP requests are send with timeouts: 10ms, 40ms, 90ms
  -- before each try, we wait at least 100ms
  -- in summary, this test takes at least 100ms and at most 440ms
  for i=1,3 do
    -- flush buffers :), wait quite long.
    repeat
      pcap:set_timeout(100)
      local test = host.mac_addr_src .. host.mac_addr
      status, length, layer2, layer3 = pcap:pcap_receive()
      while status and test ~= check(layer2) do
        status, length, layer2, layer3 = pcap:pcap_receive()
      end
    until status ~= true
    pcap:set_timeout(10 * i*i)

    dnet:ethernet_send(test)

    local test = host.mac_addr_src .. host.mac_addr
    status, length, layer2, layer3 = pcap:pcap_receive()
    while status and test ~= check(layer2) do
      status, length, layer2, layer3 = pcap:pcap_receive()
    end
    if status == true then
      -- the basic idea, was to inform user about time, when we got packet
      -- so that 1 would mean (0-10ms), 2=(10-40ms) and 3=(40ms-90ms)
      -- but when we're running this tests on macs, first test is always 2.
      -- which means that the first answer is dropped.
      -- for now, just return 1 if test was successful, it's easier
      -- return(i)
      return(1)
    end
  end
  return('_')
end

action = function(host)
  local dnet = nmap.new_dnet()
  local pcap = nmap.new_socket()
  local _
  local status
  local results = {
    ['1_____1_'] = false, -- MacOSX(Tiger.Panther)/Linux/ ?Win98/ WinXP sp2(no pcap)
    ['1_______'] = false, -- Old Apple/SunOS/3Com
    ['1___1_1_'] = false, -- MacOSX(Tiger)
    ['11111111'] = true,  -- BSD/Linux/OSX/     (or not promiscuous openwrt )
    ['1_1___1_'] = false, -- WinXP sp2 + pcap|| win98 sniff || win2k sniff (see below)
    ['111___1_'] = true,  -- WinXP sp2 promisc
    --['1111__1_'] = true,  -- ?Win98 promisc + ??win98 no promisc *not confirmed*
  }
  dnet:ethernet_open(host.interface)

  pcap:pcap_open(host.interface, 64, false, "arp")

  local test_static = host.mac_addr_src ..
    "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01" ..
    host.mac_addr_src ..
    host.bin_ip_src ..
    "\x00\x00\x00\x00\x00\x00" ..
    host.bin_ip
  local t = {
    "\xff\xff\xff\xff\xff\xff", -- B32 no meaning?
    "\xff\xff\xff\xff\xff\xfe", -- B31
    "\xff\xff\x00\x00\x00\x00", -- B16
    "\xff\x00\x00\x00\x00\x00", -- B8
    "\x01\x00\x00\x00\x00\x00", -- G
    "\x01\x00\x5e\x00\x00\x00", -- M0
    "\x01\x00\x5e\x00\x00\x01", -- M1 no meaning?
    "\x01\x00\x5e\x00\x00\x03", -- M3
  }
  local v
  local out = {}
  for _, v in ipairs(t) do
    out[#out+1] = do_test(dnet, pcap, host, v .. test_static)
  end
  out = table.concat(out)

  dnet:ethernet_close()
  pcap:pcap_close()

  if out == '1_1___1_' then
    return 'Windows with libpcap installed; may or may not be sniffing (tests: "' .. out .. '")'
  end
  if results[out] == false then
    -- probably not sniffing
    return
  end
  if results[out] == true then
    -- rather sniffer.
    return 'Likely in promiscuous mode (tests: "' .. out .. '")'
  end

  -- results[out] == nil
  return 'Unknown (tests: "' .. out .. '")'
end
