local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks if a host is infected with Conficker.C or higher, based on
Conficker's peer to peer communication.

When Conficker.C or higher infects a system, it opens four ports: two TCP
and two UDP. The ports are random, but are seeded with the current week and
the IP of the infected host. By determining the algorithm, one can check if
these four ports are open, and can probe them for more data.

Once the open ports are found, communication can be initiated using
Conficker's custom peer to peer protocol.  If a valid response is received,
then a valid Conficker infection has been found.

This check won't work properly on a multihomed or NATed system because the
open ports will be based on a nonpublic IP.  The argument
<code>checkall</code> tells Nmap to attempt communication with every open
port (much like a version check) and the argument <code>realip</code> tells
Nmap to base its port generation on the given IP address instead of the
actual IP.

By default, this will run against a system that has a standard Windows port
open (445, 139, 137). The arguments <code>checkall</code> and
<code>checkconficker</code> will both perform checks regardless of which
port is open, see the args section for more information.

Note: Ensure your clock is correct (within a week) before using this script!

The majority of research for this script was done by Symantec Security
Response, and some was taken from public sources (most notably the port
blacklisting was found by David Fifield). A big thanks goes out to everybody
who contributed!
]]

---
-- @args checkall If set to <code>1</code> or <code>true</code>, attempt
-- to communicate with every open port.
-- @args checkconficker If set to <code>1</code> or <code>true</code>, the script will always run on active hosts,
--       it doesn't matter if any open ports were detected.
-- @args realip An IP address to use in place of the one known by Nmap.
--
-- @usage
-- # Run the scripts against host(s) that appear to be Windows
-- nmap --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=safe=1 -T4 -vv -p445 <host>
-- sudo nmap -sU -sS --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=safe=1 -vv -T4 -p U:137,T:139 <host>
--
-- # Run the scripts against all active hosts (recommended)
-- nmap -p139,445 -vv --script p2p-conficker,smb-os-discovery,smb-check-vulns --script-args=checkconficker=1,safe=1 -T4 <host>
--
-- # Run scripts against all 65535 ports (slow)
-- nmap --script p2p-conficker,smb-os-discovery,smb-check-vulns -p- --script-args=checkall=1,safe=1 -vv -T4 <host>
--
-- # Base checks on a different ip address (NATed)
-- nmap --script p2p-conficker,smb-os-discovery -p445 --script-args=realip=\"192.168.1.65\" -vv -T4 <host>
--
-- @output
-- Clean machine (results printed only if extra verbosity ("-vv")is specified):
-- Host script results:
-- | p2p-conficker: Checking for Conficker.C or higher...
-- |   Check 1 (port 44329/tcp): CLEAN (Couldn't connect)
-- |   Check 2 (port 33824/tcp): CLEAN (Couldn't connect)
-- |   Check 3 (port 31380/udp): CLEAN (Failed to receive data)
-- |   Check 4 (port 52600/udp): CLEAN (Failed to receive data)
-- |_  0/4 checks: Host is CLEAN or ports are blocked
--
-- Infected machine (results always printed):
-- Host script results:
-- | p2p-conficker: Checking for Conficker.C or higher...
-- |   Check 1 (port 18707/tcp): INFECTED (Received valid data)
-- |   Check 2 (port 65273/tcp): INFECTED (Received valid data)
-- |   Check 3 (port 11722/udp): INFECTED (Received valid data)
-- |   Check 4 (port 12690/udp): INFECTED (Received valid data)
-- |_  4/4 checks: Host is likely INFECTED
--
-----------------------------------------------------------------------

author = "Ron Bowes (with research from Symantec Security Response)"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default","safe"}


-- Max packet size
local MAX_PACKET = 0x2000

-- Flags
local mode_flags =
{
  FLAG_MODE              = 1 << 0,
  FLAG_LOCAL_ACK         = 1 << 1,
  FLAG_IS_TCP            = 1 << 2,
  FLAG_IP_INCLUDED       = 1 << 3,
  FLAG_UNKNOWN0_INCLUDED = 1 << 4,
  FLAG_UNKNOWN1_INCLUDED = 1 << 5,
  FLAG_DATA_INCLUDED     = 1 << 6,
  FLAG_SYSINFO_INCLUDED  = 1 << 7,
  FLAG_ENCODED           = 1 << 15,
}

---For a hostrule, simply use the 'smb' ports as an indicator, unless the user overrides it
hostrule = function(host)
  if ( nmap.address_family() ~= 'inet' ) then
    return false
  end
  if(smb.get_port(host) ~= nil) then
    return true
  elseif(nmap.registry.args.checkall == "true" or nmap.registry.args.checkall == "1") then
    return true
  elseif(nmap.registry.args.checkconficker == "true" or nmap.registry.args.checkconficker == "1") then
    return true
  end

  return false
end

-- Multiply two 32-bit integers and return a 64-bit product. The first return
-- value is the low-order 32 bits of the product and the second return value is
-- the high-order 32 bits.
--
--@param u First number (0 <= u <= 0xFFFFFFFF)
--@param v Second number (0 <= v <= 0xFFFFFFFF)
--@return 64-bit product of u*v, as a pair of 32-bit integers.
local function mul64(u, v)
  -- This is based on formula (2) from section 4.3.3 of The Art of
  -- Computer Programming. We split u and v into upper and lower 16-bit
  -- chunks, such that
  --   u = 2**16 u1 + u0    and    v = 2**16 v1 + v0
  -- Then
  --   u v = (2**16 u1 + u0) * (2**16 v1 + v0)
  --       = 2**32 u1 v1 + 2**16 (u0 v1 + u1 v0) + u0 v0
  assert(0 <= u and u <= 0xFFFFFFFF)
  assert(0 <= v and v <= 0xFFFFFFFF)
  local u0, u1 = (u & 0xFFFF), (u >> 16)
  local v0, v1 = (v & 0xFFFF), (v >> 16)
  -- t uses at most 49 bits, which is within the range of exact integer
  -- precision of a Lua number.
  local t = u0 * v0 + (u0 * v1 + u1 * v0) * 65536
  return (t & 0xFFFFFFFF), u1 * v1 + (t >> 32)
end

---Rotates the 64-bit integer defined by h:l left by one bit.
--
--@param h The high-order 32 bits
--@param l The low-order 32 bits
--@return 64-bit rotated integer, as a pair of 32-bit integers.
local function rot64(h, l)
  local i

  assert(0 <= h and h <= 0xFFFFFFFF)
  assert(0 <= l and l <= 0xFFFFFFFF)

  local tmp = h & 0x80000000
  h = h << 1
  h = h | (l >> 31)
  l = l << 1
  if tmp ~= 0 then
    l = l | 1
  end

  h = h & 0xFFFFFFFF
  l = l & 0xFFFFFFFF

  return h, l
end


---Check if a port is Blacklisted. Thanks to David Fifield for determining the purpose of the "magic"
-- array:
-- <http://www.bamsoftware.com/wiki/Nmap/PortSetGraphics#conficker>
--
-- Basically, each bit in the blacklist array represents a group of 32 ports. If that bit is on, those ports
-- are blacklisted and will never come up.
--
--@param port The port to check
--@return true if the port is blacklisted, false otherwise
local function is_blacklisted_port(port)
  local r, l

  local blacklist = { 0xFFFFFFFF, 0xFFFFFFFF, 0xF0F6BFBB, 0xBB5A5FF3,
    0xF3977011, 0xEB67BFBF, 0x5F9BFAC8, 0x34D88091, 0x1E2282DF, 0x573402C4,
    0xC0000084, 0x03000209, 0x01600002, 0x00005000, 0x801000C0, 0x00500040,
    0x000000A1, 0x01000000, 0x01000000, 0x00022A20, 0x00000080, 0x04000000,
    0x40020000, 0x88000000, 0x00000180, 0x00081000, 0x08801900, 0x00800B81,
    0x00000280, 0x080002C0, 0x00A80000, 0x00008000, 0x00100040, 0x00100000,
    0x00000000, 0x00000000, 0x10000008, 0x00000000, 0x00000000, 0x00000004,
    0x00000002, 0x00000000, 0x00040000, 0x00000000, 0x00000000, 0x00000000,
    0x00410000, 0x82000000, 0x00000000, 0x00000000, 0x00000001, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008, 0x80000000,
  }

  r = port >> 5
  l = 1 << (r & 0x1f)
  r = r >> 5

  return blacklist[r + 1] & l ~= 0
end

---Generates the four random ports that Conficker uses, based on the current time and the IP address.
--
--@param ip The IP address as a 32-bit little endian integer
--@param seed The seed, based on the time (<code>floor((time - 345600) / 604800)</code>)
--@return An array of four ports; the first and third are TCP, and the second and fourth are UDP.
local function prng_generate_ports(ip, seed)
  local ports = {0, 0, 0, 0}
  local v1, v2
  local port1, port2, shift1, shift2
  local i
  local magic = 0x015A4E35

  stdnse.debug1("Conficker: Generating ports based on ip (0x%08x) and seed (%d)", ip, seed)

  v1 = -(ip + 1)
  repeat
    -- Loop 10 times to generate the first pair of ports
    for i = 0, 9, 1 do
      v1, v2 = mul64(v1 & 0xFFFFFFFF, magic & 0xFFFFFFFF)

      -- Add 1 to v1, handling overflows
      if(v1 ~= 0xFFFFFFFF) then
        v1 = v1 + 1
      else
        v1 = 0
        v2 = v2 + 1
      end

      v2 = v2 >> i

      ports[(i % 2) + 1] = (v2 & 0xFFFF) ~ ports[(i % 2) + 1]
    end
  until(is_blacklisted_port(ports[1]) == false and is_blacklisted_port(ports[2]) == false and ports[1] ~= ports[2])

  -- Update the accumulator with the seed
  v1 = v1 ~ seed

  -- Loop 10 more times to generate the second pair of ports
  repeat
    for i = 0, 9, 1 do
      v1, v2 = mul64(v1 & 0xFFFFFFFF, magic & 0xFFFFFFFF)

      -- Add 1 to v1, handling overflows
      if(v1 ~= 0xFFFFFFFF) then
        v1 = v1 + 1
      else
        v1 = 0
        v2 = v2 + 1
      end

      v2 = v2 >> i

      ports[(i % 2) + 3] = (v2 & 0xFFFF) ~ ports[(i % 2) + 3]
    end
  until(is_blacklisted_port(ports[3]) == false and is_blacklisted_port(ports[4]) == false and ports[3] ~= ports[4])

  return {ports[1], ports[2], ports[3], ports[4]}
end

---Calculate a checksum for the data. This checksum is appended to every Conficker packet before the random noise.
-- The checksum includes the key and data, but not the noise and optional length.
--
--@param data The data to create a checksum for.
--@return An integer representing the checksum.
local function p2p_checksum(data)
  local hash = #data

  stdnse.debug2("Conficker: Calculating checksum for %d-byte buffer", #data)

  data:gsub(".", function(i)
      local h = hash ~ string.byte(i)
      -- Incorporate the current character into the checksum
      hash = (h + h) | (h >> 31)
      hash = hash & 0xFFFFFFFF
    end
    )

  return hash
end

---Encrypt/decrypt the buffer with a simple xor-based symmetric encryption. It uses a 64-bit key, represented
-- by key1:key2, that is transmitted in plain text. Since sniffed packets can be decrypted, this is a
-- simple obfuscation technique.
--
--@param packet The packet to encrypt (before the key and optional length are prepended).
--@param key1 The low-order 32 bits in the key.
--@param key2 The high-order 32 bits in the key.
--@return The encrypted (or decrypted) data.
local function p2p_cipher(packet, key1, key2)
  local i
  local buf = {}

  for i = 1, #packet, 1 do
    -- Do a 64-bit rotate on key1:key2
    key2, key1 = rot64(key2, key1)

    -- Generate the key (the right-most byte)
    local k = key1 & 0x0FF

    -- Xor the current character and add it to the encrypted buffer
    buf[i] = string.char(string.byte(packet, i) ~ k)

    -- Update the key with 'k'
    key1 = key1 + k
    if(key1 > 0xFFFFFFFF) then
      -- Handle overflows
      key2 = key2 + (key1 >> 32)
      key2 = key2 & 0xFFFFFFFF
      key1 = key1 & 0xFFFFFFFF
    end
  end

  return table.concat(buf)
end

---Decrypt the packet, verify it, and parse it. This function will fail with an error if the packet can't be
-- parsed properly (likely means the port is being used for something else), but will return successfully
-- without checking the packet's checksum (although it does calculate the checksum). It's up to the calling
-- function to decide if it cares about the checksum.
--
--@param packet The packet, without the optional length (if it's TCP).
--@return (status, result) If status is true, result is a table (including 'hash' and 'real_hash'). If status
--        is false, result is a string that indicates why the parse failed.
function p2p_parse(packet)
  local pos = 1
  local data = {}

  -- Get the key
  if #packet < 8 then
    return false, "Packet was too short [1]"
  end
  data['key1'], data['key2'], pos = string.unpack("<I4 I4", packet, pos)

  -- Decrypt the second half of the packet using the key
  packet = string.sub(packet, 1, pos - 1) .. p2p_cipher(string.sub(packet, pos), data['key1'], data['key2'])

  -- Parse the flags
  if #packet - pos + 1 < 2 then
    return false, "Packet was too short [2]"
  end
  data['flags'], pos = string.unpack("<I2", packet, pos)

  -- Get the IP, if it's present
  if(data['flags'] & mode_flags.FLAG_IP_INCLUDED) ~= 0 then
    if #packet - pos + 1 < 6 then
      return false, "Packet was too short [3]"
    end
    data['ip'], data['port'], pos = string.unpack("<I4 I2", packet, pos)
  end

  -- Read the first unknown value, if present
  if(data['flags'] & mode_flags.FLAG_UNKNOWN0_INCLUDED) ~= 0 then
    if #packet - pos + 1 < 4 then
      return false, "Packet was too short [3]"
    end
    data['unknown0'], pos = string.unpack("<I4", packet, pos)
  end

  -- Read the second unknown value, if present
  if(data['flags'] & mode_flags.FLAG_UNKNOWN1_INCLUDED) ~= 0 then
    if #packet - pos + 1 < 4 then
      return false, "Packet was too short [4]"
    end
    data['unknown1'], pos = string.unpack("<I4", packet, pos)
  end

  -- Read the data, if present
  if(data['flags'] & mode_flags.FLAG_DATA_INCLUDED) ~= 0 then
    if #packet - pos + 1 < 3 then
      return false, "Packet was too short [5]"
    end
    data['data_flags'], data['data_length'], pos = string.unpack("<B I2", packet, pos)
    if #packet - pos + 1 < data.data_length then
      return false, "Packet was too short [6]"
    end
    data['data'], pos = string.unpack(("c%d"):format(data['data_length']), packet, pos)
  end

  -- Read the sysinfo, if present
  if(data['flags'] & mode_flags.FLAG_SYSINFO_INCLUDED) ~= 0 then
    local sysinfo_format = "<I2 BBI2 BB I2 I4 I2I2I4I2I2"
    if #packet - pos + 1 < string.packsize(sysinfo_format) then
      return false, "Packet was too short [7]"
    end

    data['sysinfo_systemtestflags'],
    data['sysinfo_os_major'],
    data['sysinfo_os_minor'],
    data['sysinfo_os_build'],
    data['sysinfo_os_servicepack_major'],
    data['sysinfo_os_servicepack_minor'],
    data['sysinfo_ntdll_translation_file_information'],
    data['sysinfo_prng_sample'],
    data['sysinfo_unknown0'],
    data['sysinfo_unknown1'],
    data['sysinfo_unknown2'],
    data['sysinfo_unknown3'],
    data['sysinfo_unknown4'], pos = string.unpack(sysinfo_format, packet, pos)
  end

  -- Pull out the data that's used in the hash
  data['hash_data'] = string.sub(packet, 1, pos - 1)

  -- Read the hash
  if #packet - pos + 1 < 4 then
    return false, "Packet was too short [8]"
  end
  data['hash'], pos = string.unpack("<I4", packet, pos)

  -- Record the noise
  data['noise'] = string.sub(packet, pos)

  -- Generate the actual hash (we're going to ignore it for now, but it can be checked higher up)
  data['real_hash'] = p2p_checksum(data['hash_data'])

  return true, data
end

---Create a peer to peer packet for the given protocol.
--
--@param protocol The protocol (either 'tcp' or 'udp' -- tcp packets have a length in front, and an extra
--       flag)
--@param do_encryption (optional) If set to false, packets aren't encrypted (the key '0' is used). Useful
--       for testing. Default: true.
local function p2p_create_packet(protocol, do_encryption)
  assert(protocol == "tcp" or protocol == "udp")

  local key1 = math.random(1, 0x7FFFFFFF)
  local key2 = math.random(1, 0x7FFFFFFF)

  -- A key of 0 disables the encryption
  if(do_encryption == false) then
    key1 = 0
    key2 = 0
  end

  local flags = 0

  -- Set a couple flags that we need (we don't send any optional data)
  flags = flags | mode_flags.FLAG_MODE
  flags = flags | mode_flags.FLAG_ENCODED
  --  flags = flags | mode_flags.FLAG_LOCAL_ACK)
  -- Set the special TCP flag
  if(protocol == "tcp") then
    flags = flags | mode_flags.FLAG_IS_TCP
  end

  -- Add the key and flags that are always present (and skip over the boring stuff)
  local packet = string.pack("<I4 I4 I2", key1, key2, flags)

  -- Generate the checksum for the packet
  local hash = p2p_checksum(packet)
  packet = packet .. string.pack("<I4", hash)

  -- Encrypt the full packet, except for the key and optional length
  packet = string.sub(packet, 1, 8) .. p2p_cipher(string.sub(packet, 9), key1, key2)

  -- Add the length in front if it's TCP
  if(protocol == "tcp") then
    packet = string.pack("<s2", packet)
  end

  return true, packet
end

---Checks if conficker is present on the given port/protocol. The ports Conficker uses are fairly standard, so
-- those should generally be used for this check. This can also be sent to any open port on the system.
--
--@param ip The ip address of the system to check
--@param port The port to check (can be taken from <code>prng_generate_ports</code>, or from unidentified ports)
--@return (status, reason, data) Status indicates whether or not Conficker is suspected to be present (<code>true</code) =
--        Conficker, <code>false</code> = no Conficker). If status is true, data is the table of information returned by
--        Conficker.
local function conficker_check(ip, port, protocol)
  local status, packet
  local socket
  local response

  status, packet = p2p_create_packet(protocol)
  if(status == false) then
    return false, packet
  end

  -- Try to connect to the first socket
  socket = nmap.new_socket()
  socket:set_timeout(5000)
  status, response = socket:connect(ip, port, protocol)
  if(status == false) then
    return false, "Couldn't establish connection (" .. response .. ")"
  end

  -- Send the packet
  socket:send(packet)

  -- Read a response (2 bytes minimum, because that's the TCP length)
  status, response = socket:receive_bytes(2)
  if(status == false) then
    return false, "Couldn't receive bytes: " .. response
  elseif(response == "ERROR") then
    return false, "Failed to receive data"
  elseif(response == "TIMEOUT") then
    return false, "Timeout"
  elseif(response == "EOF") then
    return false, "Couldn't connect"
  elseif #response < 2 then
    return false, "Data too short"
  end

  -- If it's TCP, get the length and make sure we have the full packet
  if(protocol == "tcp") then
    local length = string.unpack("<I2", response)

    -- Only try for 2 timeouts to get the whole packet
    local tries = 2
    while length > (#response - 2) and tries > 0 do
      tries = tries - 1

      local status, response2 = socket:receive_bytes(length - (#response - 2))
      if(status == false) then
        return false, "Couldn't receive bytes: " .. response2
      elseif(response2 == "ERROR") then
        return false, "Failed to receive data"
      elseif(response2 == "TIMEOUT") then
        return false, "Timeout"
      elseif(response2 == "EOF") then
        return false, "Couldn't connect"
      end

      response = response .. response2
    end

    -- Remove the 'length' bytes
    response = string.sub(response, 3)
  end

  -- Close the socket
  socket:close()

  local status, result = p2p_parse(response)

  if(status == false) then
    return false, "Data received, but wasn't Conficker data: " .. result
  end

  if(result['hash'] ~= result['real_hash']) then
    return false, "Data received, but checksum was invalid (possibly INFECTED)"
  end

  return true, "Received valid data", result
end

action = function(host)
  local tcp_ports = {}
  local udp_ports = {}
  local response = {}
  local i
  local port, protocol
  local count = 0
  local checks = 0

  -- Generate a complete list of valid ports
  if(nmap.registry.args.checkall == "true" or nmap.registry.args.checkall == "1") then
    for i = 1, 65535, 1 do
      if(not(is_blacklisted_port(i))) then
        local tcp = nmap.get_port_state(host, {number=i, protocol="tcp"})
        if(tcp ~= nil and tcp.state == "open") then
          tcp_ports[i] = true
        end

        local udp = nmap.get_port_state(host, {number=i, protocol="udp"})
        if(udp ~= nil and (udp.state == "open" or udp.state == "open|filtered")) then
          udp_ports[i] = true
        end
      end
    end
  end


  -- Generate ports based on the ip and time
  local seed = math.floor((os.time() - 345600) / 604800)
  local ip = host.ip

  -- Use the provided IP, if it exists
  if(nmap.registry.args.realip ~= nil) then
    ip = nmap.registry.args.realip
  end

  -- Reverse the IP's endianness
  ip = ipOps.todword(ip)
  ip = string.pack(">I4", ip)
  ip = string.unpack("<I4", ip)

  -- Generate the ports
  local generated_ports = prng_generate_ports(ip, seed)
  tcp_ports[generated_ports[1]] = true
  tcp_ports[generated_ports[3]] = true
  udp_ports[generated_ports[2]] = true
  udp_ports[generated_ports[4]] = true

  table.insert(response, "Checking for Conficker.C or higher...")

  -- Check the TCP ports
  for port in pairs(tcp_ports) do
    local status, reason

    status, reason = conficker_check(host.ip, port, "tcp")
    checks = checks + 1

    if(status == true) then
      table.insert(response, string.format("Check %d (port %d/%s): INFECTED (%s)", checks, port, "tcp", reason))
      count = count + 1
    else
      table.insert(response, string.format("Check %d (port %d/%s): CLEAN (%s)", checks, port, "tcp", reason))
    end
  end

  -- Check the UDP ports
  for port in pairs(udp_ports) do
    local status, reason

    status, reason = conficker_check(host.ip, port, "udp")
    checks = checks + 1

    if(status == true) then
      table.insert(response, string.format("Check %d (port %d/%s): INFECTED (%s)", checks, port, "udp", reason))
      count = count + 1
    else
      table.insert(response, string.format("Check %d (port %d/%s): CLEAN (%s)", checks, port, "udp", reason))
    end
  end

  -- Check how many INFECTED hits we got
  if(count == 0) then
    if (nmap.verbosity() > 1) then
      table.insert(response, string.format("%d/%d checks are positive: Host is CLEAN or ports are blocked", count, checks))
    else
      response = ''
    end
  else
    table.insert(response, string.format("%d/%d checks are positive: Host is likely INFECTED", count, checks))
  end

  return stdnse.format_output(true, response)
end

