local ipOps = require "ipOps"
local nmap = require "nmap"
local ssh1 = require "ssh1"
local stdnse = require "stdnse"
local table = require "table"
local tableaux = require "tableaux"

description = [[
Attempts to discover multihomed systems by analysing and comparing
information collected by other scripts. The information analyzed
currently includes, SSL certificates, SSH host keys, MAC addresses,
and Netbios server names.

In order for the script to be able to analyze the data it has dependencies to
the following scripts: ssl-cert,ssh-hostkey,nbtstat.

One or more of these scripts have to be run in order to allow the duplicates
script to analyze the data.
]]

---
-- @usage
-- sudo nmap -PN -p445,443 --script duplicates,nbstat,ssl-cert <ips>
--
-- @output
-- | duplicates:
-- |   ARP
-- |       MAC: 01:23:45:67:89:0a
-- |           192.168.99.10
-- |           192.168.99.11
-- |   Netbios
-- |       Server Name: WIN2KSRV001
-- |           192.168.0.10
-- |_          192.168.1.10
--


--
-- While the script provides basic duplicate functionality, here are some ideas
-- on improvements.
--
-- Possible additional information sources:
-- * Microsoft SQL Server instance names (Match hostname, version, instance
--   names and ports) - Reliable given several instances
-- * Oracle TNS names - Not very reliable
--
-- Possible enhancements:
-- * Compare hosts across information sources and create a global category
--   in which system duplicates are reported based on more than one source.
-- * Add a reliability index for each information source that indicates how
--   reliable the duplicate match was. This could be an index compared to
--   other information sources as well as an indicator of how good the match
--   was for a particular information source.

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}
dependencies = {"ssl-cert", "ssh-hostkey", "nbstat"}


hostrule = function() return true end
postrule = function() return true end

local function processSSLCerts(tab)

  -- Handle SSL-certificates
  -- We create a new table using the SHA1 digest as index
  local ssl_certs = {}
  for host, v in pairs(tab) do
    for port, sha1 in pairs(v) do
      ssl_certs[sha1] = ssl_certs[sha1] or {}
      if ( not tableaux.contains(ssl_certs[sha1], host.ip) ) then
        table.insert(ssl_certs[sha1], host.ip)
      end
    end
  end

  local results = {}
  for sha1, hosts in pairs(ssl_certs) do
    table.sort(hosts, function(a, b) return ipOps.compare_ip(a, "lt", b) end)
    if ( #hosts > 1 ) then
      table.insert(results, { name = ("Certficate (%s)"):format(sha1), hosts } )
    end
  end

  return results
end

local function processSSHKeys(tab)

  local hostkeys = {}

  -- create a reverse mapping key_fingerprint -> host(s)
  for ip, keys in pairs(tab) do
    for _, key in ipairs(keys) do
      local fp = ssh1.fingerprint_hex(key.fingerprint, key.algorithm, key.bits)
      if not hostkeys[fp] then
        hostkeys[fp] = {}
      end
      -- discard duplicate IPs
      if not tableaux.contains(hostkeys[fp], ip) then
        table.insert(hostkeys[fp], ip)
      end
    end
  end

  -- look for hosts using the same hostkey
  local results = {}
  for key, hosts in pairs(hostkeys) do
    if #hostkeys[key] > 1 then
      table.sort(hostkeys[key], function(a, b) return ipOps.compare_ip(a, "lt", b) end)
      local str = 'Key ' .. key .. ':'
      table.insert( results, { name = str, hostkeys[key] } )
    end
  end

  return results
end

local function processNBStat(tab)

  local results, mac_table, name_table = {}, {}, {}
  for host, v in pairs(tab) do
    mac_table[v.mac] = mac_table[v.mac] or {}
    if ( not(tableaux.contains(mac_table[v.mac], host.ip)) ) then
      table.insert(mac_table[v.mac], host.ip)
    end

    name_table[v.server_name] = name_table[v.server_name] or {}
    if ( not(tableaux.contains(name_table[v.server_name], host.ip)) ) then
      table.insert(name_table[v.server_name], host.ip)
    end
  end

  for mac, hosts in pairs(mac_table) do
    if ( #hosts > 1 ) then
      table.sort(hosts, function(a, b) return ipOps.compare_ip(a, "lt", b) end)
      table.insert(results, { name = ("MAC: %s"):format(mac), hosts })
    end
  end

  for srvname, hosts in pairs(name_table) do
    if ( #hosts > 1 ) then
      table.sort(hosts, function(a, b) return ipOps.compare_ip(a, "lt", b) end)
      table.insert(results, { name = ("Server Name: %s"):format(srvname), hosts })
    end
  end

  return results
end

local function processMAC(tab)

  local mac
  local mac_table = {}

  for host in pairs(tab) do
    if ( host.mac_addr ) then
      mac = stdnse.format_mac(host.mac_addr)
      mac_table[mac] = mac_table[mac] or {}
      if ( not(tableaux.contains(mac_table[mac], host.ip)) ) then
        table.insert(mac_table[mac], host.ip)
      end
    end
  end

  local results = {}
  for mac, hosts in pairs(mac_table) do
    if ( #hosts > 1 ) then
      table.sort(hosts, function(a, b) return ipOps.compare_ip(a, "lt", b) end)
      table.insert(results, { name = ("MAC: %s"):format(mac), hosts })
    end
  end

  return results
end

postaction = function()

  local handlers = {
    ['ssl-cert'] = { func = processSSLCerts, name = "SSL" },
    ['sshhostkey'] = { func = processSSHKeys, name = "SSH" },
    ['nbstat'] = { func = processNBStat, name = "Netbios" },
    ['mac'] = { func = processMAC, name = "ARP" }
  }

  -- temporary re-allocation code for SSH keys
  for k, v in pairs(nmap.registry.sshhostkey or {}) do
    nmap.registry['duplicates'] = nmap.registry['duplicates'] or {}
    nmap.registry['duplicates']['sshhostkey'] = nmap.registry['duplicates']['sshhostkey'] or {}
    nmap.registry['duplicates']['sshhostkey'][k] = v
  end

  if ( not(nmap.registry['duplicates']) ) then
    return
  end

  local results = {}
  for key, handler in pairs(handlers) do
    if ( nmap.registry['duplicates'][key] ) then
      local result_part = handler.func( nmap.registry['duplicates'][key] )
      if ( result_part and #result_part > 0 ) then
        table.insert(results, { name = handler.name, result_part } )
      end
    end
  end

  return stdnse.format_output(true, results)
end

-- we have no real action in here. In essence we move information from the
-- host based registry to the global one, so that our postrule has access to
-- it when we need it.
hostaction = function(host)

  nmap.registry['duplicates'] = nmap.registry['duplicates'] or {}

  for port, cert in pairs(host.registry["ssl-cert"] or {}) do
    nmap.registry['duplicates']['ssl-cert'] = nmap.registry['duplicates']['ssl-cert'] or {}
    nmap.registry['duplicates']['ssl-cert'][host] = nmap.registry['duplicates']['ssl-cert'][host] or {}
    nmap.registry['duplicates']['ssl-cert'][host][port] = stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

  if ( host.registry['nbstat'] ) then
    nmap.registry['duplicates']['nbstat'] = nmap.registry['duplicates']['nbstat'] or {}
    nmap.registry['duplicates']['nbstat'][host] = host.registry['nbstat']
  end

  if ( host.mac_addr_src ) then
    nmap.registry['duplicates']['mac'] = nmap.registry['duplicates']['mac'] or {}
    nmap.registry['duplicates']['mac'][host] = true
  end

  return
end

local Actions = {
  hostrule = hostaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
