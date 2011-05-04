description = [[
Shows SSH hostkeys.

Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key itself.  It records the discovered host keys in <code>nmap.registry</code> for use by other scripts.  Output can be controlled with the <code>ssh_hostkey</code> script argument.

The script also includes a postrule that check for duplicate hosts using the gathered keys.
]]

---
--@usage
-- nmap host --script SSH-hostkey --script-args ssh_hostkey=full
-- nmap host --script SSH-hostkey --script-args ssh_hostkey=all
-- nmap host --script SSH-hostkey --script-args ssh_hostkey='visual bubble'
--
--@args ssh_hostkey Controls the output format of keys. Multiple values may be
-- given, separated by spaces. Possible values are
-- * <code>"full"</code>: The entire key, not just the fingerprint.
-- * <code>"bubble"</code>: Bubble Babble output,
-- * <code>"visual"</code>: Visual ASCII art representation.
-- * <code>"all"</code>: All of the above.
--
--@output
-- 22/tcp open  ssh
-- |  ssh-hostkey: 2048 f0:58:ce:f4:aa:a4:59:1c:8e:dd:4d:07:44:c8:25:11 (RSA)
-- 22/tcp open  ssh
-- |  ssh-hostkey: 2048 f0:58:ce:f4:aa:a4:59:1c:8e:dd:4d:07:44:c8:25:11 (RSA)
-- |  +--[ RSA 2048]----+
-- |  |       .E*+      |
-- |  |        oo       |
-- |  |      . o .      |
-- |  |       O . .     |
-- |  |      o S o .    |
-- |  |     = o + .     |
-- |  |    . * o .      |
-- |  |     = .         |
-- |  |    o .          |
-- |_ +-----------------+
-- 22/tcp open  ssh
-- |  ssh-hostkey: 2048 xuvah-degyp-nabus-zegah-hebur-nopig-bubig-difeg-hisym-rumef-cuxex (RSA)
-- |_ ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVuv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lUx5tTA+vefXUWEMxgMuA7iX4irJHy2zer0NQ3Z3yJvr5scPgTYIaEOp5Uo/eGFG9Agpk5wE8CoF0e47iCAPHqzlmP2V7aNURLMODb3jVZuI07A2ZRrMGrD8d888E2ORVORv1rYeTYCqcMMoVFmX9l3gWEdk4yx3w5sD8v501Iuyd1v19mPfyhrI5E1E1nl/Xjp5N0/xP2GUBrdkDMxKaxqTPMie/f0dXBUPQQN697a5q+5lBRPhKYOtn6yQKCd9s1Q22nxn72Jmi1RzbMyYJ52FosDT755Qmb46GLrDMaZMQ==
--
--@output
-- Post-scan script results:
-- | ssh-hostkey: Possible duplicate hosts
-- | Key 1024 60:ac:4d:51:b1:cd:85:09:12:16:92:76:1d:5d:27:6e (DSA) used by:
-- |   192.168.1.1
-- |   192.168.1.2
-- | Key 2048 2c:22:75:60:4b:c3:3b:18:a2:97:2c:96:7e:28:dc:dd (RSA) used by:
-- |   192.168.1.1
-- |_  192.168.1.2
--

author = "Sven Klemm"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","default","discovery"}

require("shortport")
require("stdnse")
require("openssl")
require("ssh1")
require("ssh2")

portrule = shortport.port_or_service(22, "ssh")

postrule = function() return (nmap.registry.sshhostkey ~= nil) end

--- put hostkey in the nmap registry for usage by other scripts
--@param host nmap host table
--@param key host key table
local add_key_to_registry = function( host, key )
  nmap.registry.sshhostkey = nmap.registry.sshhostkey or {}
  nmap.registry.sshhostkey[host.ip] = nmap.registry.sshhostkey[host.ip] or {}
  table.insert( nmap.registry.sshhostkey[host.ip], key )
end

--- gather host keys
--@param host nmap host table
--@param port nmap port table of the currently probed port
local function portaction(host, port)
  local output = {}
  local keys = {}
  local _,key
  local format = nmap.registry.args.ssh_hostkey or "hex"
  local all_formats = format:find( 'all', 1, true )

  key = ssh1.fetch_host_key( host, port )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ssh-dss" )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ssh-rsa" )
  if key then table.insert( keys, key ) end

  for _, key in ipairs( keys ) do
    add_key_to_registry( host, key )
    if format:find( 'hex', 1, true ) or all_formats then
      table.insert( output, ssh1.fingerprint_hex( key.fingerprint, key.algorithm, key.bits ) )
    end
    if format:find( 'bubble', 1, true ) or all_formats then
      table.insert( output, ssh1.fingerprint_bubblebabble( openssl.sha1(key.fp_input), key.algorithm, key.bits ) )
    end
    if format:find( 'visual', 1, true ) or all_formats then
      -- insert empty line so table is not destroyed if this is the first
      -- line of output
      if #output == 0 then table.insert( output, " " ) end
      table.insert( output, ssh1.fingerprint_visual( key.fingerprint, key.algorithm, key.bits ) )
    end
    if nmap.verbosity() > 1 or format:find( 'full', 1, true ) or all_formats then
      table.insert( output, key.full_key )
    end
  end

  if #output > 0 then
    return table.concat( output, '\n' )
  end
end

--- check for the presence of a value in a table
--@param tab the table to search into
--@param item the searched value
--@return a boolean indicating whether the value has been found or not
local function contains(tab, item)
  for _, val in pairs(tab) do
    if val == item then
      return true
    end
  end
  return false
end

--- iterate over the list of gathered keys and look for duplicate hosts (sharing the same hostkeys)
local function postaction()
  local hostkeys = {}
  local output = {}

  -- create a reverse mapping key_fingerprint -> host(s)
  for ip, keys in pairs(nmap.registry.sshhostkey) do
    for _, key in ipairs(keys) do
      local fp = ssh1.fingerprint_hex(key.fingerprint, key.algorithm, key.bits)
      if not hostkeys[fp] then
        hostkeys[fp] = {}
      end
      -- discard duplicate IPs
      if not contains(hostkeys[fp], ip) then
        table.insert(hostkeys[fp], ip)
      end
    end
  end

  -- look for hosts using the same hostkey
  for key, hosts in pairs(hostkeys) do
    if #hostkeys[key] > 1 then
      local str = 'Key ' .. key .. ' used by:'
      for _, host in ipairs(hostkeys[key]) do
        str = str .. '\n  ' .. host
      end
      table.insert(output, str)
    end
  end

  if #output > 0 then
    return 'Possible duplicate hosts\n' .. table.concat(output, '\n')
  end
end

local ActionsTable = {
  -- portrule: retrieve ssh hostkey
  portrule = portaction,
  -- postrule: look for duplicate hosts (same hostkey)
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end

