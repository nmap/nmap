description = [[
Shows SSH hostkeys.

Shows the target SSH server's key fingerprint and (with high enough verbosity level) the public key itself.  It records the discovered host keys in <code>nmap.registry</code> for use by other scripts.  Output can be controlled with the <code>ssh_hostkey</code> script argument.
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
author = "Sven Klemm"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","default","intrusive"}

require("shortport")
require("stdnse")

-- openssl is required for this script
if pcall(require,"openssl") then
  require("ssh1")
  require("ssh2")
else
  portrule = function() return false end
  action = function() end
  stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.", filename )
  return;
end

portrule = shortport.port_or_service(22, "ssh")


--- put hostkey in the nmap registry for usage by other scripts
--@param host nmap host table
--@param key host key table
local add_key_to_registry = function( host, key )
  nmap.registry.sshhostkey = nmap.registry.sshhostkey or {}
  nmap.registry.sshhostkey[host.ip] = nmap.registry.sshhostkey[host.ip] or {}
  table.insert( nmap.registry.sshhostkey[host.ip], key )
end

action = function(host, port)
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

