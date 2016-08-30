local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local ssh1 = require "ssh1"
local ssh2 = require "ssh2"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local base64 = require "base64"
local comm = require "comm"

local openssl = stdnse.silent_require "openssl"

description = [[
Shows SSH hostkeys.

Shows the target SSH server's key fingerprint and (with high enough
verbosity level) the public key itself.  It records the discovered host keys
in <code>nmap.registry</code> for use by other scripts.  Output can be
controlled with the <code>ssh_hostkey</code> script argument.

You may also compare the retrieved key with the keys in your known-hosts
file using the <code>known-hosts</code> argument.

The script also includes a postrule that check for duplicate hosts using the
gathered keys.
]]

---
--@usage
-- nmap host --script ssh-hostkey --script-args ssh_hostkey=full
-- nmap host --script ssh-hostkey --script-args ssh_hostkey=all
-- nmap host --script ssh-hostkey --script-args ssh_hostkey='visual bubble'
--
--@args ssh_hostkey Controls the output format of keys. Multiple values may be
-- given, separated by spaces. Possible values are
-- * <code>"full"</code>: The entire key, not just the fingerprint.
-- * <code>"bubble"</code>: Bubble Babble output,
-- * <code>"visual"</code>: Visual ASCII art representation.
-- * <code>"all"</code>: All of the above.
-- @args ssh-hostkey.known-hosts If this is set, the script will check if the
-- known hosts file contains a key for the host being scanned and will compare
-- it with the keys that have been found by the script. The script will try to
-- detect your known-hosts file but you can, optionally, pass the path of the
-- file to this option.
--
-- @args ssh-hostkey.known-hosts-path. Path to a known_hosts file.
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
-- 22/tcp open  ssh     syn-ack
-- | ssh-hostkey: Key comparison with known_hosts file:
-- |   GOOD Matches in known_hosts file:
-- |       L7: 199.19.117.60
-- |       L11: foo
-- |       L15: bar
-- |       L19: <unknown>
-- |   WRONG Matches in known_hosts file:
-- |       L3: 199.19.117.60
-- | ssh-hostkey: 2048 xuvah-degyp-nabus-zegah-hebur-nopig-bubig-difeg-hisym-rumef-cuxex (RSA)
-- |_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVuv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lUx5tTA+vefXUWEMxgMuA7iX4irJHy2zer0NQ3Z3yJvr5scPgTYIaEOp5Uo/eGFG9Agpk5wE8CoF0e47iCAPHqzlmP2V7aNURLMODb3jVZuI07A2ZRrMGrD8d888E2ORVORv1rYeTYCqcMMoVFmX9l3gWEdk4yx3w5sD8v501Iuyd1v19mPfyhrI5E1E1nl/Xjp5N0/xP2GUBrdkDMxKaxqTPMie/f0dXBUPQQN697a5q+5lBRPhKYOtn6yQKCd9s1Q22nxn72Jmi1RzbMyYJ52FosDT755Qmb46GLrDMaZMQ==
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
--@xmloutput
-- <table>
--   <elem key="key">ssh-dss AAAAB3NzaC1kc3MAAACBANraqxAILTygMTgFu/0snrJck8BkhOpBbN61DAZENgeulLMaJdmNFWZpvhLOJVXSqHt2TCrspbMyvpBH4Fnv7Kb+QBAhXyzeCNnOQ7OVBfqNzkfezoFrQJgOQZSEenP6sCVDqcW2j0KVumnYdPU7FGa8SLfNqA+hUOR2HSSluynFAAAAFQDWKNq4PVbpDA7UExE8JSHnWxv4AwAAAIAWEDdNu5mWfTz52IdxELNjsmn5FvKRmnhPqq/PrTkYqAADL5WYazg7POQZ4yI2nqTq++47ONDK87Wke3qbeIhMrV13Mrgf2JuCUSNqrfEmvzZ2l9x3QyZrj+bJRPRuhwYq8rFup01qaANJ0p4WS/7voNbRhh+l57FkJF+XAJRRTAAAAIEAts1Se+u+hV9ZedXopzfXv1I5ZOSONxZanM10wjM2GRWygCYsHqDM315swBPkzhmB73oBesnhDW3bq0dmW3wvk4gzQZ2E2SHhzVGjlgDpjEahlQ+XGpDZsvqqFGGGx8lvKYFUxBR+UkqMRGmjkHw5sK5ydO1n4R3XJ4FfQFqmoyU=</elem>
--   <elem key="bits">1024</elem>
--   <elem key="fingerprint">18782fd3be7178a38e584b5a83bd60a8</elem>
--   <elem key="type">ssh-dss</elem>
-- </table>
-- <table>
--   <elem key="key">ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVuv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lUx5tTA+vefXUWEMxgMuA7iX4irJHy2zer0NQ3Z3yJvr5scPgTYIaEOp5Uo/eGFG9Agpk5wE8CoF0e47iCAPHqzlmP2V7aNURLMODb3jVZuI07A2ZRrMGrD8d888E2ORVORv1rYeTYCqcMMoVFmX9l3gWEdk4yx3w5sD8v501Iuyd1v19mPfyhrI5E1E1nl/Xjp5N0/xP2GUBrdkDMxKaxqTPMie/f0dXBUPQQN697a5q+5lBRPhKYOtn6yQKCd9s1Q22nxn72Jmi1RzbMyYJ52FosDT755Qmb46GLrDMaZMQ==</elem>
--   <elem key="bits">2048</elem>
--   <elem key="fingerprint">f058cef4aaa4591c8edd4d0744c82511</elem>
--   <elem key="type">ssh-rsa</elem>
-- </table>
-- <table key="Key comparison with known_hosts file">
--   <table key="GOOD Matches in known_hosts file">
--     <table>
--       <elem key="lnumber">5</elem>
--       <elem key="name">localhost</elem>
--       <elem key="key">ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwVuv2gcr0maaKQ69VVIEv2ob4OxnuI64fkeOnCXD1lUx5tTA+vefXUWEMxgMuA7iX4irJHy2zer0NQ3Z3yJvr5scPgTYIaEOp5Uo/eGFG9Agpk5wE8CoF0e47iCAPHqzlmP2V7aNURLMODb3jVZuI07A2ZRrMGrD8d888E2ORVORv1rYeTYCqcMMoVFmX9l3gWEdk4yx3w5sD8v501Iuyd1v19mPfyhrI5E1E1nl/Xjp5N0/xP2GUBrdkDMxKaxqTPMie/f0dXBUPQQN697a5q+5lBRPhKYOtn6yQKCd9s1Q22nxn72Jmi1RzbMyYJ52FosDT755Qmb46GLrDMaZMQ==</elem>
--     </table>
--   </table>
-- </table>
--
--@xmloutput
-- <table>
--   <table key="hosts">
--     <elem>192.168.1.1</elem>
--     <elem>192.168.1.2</elem>
--   </table>
--   <table key="key">
--     <elem key="fingerprint">2c2275604bc33b18a2972c967e28dcdd</elem>
--     <elem key="bits">2048</elem>
--     <elem key="type">ssh-rsa</elem>
--   </table>
-- </table>
-- <table>
--   <table key="hosts">
--     <elem>192.168.1.1</elem>
--     <elem>192.168.1.2</elem>
--   </table>
--   <table key="key">
--     <elem key="fingerprint">60ac4d51b1cd8509121692761d5d276e</elem>
--     <elem key="bits">1024</elem>
--     <elem key="type">ssh-dss</elem>
--   </table>
-- </table>

author = {"Sven Klemm", "Piotr Olma", "George Chatzisofroniou"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe","default","discovery"}


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

--- check if there is a key in known_hosts file for the host that's being scanned
--- and if there is, compare the keys
local function check_keys(host, keys, f)
  local keys_found = {}
  for _,k in ipairs(keys) do
    table.insert(keys_found, k.full_key)
  end
  local keys_from_file = {}
  local same_key, same_key_hashed = {}, {}
  local hostname = host.name == "" and nil or host.name
  local possible_host_names = {hostname or nil, host.ip or nil, (hostname and host.ip) and ("%s,%s"):format(hostname, host.ip) or nil}
  for _p, parts in ipairs(f) do
    local lnumber = parts.linenumber
    parts = parts.entry
    local foundhostname = false
    if #parts >= 3 then
      -- the line might be hashed
      if string.match(parts[1], "^|") then
        -- split the first part of the line - it contains base64'ed salt and hashed hostname
        local parts_hostname = stdnse.strsplit("|", parts[1])
        if #parts_hostname == 4 then
          -- check if the hash corresponds to the host being scanned
          local salt = base64.dec(parts_hostname[3])
          for _,name in ipairs(possible_host_names) do
            local hash = base64.enc(openssl.hmac("SHA1", salt, name))
            if parts_hostname[4] == hash then
              stdnse.debug2("found a hash that matches: %s for hostname: %s", hash, name)
              foundhostname = true
              table.insert(keys_from_file, {name=name, key=("%s %s"):format(parts[2], parts[3]), lnumber=lnumber})
            end
          end
          -- Is the key the same but the hashed hostname isn't?
          if not foundhostname then
            for _, k in ipairs(keys_found) do
              if ("%s %s"):format(parts[2], parts[3]) == k then
                table.insert(same_key_hashed, {name="<unknown>", key=k, lnumber = lnumber})
              end
            end
          end
        end
      else
        if stdnse.contains(possible_host_names, parts[1]) then
          stdnse.debug2("Found an entry that matches: %s", parts[1])
          table.insert(keys_from_file, ("%s %s"):format(parts[2], parts[3]))
        else
          -- Is the key the same but the clear text hostname isn't?
          for _, k in ipairs(keys_found) do
            if ("%s %s"):format(parts[2], parts[3]) == k then
              table.insert(same_key, {name=parts[1], key=("%s %s"):format(parts[2], parts[3]), lnumber=lnumber})
            end
          end
        end
      end
    end
  end

  local matched_keys, different_keys = {}, {}
  local matched

  -- Compare the keys found for this hostname and update the counts.
  for _,k in ipairs(keys_from_file) do
    matched = false
    for __,l in ipairs(keys_found) do
      if l == k.key then
        table.insert(matched_keys, k)
        matched = true
      end
    end
    if not matched then
      table.insert(different_keys, k)
    end
  end

  -- Start making output.
  local out
  if #keys_from_file == 0 then
    out = "No entry for scanned host found in known_hosts file."
  else
    out = stdnse.output_table()
    local match_mt = {
      __tostring = function(self)
        return string.format("L%d: %s", self.lnumber, self.name)
      end
    }
    local good = {}
    for __, gm in ipairs(matched_keys) do
      setmetatable(gm, match_mt)
      good[#good+1] = gm
    end
    for __, gm in ipairs(same_key) do
      setmetatable(gm, match_mt)
      good[#good+1] = gm
    end
    for __, gm in ipairs(same_key_hashed) do
      setmetatable(gm, match_mt)
      good[#good+1] = gm
    end
    if #good > 0 then
      out["GOOD Matches in known_hosts file"] = good
    end

    local wrong = {}
    for __, gm in ipairs(different_keys) do
      setmetatable(gm, match_mt)
      wrong[#wrong+1] = gm
    end
    if #wrong > 0 then
      out["WRONG Matches in known_hosts file"] = wrong
    end
  end
  return out
end

--- gather host keys
--@param host nmap host table
--@param port nmap port table of the currently probed port
local function portaction(host, port)
  if port.version.name_confidence < 8 or port.version.name ~= "ssh" then
    -- additional check if version scan was not done or if it doesn't think it's SSH.
    -- Since the fetch_host_key functions don't indicate what failed, we could
    -- waste a lot of time on e.g. tcpwrapped port 22
    -- Using opencon instead of get_banner to avoid trying SSL first in some cases
    local status, banner = comm.opencon(host, port, nil, {recv_before=true})
    if not string.match(banner, "^SSH") then
      stdnse.debug1("Service does not appear to be SSH: quitting.")
      return nil
    end
  end
  local output_tab = {}
  local keys = {}
  local key
  local format = nmap.registry.args.ssh_hostkey or "hex"
  local all_formats = format:find( 'all', 1, true )

  key = ssh1.fetch_host_key( host, port )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ssh-dss" )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ssh-rsa" )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ecdsa-sha2-nistp256" )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ecdsa-sha2-nistp384" )
  if key then table.insert( keys, key ) end

  key = ssh2.fetch_host_key( host, port, "ecdsa-sha2-nistp521" )
  if key then table.insert( keys, key ) end

  if #keys == 0 then
    return nil
  end

  for _, key in ipairs( keys ) do
    add_key_to_registry( host, key )
    local output = {}
    local out = {
      fingerprint=stdnse.tohex(key.fingerprint),
      type=key.key_type,
      bits=key.bits,
      key=key.key,
    }
    if format:find( 'hex', 1, true ) or all_formats then
      table.insert( output, ssh1.fingerprint_hex( key.fingerprint, key.algorithm, key.bits ) )
    end
    if format:find( 'bubble', 1, true ) or all_formats then
      table.insert( output, ssh1.fingerprint_bubblebabble( openssl.sha1(key.fp_input), key.algorithm, key.bits ) )
    end
    if format:find( 'visual', 1, true ) or all_formats then
      table.insert( output, ssh1.fingerprint_visual( key.fingerprint, key.algorithm, key.bits ) )
    end
    if nmap.verbosity() > 1 or format:find( 'full', 1, true ) or all_formats then
      table.insert( output, key.full_key )
    end
    setmetatable(out, {
        __tostring = function(self)
          return table.concat(output, "\n")
        end
      })
    table.insert(output_tab, out)
  end

  -- if a known_hosts file was given, then check if it contains a key for the host being scanned
  local known_hosts = stdnse.get_script_args("ssh-hostkey.known-hosts") or false
  if known_hosts then
    known_hosts = ssh1.parse_known_hosts_file(known_hosts)
    output_tab["Key comparison with known_hosts file"] = check_keys(
      host, keys, known_hosts)
  end

  return output_tab
end

--- iterate over the list of gathered keys and look for duplicate hosts (sharing the same hostkeys)
local function postaction()
  local hostkeys = {}
  local output = {}
  local output_tab = {}
  local revmap = {}

  -- create a reverse mapping key_fingerprint -> host(s)
  for ip, keys in pairs(nmap.registry.sshhostkey) do
    for _, key in ipairs(keys) do
      local fp = ssh1.fingerprint_hex(key.fingerprint, key.algorithm, key.bits)
      if not hostkeys[fp] then
        hostkeys[fp] = {}
        revmap[fp] = {
          fingerprint=stdnse.tohex(key.fingerprint,{separator=":"}),
          type=key.key_type,
          bits=key.bits
        }
      end
      -- discard duplicate IPs
      if not stdnse.contains(hostkeys[fp], ip) then
        table.insert(hostkeys[fp], ip)
      end
    end
  end

  -- look for hosts using the same hostkey
  for key, hosts in pairs(hostkeys) do
    if #hostkeys[key] > 1 then
      table.sort(hostkeys[key], function(a, b) return ipOps.compare_ip(a, "lt", b) end)
      local str = {'Key ' .. key .. ' used by:'}
      local tab = {key=revmap[key], hosts={}}
      for _, host in ipairs(hostkeys[key]) do
        str[#str+1] = host
        table.insert(tab.hosts, host)
      end
      table.insert(output, table.concat(str, "\n  "))
      table.insert(output_tab, tab)
    end
  end

  if #output > 0 then
    return output_tab, 'Possible duplicate hosts\n' .. table.concat(output, '\n')
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

