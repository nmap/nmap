local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

local openssl = stdnse.silent_require "openssl"
local ssh2 = stdnse.silent_require "ssh2"

description = [[
Reports the number of algorithms (for encryption, compression, etc.) that
the target SSH2 server offers. If verbosity is set, the offered algorithms
are each listed by type.

If the "client to server" and "server to client" algorithm lists are identical
(order specifies preference) then the list is shown only once under a combined
type.
]]

---
-- @usage
-- nmap --script ssh2-enum-algos target
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh2-enum-algos:
-- |   kex_algorithms (4)
-- |       diffie-hellman-group-exchange-sha256
-- |       diffie-hellman-group-exchange-sha1
-- |       diffie-hellman-group14-sha1
-- |       diffie-hellman-group1-sha1
-- |   server_host_key_algorithms (2)
-- |       ssh-rsa
-- |       ssh-dss
-- |   encryption_algorithms (13)
-- |       aes128-ctr
-- |       aes192-ctr
-- |       aes256-ctr
-- |       arcfour256
-- |       arcfour128
-- |       aes128-cbc
-- |       3des-cbc
-- |       blowfish-cbc
-- |       cast128-cbc
-- |       aes192-cbc
-- |       aes256-cbc
-- |       arcfour
-- |       rijndael-cbc@lysator.liu.se
-- |   mac_algorithms (6)
-- |       hmac-md5
-- |       hmac-sha1
-- |       hmac-ripemd160
-- |       hmac-ripemd160@openssh.com
-- |       hmac-sha1-96
-- |       hmac-md5-96
-- |   compression_algorithms (2)
-- |       none
-- |_      zlib@openssh.com
--
-- @xmloutput
-- <table key="kex_algorithms">
--   <elem>ecdh-sha2-nistp256</elem>
--   <elem>ecdh-sha2-nistp384</elem>
--   <elem>ecdh-sha2-nistp521</elem>
--   <elem>diffie-hellman-group-exchange-sha256</elem>
--   <elem>diffie-hellman-group-exchange-sha1</elem>
--   <elem>diffie-hellman-group14-sha1</elem>
--   <elem>diffie-hellman-group1-sha1</elem>
-- </table>
-- <table key="server_host_key_algorithms">
--   <elem>ssh-rsa</elem>
--   <elem>ecdsa-sha2-nistp256</elem>
-- </table>
-- <table key="encryption_algorithms">
--   <elem>aes128-ctr</elem>
--   <elem>aes192-ctr</elem>
--   <elem>aes256-ctr</elem>
--   <elem>aes128-cbc</elem>
--   <elem>3des-cbc</elem>
--   <elem>blowfish-cbc</elem>
--   <elem>cast128-cbc</elem>
--   <elem>aes192-cbc</elem>
--   <elem>aes256-cbc</elem>
-- </table>
-- <table key="mac_algorithms">
--   <elem>hmac-sha1</elem>
--   <elem>umac-64@openssh.com</elem>
--   <elem>hmac-ripemd160</elem>
--   <elem>hmac-sha2-256</elem>
--   <elem>hmac-sha2-512</elem>
-- </table>
-- <table key="compression_algorithms">
--   <elem>none</elem>
--   <elem>zlib@openssh.com</elem>
-- </table>

author = "Kris Katterjohn"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}


portrule = shortport.port_or_service(22, "ssh")

-- Build onto lists{} and possibly modify parsed{} based on whether the
-- algorithm name-lists are identical between the server-to-client and
-- client-to-server types.  Note that this simply modifies the passed tables.
local combine_types = function(parsed, lists)
  local doubles = {
    "encryption_algorithms",
    "mac_algorithms",
    "compression_algorithms"
  }

  for _, i in ipairs(doubles) do
    local c2s = i .. "_client_to_server"
    local s2c = i .. "_server_to_client"

    if parsed[c2s] == parsed[s2c] then
      parsed[i] = parsed[c2s]
      parsed[c2s] = nil
      parsed[s2c] = nil
      table.insert(lists, i)
    else
      table.insert(lists, c2s)
      table.insert(lists, s2c)
    end
  end
end

-- Build and return the output table
local output = function(parsed, lists)
  local out = stdnse.output_table()

  for _, l in ipairs(lists) do
    local v = parsed[l]
    local a = v:len() > 0 and stdnse.strsplit(",", v) or {}
    if nmap.verbosity() > 0 then
      setmetatable(a, {
        __tostring = function(t)
          return string.format("(%d)\n      %s", #t, table.concat(t, "\n      "))
        end
      })
    else
      setmetatable(a, {
        __tostring = function(t)
          return string.format("(%d)", #t)
        end
      })
    end
    out[l] = a
  end

  return out
end

action = function(host, port)
  local sock = nmap.new_socket()
  local status = sock:connect(host, port)

  if not status then
    return
  end

  status = sock:receive_lines(1)
  if not status then
    sock:close()
    return
  end

  status = sock:send("SSH-2.0-Nmap-SSH2-Enum-Algos\r\n")
  if not status then
    sock:close()
    return
  end

  local ssh = ssh2.transport

  -- I would think that the server would send its kex data right after
  -- receiving and verifying our protocol id string above, then we could
  -- just use it here, but I've seen no definitive documentation saying
  -- that we don't ever send ours first.  All I've seen is that if the
  -- server doesn't care about compatibility with older clients then it
  -- MAY send its kex data after the protocol id string.  So I guess I'll
  -- send it here until I know for sure (removing this send works against
  -- OpenSSH though).
  local pkt = ssh.build(ssh.kex_init())

  status = sock:send(pkt)
  if not status then
    sock:close()
    return
  end

  local status, response = ssh.receive_packet(sock)

  sock:close()

  if not status then
    return
  end

  local parsed = ssh.parse_kex_init(ssh.payload(response))

  local lists = {
    "kex_algorithms",
    "server_host_key_algorithms"
    -- Other types will be added below in combine_types()
  }

  -- Modifies tables
  combine_types(parsed, lists)

  return output(parsed, lists)
end

