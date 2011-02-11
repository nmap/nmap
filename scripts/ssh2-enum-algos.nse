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

author = "Kris Katterjohn"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

require "shortport"
require "stdnse"
if pcall(require,"openssl") then
  require("ssh2")
else
  portrule = function() return false end
  action = function() end
  stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.",
      SCRIPT_NAME)
  return;
end

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
	local out = {}

	for _, l in ipairs(lists) do
		local v = parsed[l]
		local a = v:len() > 0 and stdnse.strsplit(",", v) or {}
		local e = { ["name"] = l .. " (" .. #a .. ")" }
		if nmap.verbosity() > 0 then
			table.insert(e, a)
		end
		table.insert(out, e)
	end

	return stdnse.format_output(true, out)
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

