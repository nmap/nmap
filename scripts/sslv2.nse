description = [[
Determines whether the server supports obsolete and less secure SSLv2, and discovers which ciphers it
supports.
]]

---
--@output
-- 443/tcp open   https   syn-ack
-- |  sslv2: server still supports SSLv2
-- |       SSL2_RC4_128_WITH_MD5
-- |       SSL2_DES_192_EDE3_CBC_WITH_MD5
-- |       SSL2_RC2_CBC_128_CBC_WITH_MD5
-- |       SSL2_DES_64_CBC_WITH_MD5
-- |       SSL2_RC4_128_EXPORT40_WITH_MD5
-- |_      SSL2_RC2_CBC_128_CBC_WITH_MD5

author = "Matthew Boyle"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

require "shortport"

portrule = shortport.ssl

hex2dec = function(hex)

	local byte1, byte2;

	byte1 = string.byte(hex, 1);
	byte2 = string.byte(hex, 2);

	if (byte1 == nil or byte2 == nil) then return 0; end;
	
	return (byte1 * 256) + byte2;

end

cyphers = function(cypher_list, len)

-- returns names of cyphers supported by the server

	local cypher;
	local cypher_name;
	local byte1, byte2, byte3;
	local available_cyphers = "";
	local idx = 0;

	local ssl_cyphers = {
-- (cut down) table of codes with their corresponding cyphers.
-- inspired by Wireshark's 'epan/dissectors/packet-ssl-utils.h'
		[0x010080] = "SSL2_RC4_128_WITH_MD5",
		[0x020080] = "SSL2_RC4_128_EXPORT40_WITH_MD5",
		[0x030080] = "SSL2_RC2_CBC_128_CBC_WITH_MD5",
		[0x040080] = "SSL2_RC2_CBC_128_CBC_WITH_MD5",
		[0x050080] = "SSL2_IDEA_128_CBC_WITH_MD5",
		[0x060040] = "SSL2_DES_64_CBC_WITH_MD5",
		[0x0700c0] = "SSL2_DES_192_EDE3_CBC_WITH_MD5",
		[0x080080] = "SSL2_RC4_64_WITH_MD5",
	};

	if (len == 0) then return "none"; end
-- something's got broken along the way if these aren't equal
	if (len ~= #cypher_list) then
		return "";
	end

	for idx = 1, len, 3 do
		cypher = string.sub(cypher_list, idx, idx + 2);

		byte1 = string.byte(cypher, 1);
		byte2 = string.byte(cypher, 2);
		byte3 = string.byte(cypher, 3);

		cypher = (byte1 * 256 * 256) + (byte2 * 256) + byte3;

		cypher_name = ssl_cyphers[cypher];

		if (cypher_name == nil) then
			cypher_name = "unknown cypher (" .. byte1 .. "-" .. byte2 .. "-" .. byte3 .. " dec)"
		end

		-- Check for duplicate cyphers
		if not available_cyphers:match("\t" .. cypher_name .. "\n") then
			available_cyphers = available_cyphers .. "\t" .. cypher_name .. "\n";
		end
	end

	return available_cyphers

end

give_n_bytes = function(idx, n, str)

-- returns the next n bytes of a string

	if (idx + (n - 1) > #str) then
		return (idx + n), string.rep(string.char(0x00), n);
	end

	return (idx + n), string.sub(str, idx, (idx + (n - 1)) );

end

action = function(host, port)

	local socket = nmap.new_socket();
	local status = true;
	
	local tmp;

	local idx = 3;	-- start reading after the end of the length record

	local return_string = "";
	local available_cyphers = "";

	local ssl_v2_hello;
	local server_hello;

	local server_hello_len;
	local message_type;
	local SID_hit;
	local certificate_type;
	local ssl_version;
	local certificate_len;
	local cyphers_len;
	local certificate;
	local connection_ID_len;
	local cypher_list;
	local connection_ID;

-- build client hello packet (contents inspired by
-- http://mail.nessus.org/pipermail/plugins-writers/2004-October/msg00041.html )
	local t = {};
	table.insert(t, string.char(0x80, 0x31));
	table.insert(t, string.char(0x01));
	table.insert(t, string.char(0x00, 0x02));
	table.insert(t, string.char(0x00, 0x18));
	table.insert(t, string.char(0x00, 0x00));
	table.insert(t, string.char(0x00, 0x10));
	table.insert(t, string.char(0x07, 0x00, 0xc0));
	table.insert(t, string.char(0x05, 0x00, 0x80));
	table.insert(t, string.char(0x03, 0x00, 0x80));
	table.insert(t, string.char(0x01, 0x00, 0x80));
	table.insert(t, string.char(0x08, 0x00, 0x80));
	table.insert(t, string.char(0x06, 0x00, 0x40));
	table.insert(t, string.char(0x04, 0x00, 0x80));
	table.insert(t, string.char(0x02, 0x00, 0x80));
	table.insert(t, string.char(0xe4, 0xbd, 0x00, 0x00));
	table.insert(t, string.char(0xa4, 0x41, 0xb6, 0x74));
	table.insert(t, string.char(0x71, 0x2b, 0x27, 0x95));
	table.insert(t, string.char(0x44, 0xc0, 0x3d, 0xc0));
	ssl_v2_hello = table.concat(t, "")

	socket:connect(host, port, "tcp");
	socket:send(ssl_v2_hello);

	status, server_hello = socket:receive_bytes(2);

	if (not status) then
		socket:close();
		return;
	end

	server_hello_len = string.sub(server_hello, 1, 2);
	server_hello_len = hex2dec(server_hello_len);
-- length record doesn't include its own length, and is "broken".
	server_hello_len = server_hello_len - (128 * 256) + 2;

-- the hello needs to be at least 13 bytes long to be of any use
	if (server_hello_len < 13) then
		socket:close();
		return;
	end
--try to get entire hello, if we don't already
	if (#server_hello < server_hello_len) then
		status, tmp = socket:receive_bytes(server_hello_len - #server_hello);

		if (not status) then
			socket:close();
			return;
		end

		server_hello = server_hello .. tmp;
	end;

	socket:close();

-- split up server hello into components
	idx, message_type = 	give_n_bytes(idx, 1, server_hello);
	idx, SID_hit = 			give_n_bytes(idx, 1, server_hello);
	idx, certificate_type = 	give_n_bytes(idx, 1, server_hello);
	idx, ssl_version = 		give_n_bytes(idx, 2, server_hello);
	idx, certificate_len = 		give_n_bytes(idx, 2, server_hello);
		certificate_len = hex2dec(certificate_len);
	idx, cyphers_len = 		give_n_bytes(idx, 2, server_hello);
		cyphers_len = hex2dec(cyphers_len);
	idx, connection_ID_len = 	give_n_bytes(idx, 2, server_hello);
		connection_ID_len = hex2dec(connection_ID_len);
	idx, certificate = 		give_n_bytes(idx, certificate_len, server_hello);
	idx, cypher_list = 		give_n_bytes(idx, cyphers_len, server_hello);
	idx, connection_ID = 		give_n_bytes(idx, connection_ID_len, server_hello);

-- some sanity checks:
-- is response a server hello?
	if (message_type ~= string.char(0x04)) then
		return;
	end
-- is certificate in X.509 format?
	if (certificate_type ~= string.char(0x01)) then
		return;
	end

-- get a list of cyphers offered
	available_cyphers = cyphers(cypher_list, cyphers_len);

-- actually run some tests:
	if (ssl_version == string.char(0x00, 0x02)) then
		if (available_cyphers == "none") then
			return_string = "server supports SSLv2 protocol, but no SSLv2 cyphers\n";
		else
			return_string = "server still supports SSLv2\n";
			if (nmap.verbosity() > 1 or nmap.debugging() > 0) then
				return_string = return_string .. available_cyphers;
			end
		end
	end

	return return_string;
end
