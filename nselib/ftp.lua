---
-- FTP functions.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local comm = require "comm"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("ftp", stdnse.seeall)

local ERROR_MESSAGES = {
  ["EOF"]     = "connection closed",
  ["TIMEOUT"] = "connection timeout",
  ["ERROR"]   = "failed to receive data"
}

--- Connects to the FTP server based on the provided options.
--
-- @param host The host table
-- @param port The port table
-- @param opts The connection option table, possible options:
--    timeout: generic timeout value
--    recv_before: receive data before returning
-- @return socket The socket descriptor, or nil on errors
-- @return response The response received on success and when
--    the recv_before is set, or the error message on failures.
connect = function(host, port, opts)
  local socket, _, _, ret = comm.tryssl(host, port, '', opts)
  if not socket then
    return socket, (ERROR_MESSAGES[ret] or 'unspecified error')
  end
  return socket, ret
end

---
-- Read an FTP reply and return the numeric code and the message. See RFC 959,
-- section 4.2.
-- @param buffer should have been created with
-- <code>stdnse.make_buffer(socket, "\r?\n")</code>.
-- @return numeric code or <code>nil</code>.
-- @return text reply or error message.
function read_reply(buffer)
	local readline
	local line, err
	local code, message
	local _, p, tmp

	line, err = buffer()
	if not line then
		    return line, err
	end

	-- Single-line response?
	code, message = string.match(line, "^(%d%d%d) (.*)$")
	if code then
		return tonumber(code), message
	end

	-- Multi-line response?
	_, p, code, message = string.find(line, "^(%d%d%d)-(.*)$")
	if p then
	while true do
		line, err = buffer()
		if not line then
			return line, err
		end
		tmp = string.match(line, "^%d%d%d (.*)$")
		if tmp then
			message = message .. "\n" .. tmp
			break
		end
		message = message .. "\n" .. line
		end

		return tonumber(code), message
	end

	return nil, string.format("Unparseable response: %q", line)
end

return _ENV;
