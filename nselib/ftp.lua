---
-- FTP functions.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

module(... or "ftp", package.seeall)

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
