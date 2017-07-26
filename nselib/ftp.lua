---
-- FTP functions.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local comm = require "comm"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("ftp", stdnse.seeall)

local ERROR_MESSAGES = {
  ["EOF"]     = "connection closed",
  ["TIMEOUT"] = "connection timeout",
  ["ERROR"]   = "failed to receive data"
}

local crlf_pattern = "\r?\n"
--- Connects to the FTP server based on the provided options and returns the parsed banner.
--
-- @param host The host table
-- @param port The port table
-- @param opts The connection option table, from comm.lua.
-- @return socket The socket descriptor, or nil on errors
-- @return code The numeric response code, as returned by read_reply, or error message if socket is nil.
-- @return message The response message
-- @return buffer The socket read buffer function, to be passed to read_reply.
-- @see comm.lua
connect = function(host, port, opts)
  opts = opts or {}
  opts.recv_before = true
  local socket, err, proto, ret = comm.tryssl(host, port, '', opts)
  if not socket then
    return socket, (ERROR_MESSAGES[ret] or 'unspecified error')
  end
  local buffer = stdnse.make_buffer(socket, crlf_pattern)
  local pos = 1
  -- Should we just pass the output of buffer()?
  local usebuf = false
  -- Since we already read the first chunk of banner from the socket,
  -- we have to supply it line-by-line to read_reply.
  local code, message = read_reply(function()
      if usebuf then
        -- done reading the initial banner; pass along the socket buffer.
        return buffer()
      end
      -- Look for CRLF
      local i, j = ret:find(crlf_pattern, pos)
      if not i then
        -- Didn't find it! Grab another chunk (up to CRLF) and return it
        usebuf = true
        local chunk = buffer()
        return ret:sub(pos) .. chunk
      end
      local oldpos = pos
      -- start the next search just after CRLF
      pos = j + 1
      if pos >= #ret then
        -- We consumed the whole thing! Start calling buffer() next.
        usebuf = true
      end
      return ret:sub(oldpos, i - 1)
    end)
  return socket, code, message, buffer
end

---
-- Read an FTP reply and return the numeric code and the message. See RFC 959,
-- section 4.2.
-- @param buffer The buffer returned by ftp.connect or created with
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
  _, p, code, message = string.find(line, "^(%d%d%d)%-(.*)$")
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
