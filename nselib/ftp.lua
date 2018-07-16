---
-- FTP functions.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local comm = require "comm"
local stdnse = require "stdnse"
local string = require "string"
local ipOps = require "ipOps"
local nmap = require "nmap"
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

--- Close an FTP command connection
--
-- @param socket The socket with the live connection
function close(socket)
  socket:send("QUIT\r\n")
  socket:close()
end

--- Issue a STARTTLS command.
--
-- @param socket The connected command socket
-- @param buffer The socket read buffer
-- @return Boolean true if AUTH TLS succeeded, false otherwise
-- @return error string on failure
function starttls(socket, buffer)
  -- Send AUTH TLS command, ask the service to start encryption
  local status, err = socket:send("AUTH TLS\r\n")
  if not status then
    return nil, err
  end
  local code, result = read_reply(buffer)
  return code == 234, result
end

local function is_ssl(socket)
  return pcall(socket.get_ssl_certificate, socket)
end

-- Should we try STARTTLS based on this error?
local function should_try_ssl(code, message)
  return code and code >= 400 and (
        message:match('[Ss][Ss][Ll]') or
        message:match('[Tt][Ll][Ss]') or
        message:match('[Ss][Ee][Cc][Uu][Rr]')
        )
end

-- Try to reconnect over STARTTLS.
local function reconnect_ssl(socket, buffer)
  local status, err = starttls(socket, buffer)
  if status then
    status, err = socket:reconnect_ssl()
    if status then
      return true
    end
  end
  return nil, err
end

--- Authenticate with username and password
--
-- May negotiate AUTH TLS if required
-- @param socket The connected command socket
-- @param buffer The socket read buffer
-- @param username The username to send
-- @param password The password to send
-- @param acct (optional) If the server requires it, send this account name. Default: username
-- @return Boolean true if auth succeeded, false otherwise
-- @return FTP response code
-- @return FTP response message
function auth(socket, buffer, username, password, acct)
  local already_ssl = is_ssl(socket)
  ::TRY_AGAIN::
  local status, err = socket:send(("USER %s\r\n"):format(username))
  if not status then
    return nil, err
  end
  local code, message = read_reply(buffer)
  if code == 331 then
    -- 331: User name okay, need password.
    status, err =socket:send(("PASS %s\r\n"):format(password))
    if not status then
      return nil, err
    end
    code, message = read_reply(buffer)
  elseif not already_ssl and should_try_ssl(code, message) then
    if not reconnect_ssl(socket, buffer) then
      return nil
    end
    already_ssl = true
    goto TRY_AGAIN
  end

  if code == 332 then
    -- 332: Need account for login.
    -- This is rarely seen but may come in response to a
    -- USER or PASS command.
    status, err = socket:send("ACCT %s\r\n"):format(acct or username)
    if not status then
      return nil, err
    end
    code, message = read_reply(buffer)
    if code == 331 then
      -- 331: User name okay, need password.
      status, err = socket:send("PASS %s\r\n"):format(password)
      if not status then
        return nil, err
      end
      code, message = read_reply(buffer)
    elseif not already_ssl and should_try_ssl(code, message) then
      if not reconnect_ssl(socket, buffer) then
        return nil
      end
      already_ssl = true
      goto TRY_AGAIN
    end
  end

  if code and code >= 200 and code < 300 then
    -- We are primarily looking for 230: User logged in, proceed.
    return true, code, message
  else
    if code and not already_ssl and should_try_ssl(code, message) then
      if not reconnect_ssl(socket, buffer) then
        return nil
      end
      already_ssl = true
      goto TRY_AGAIN
    end
    return nil, code, message
  end
end

--- Start PASV mode
--
-- For IPv6 connections, attempts to use EPSV (RFC 2428). If the server sends an address that is not the target address, then this is an error.
-- @param socket The connected command socket
-- @param buffer The receive buffer
-- @return The connected data socket, or nil on error
-- @return Error message if data socket is nil
function pasv(socket, buffer)
  local epsv = false
  local status, lhost, lport, rhost, rport = socket:get_info()
  if not status then
    return nil, ("Can't determine remote host IP: %s"):format(lhost)
  end
  epsv = #ipOps.ip_to_str(rhost) > 4

  ::TRY_AGAIN::
  local cmd = epsv and "EPSV" or "PASV"
  -- ask the server for a Passive Mode: it should give us a port to
  -- listen to, where it will dump the directory listing
  local status, err = socket:send(cmd .. "\r\n")
  if not status then
    return status, err
  end
  local code, message = read_reply(buffer)

  local pasv_port
  if epsv then
    if not code then
      return nil, ("EPSV failed: socket %s"):format(message)
    elseif code ~= 229 then
      stdnse.debug2("Falling back to PASV. EPSV: %d %s", code, message)
      epsv = false
      goto TRY_AGAIN
    end
    status, pasv_port = string.match(message, "%((.)%1%1(%d+)%1%)")
    if not status then
      stdnse.debug2("Can't parse EPSV response: %s", message)
      epsv = false
      goto TRY_AGAIN
    end
  else
    if not code or code >= 300 then
      return nil, ("PASV failed: %s %s"):format(code or "socket", message)
    end
    -- Compute the PASV port as given by the server
    -- The server should answer with something like
    -- 2xx Entering Passive Mode (a,b,c,d,hp,lp)
    --                           (-- IP--,PORT)
    -- PORT is (hp x 256) + lp
    local ip, high, low = string.match(message, "%((%d+,%d+,%d+,%d+),(%d+),(%d+)%)")
    if not ip then
      return nil, string.format("Can't parse PASV response: %q", message)
    end
    ip = ip:gsub(",", ".")
    if not (ipOps.compare_ip(ip, "eq", rhost) or ipOps.compare_ip(ip, "eq", "0.0.0.0")) then
      return nil, ("PASV IP %s is not the same as %s"):format(ip, rhost)
    end

    pasv_port = high * 256 + low
  end

  local list_socket = nmap.new_socket()
  status, err = list_socket:connect(rhost, pasv_port, "tcp")
  if not status then
    return status, err
  end

  return list_socket
end

return _ENV;
