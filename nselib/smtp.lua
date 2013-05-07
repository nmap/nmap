---
-- Simple Mail Transfer Protocol (SMTP) operations.
--
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

local base64 = require "base64"
local comm = require "comm"
local nmap = require "nmap"
local sasl = require "sasl"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("smtp", stdnse.seeall)

local ERROR_MESSAGES = {
  ["EOF"]     = "connection closed",
  ["TIMEOUT"] = "connection timeout",
  ["ERROR"]   = "failed to receive data"
}

local SMTP_CMD = {
  ["EHLO"] = {
    cmd = "EHLO",
    success = {
      [250] = "Requested mail action okay, completed",
    },
    errors = {
      [421] = "<domain> Service not available, closing transmission channel",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [504] = "Command parameter not implemented",
      [550] = "Not implemented",
    },
  },
  ["HELP"] = {
    cmd = "HELP",
    success = {
      [211] = "System status, or system help reply",
      [214] = "Help message",
    },
    errors = {
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [502] = "Command not implemented",
      [504] = "Command parameter not implemented",
      [421] = "<domain> Service not available, closing transmission channel",
    },
  },
  ["AUTH"] = {
    cmd = "AUTH",
    success = {[334] = ""},
    errors = {
      [501] = "Authentication aborted",
    },
  },
  ["MAIL"] = {
    cmd = "MAIL",
    success = {
      [250] = "Requested mail action okay, completed",
    },
    errors = {
      [451] = "Requested action aborted: local error in processing",
      [452] = "Requested action not taken: insufficient system storage",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [421] = "<domain> Service not available, closing transmission channel",
      [552] = "Requested mail action aborted: exceeded storage allocation",
    },
  },
  ["RCPT"] = {
    cmd = "RCPT",
    success = {
      [250] = "Requested mail action okay, completed",
      [251] = "User not local; will forward to <forward-path>",
    },
    errors = {
      [450] = "Requested mail action not taken: mailbox unavailable",
      [451] = "Requested action aborted: local error in processing",
      [452] = "Requested action not taken: insufficient system storage",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [503] = "Bad sequence of commands",
      [521] = "<domain> does not accept mail [rfc1846]",
      [421] = "<domain> Service not available, closing transmission channel",
    },
  },
  ["DATA"] = {
    cmd = "DATA",
    success = {
      [250] = "Requested mail action okay, completed",
      [354] = "Start mail input; end with <CRLF>.<CRLF>",
    },
    errors = {
      [451] = "Requested action aborted: local error in processing",
      [554] = "Transaction failed",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [503] = "Bad sequence of commands",
      [421] = "<domain> Service not available, closing transmission channel",
      [552] = "Requested mail action aborted: exceeded storage allocation",
      [554] = "Transaction failed",
      [451] = "Requested action aborted: local error in processing",
      [452] = "Requested action not taken: insufficient system storage",
    },
  },
  ["STARTTLS"] = {
    cmd = "STARTTLS",
    success = {
      [220] = "Ready to start TLS"
    },
    errors = {
      [501] = "Syntax error (no parameters allowed)",
      [454] = "TLS not available due to temporary reason",
    },
  },
  ["RSET"] = {
    cmd = "RSET",
    success = {
      [200] = "nonstandard success response, see rfc876)",
      [250] = "Requested mail action okay, completed",
    },
    errors = {
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [504] = "Command parameter not implemented",
      [421] = "<domain> Service not available, closing transmission channel",
    },
  },
  ["VRFY"] = {
    cmd = "VRFY",
    success = {
      [250] = "Requested mail action okay, completed",
      [251] = "User not local; will forward to <forward-path>",
    },
    errors = {
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [502] = "Command not implemented",
      [504] = "Command parameter not implemented",
      [550] = "Requested action not taken: mailbox unavailable",
      [551] = "User not local; please try <forward-path>",
      [553] = "Requested action not taken: mailbox name not allowed",
      [421] = "<domain> Service not available, closing transmission channel",
    },
  },
  ["EXPN"] = {
    cmd = "EXPN",
    success = {
      [250] = "Requested mail action okay, completed",
    },
    errors = {
      [550] = "Requested action not taken: mailbox unavailable",
      [500] = "Syntax error, command unrecognised",
      [501] = "Syntax error in parameters or arguments",
      [502] = "Command not implemented",
      [504] = "Command parameter not implemented",
      [421] = "<domain> Service not available, closing transmission channel",
    },
  },
}
---
-- Returns a domain to be used in the SMTP commands that need it. If the
-- user specified one through the script argument <code>smtp.domain</code>
-- this function will return it. Otherwise it will try to find the domain
-- from the typed hostname and from the rDNS name. If it still can't find 
-- one it will return the nmap.scanme.org by default.
--
-- @param host The host table
-- @return The hostname to be used by the different SMTP commands.
get_domain = function(host)
  local nmap_domain = "nmap.scanme.org"

  -- Use the user provided options.
  local result = stdnse.get_script_args("smtp.domain")
  if not result then
    if type(host) == "table" then
      if host.targetname then
        result = host.targetname
      elseif (host.name and #host.name ~= 0) then
        result = host.name
      end
    end
  end

  return result or nmap_domain
end

--- Gets the authentication mechanisms that are listed in the response
-- of the client's EHLO command.
--
-- @param response The response of the client's EHLO command.
-- @return An array of authentication mechanisms on success, or nil
--         when it can't find authentication.
get_auth_mech = function(response)
  local list = {}

  for _, line in pairs(stdnse.strsplit("\r?\n", response)) do
    local authstr = line:match("%d+%-AUTH%s(.*)$")
    if authstr then
      for mech in authstr:gmatch("[^%s]+") do
        table.insert(list, mech)
      end
      return list
    end
  end

  return nil
end

--- Checks the SMTP server reply to see if it supports the previously
-- sent SMTP command.
--
-- @param cmd The SMTP command that was sent to the server
-- @param reply The SMTP server reply
-- @return true if the reply indicates that the SMTP command was
--         processed by the server correctly, or false on failures.
-- @return message The reply returned by the server on success, or an
--         error message on failures.
check_reply = function(cmd, reply)
  local code, msg = string.match(reply, "^([0-9]+)%s*")
  if code then
    cmd = cmd:upper()
    code = tonumber(code)
    if SMTP_CMD[cmd] then
      if SMTP_CMD[cmd].success[code] then
        return true, reply
      end
    else
      stdnse.print_debug(3,
          "SMTP: check_smtp_reply failed: %s not supported", cmd)
      return false, string.format("SMTP: %s %s", cmd, reply)
    end
  end
  stdnse.print_debug(3,
      "SMTP: check_smtp_reply failed: %s %s", cmd, reply)
  return false, string.format("SMTP: %s %s", cmd, reply)
end


--- Queries the SMTP server for a specific service.
--
-- This is a low level function that can be used to have more control
-- over the data exchanged. On network errors the socket will be closed.
-- This function automatically adds <code>CRLF<code> at the end.
--
-- @param socket connected to the server
-- @param cmd The SMTP cmd to send to the server
-- @param data The data to send to the server
-- @param lines The minimum number of lines to receive, default value: 1.
-- @return true on success, or nil on failures.
-- @return response The returned response from the server on success, or
--         an error message on failures.
query = function(socket, cmd, data, lines)
  if data then
    cmd = cmd.." "..data
  end

  local st, ret = socket:send(string.format("%s\r\n", cmd))
  if not st then
    socket:close()
    stdnse.print_debug(3, "SMTP: failed to send %s request.", cmd)
    return st, string.format("SMTP failed to send %s request.", cmd)
  end

  st, ret = socket:receive_lines(lines or 1)
  if not st then
    socket:close()
    stdnse.print_debug(3, "SMTP %s: failed to receive data: %s.",
                    cmd, (ERROR_MESSAGES[ret] or 'unspecified error'))
    return st, string.format("SMTP %s: failed to receive data: %s",
                    cmd, (ERROR_MESSAGES[ret] or 'unspecified error'))
  end

  return st, ret
end

--- Connects to the SMTP server based on the provided options.
--
-- @param host The host table
-- @param port The port table
-- @param opts The connection option table, possible options:
--    ssl: try to connect using TLS
--    timeout: generic timeout value
--    recv_before: receive data before returning
--    lines: a minimum number of lines to receive
-- @return socket The socket descriptor, or nil on errors
-- @return response The response received on success and when
--   the recv_before is set, or the error message on failures.
connect = function(host, port, opts)
  if opts.ssl then
    local socket, _, _, ret = comm.tryssl(host, port, '', opts)
    if not socket then
      return socket, (ERROR_MESSAGES[ret] or 'unspecified error') 
    end
    return socket, ret
  else
    local timeout, recv, lines
    local socket = nmap.new_socket()

    if opts then
      recv = opts.recv_before
      timeout = opts.timeout
      lines = opts.lines
    end
    socket:set_timeout(timeout or 8000)

    local st, ret = socket:connect(host, port, port.protocol)
    if not st then
      socket:close()
      return st, (ERROR_MESSAGES[ret] or 'unspecified error')
    end

    if recv then
      st, ret = socket:receive_lines(lines or 1)
      if not st then
        socket:close()
        return st, (ERROR_MESSAGES[ret] or 'unspecified error')
      end
    end

  return socket, ret
  end
end

--- Switches the plain text connection to be protected by the TLS protocol
-- by using the SMTP STARTTLS command.
-- 
-- The socket will be reconnected by using SSL. On network errors or if the
-- SMTP command fails, the connection will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @return true on success, or nil on failures.
-- @return message On success this will contain the SMTP server response
--         to the client's STARTTLS command, or an error message on failures.
starttls = function(socket)
  local st, reply, ret
  
  st, reply = query(socket, "STARTTLS")
  if not st then
    return st, reply
  end

  st, ret = check_reply('STARTTLS', reply)
  if not st then
    quit(socket)
    return st, ret
  end

  st, ret = socket:reconnect_ssl()
  if not st then
    socket:close()
    return st, ret
  end

  return true, reply
end

--- Sends the EHLO command to the SMTP server.
-- 
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server
-- @param domain to use in the EHLO command.
-- @return true on sucess, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
ehlo = function(socket, domain)
  local st, ret, response
  st, response = query(socket, "EHLO", domain)
  if not st then
    return st, response
  end

  st, ret = check_reply("EHLO", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends the HELP command to the SMTP server.
-- 
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
help = function(socket)
  local st, ret, response
  st, response = query(socket, "HELP")

  if not st then
    return st, response
  end

  st, ret = check_reply("HELP", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends the MAIL command to the SMTP server.
--
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @param address of the sender.
-- @param esmtp_opts The additional ESMTP options table, possible values:
--    size:     a decimal value to represent the message size in octets.
--    ret:      include the message in the DSN, should be 'FULL' or 'HDRS'.
--    envid:    envelope identifier, printable characters that would be
--              transmitted along with the message and included in the
--              failed DSN.
--    transid:  a globally unique case-sensitive value that identifies
--              this particular transaction.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
mail = function(socket, address, esmtp_opts)
  local st, ret, response

  if esmtp_opts and next(esmtp_opts) then
    local data = ""
    -- we do not check for strange values, read the NSEDoc.
    for k,v in pairs(esmtp_opts) do
      k = k:upper()
      data = string.format("%s %s=%s", data, k, v)
    end
    st, response = query(socket, "MAIL",
                      string.format("FROM:<%s>%s",
                      address, data))
  else
    st, response = query(socket, "MAIL",
                      string.format("FROM:<%s>", address))
  end

  if not st then
    return st, response
  end

  st, ret = check_reply("MAIL", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends the RCPT command to the SMTP server.
--
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @param address of the recipient.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
recipient = function(socket, address)
  local st, ret, response

  st, response = query(socket, "RCPT",
                      string.format("TO:<%s>", address))

  if not st then
    return st, response
  end

  st, ret = check_reply("RCPT", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends data to the SMTP server.
--
-- This function will automatically adds <code><CRLF>.<CRLF></code> at the
-- end. On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @param data to be sent.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
datasend = function(socket, data)
  local st, ret, response

  st, response = query(socket, "DATA")
  if not st then
    return st, response
  end

  st, ret = check_reply("DATA", response)
  if not st then
    quit(socket)
    return st, ret
  end

  if data then
    st, response = query(socket, data.."\r\n.")
    if not st then
      return st, response
    end

    st, ret = check_reply("DATA", response)
    if not st then
      quit(socket)
      return st, ret
    end
  end

  return st, response
end

--- Sends the RSET command to the SMTP server.
--
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
reset = function(socket)
  local st, ret, response
  st, response = query(socket, "RSET")

  if not st then
    return st, response
  end

  st, ret = check_reply("RSET", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends the VRFY command to verify the validity of a mailbox.
--
-- On network errors or if the SMTP command fails, the connection
-- will be closed and the socket cleared.
--
-- @param socket connected to server.
-- @param mailbox to verify.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.
verify = function(socket, mailbox)
  local st, ret, response
  st, response = query(socket, "VRFY", mailbox)
  
  st, ret = check_reply("VRFY", response)
  if not st then
    quit(socket)
    return st, ret
  end

  return st, response
end

--- Sends the QUIT command to the SMTP server, and closes the socket.
--
-- @param socket connected to server.
quit = function(socket)
  stdnse.print_debug(3, "SMTP: sending 'QUIT'.")
  socket:send("QUIT\r\n")
  socket:close()
end

--- Attempts to authenticate with the SMTP server. The supported authentication
--  mechanisms are: LOGIN, PLAIN, CRAM-MD5, DIGEST-MD5 and NTLM.
--
-- @param socket connected to server.
-- @param username SMTP username.
-- @param password SMTP password.
-- @param mech Authentication mechanism.
-- @return true on success, or false on failures.
-- @return response returned by the SMTP server on success, or an
--         error message on failures.

login = function(socket, username, password, mech)
	assert(mech == "LOGIN" or mech == "PLAIN" or mech == "CRAM-MD5" 
			or mech == "DIGEST-MD5" or mech == "NTLM",
			("Unsupported authentication mechanism (%s)"):format(mech or "nil"))
	local status, response = query(socket, "AUTH", mech)
	if ( not(status) ) then
		return false, "ERROR: Failed to send AUTH to server"
	end

	if ( mech == "LOGIN" ) then
		local tmp = response:match("334 (.*)")
		if ( not(tmp) ) then
			return false, "ERROR: Failed to decode LOGIN response"
		end
		tmp = base64.dec(tmp):lower()
		if ( not(tmp:match("^username")) ) then
			return false, ("ERROR: Expected \"Username\", but received (%s)"):format(tmp)
		end
		status, response = query(socket, base64.enc(username))
		if ( not(status) ) then
			return false, "ERROR: Failed to read LOGIN response"
		end
		tmp = response:match("334 (.*)")
		if ( not(tmp) ) then
			return false, "ERROR: Failed to decode LOGIN response"
		end
		tmp = base64.dec(tmp):lower()
		if ( not(tmp:match("^password")) ) then
			return false, ("ERROR: Expected \"password\", but received (%s)"):format(tmp)
		end
		status, response = query(socket, base64.enc(password))
		if ( not(status) ) then
			return false, "ERROR: Failed to read LOGIN response"
		end
		if ( response:match("^235") ) then
			return true, "Login success"
		end
		return false, response
	end
	
	
	if ( mech == "NTLM" ) then
		-- sniffed of the wire, seems to always be the same
		-- decodes to some NTLMSSP blob greatness
		status, response = query(socket, "TlRMTVNTUAABAAAAB7IIogYABgA3AAAADwAPACgAAAAFASgKAAAAD0FCVVNFLUFJUi5MT0NBTERPTUFJTg==")
		if ( not(status) ) then return false, "ERROR: Failed to receieve NTLM challenge" end 
	end
	
	
	local chall = response:match("^334 (.*)")
	chall = (chall and base64.dec(chall))
	if (not(chall)) then return false, "ERROR: Failed to retrieve challenge" end

	-- All mechanisms expect username and pass
	-- add the otheronce for those who need them
	local mech_params = { username, password, chall, "smtp" }
	local auth_data = sasl.Helper:new(mech):encode(table.unpack(mech_params))
	auth_data = base64.enc(auth_data)
	
	status, response = query(socket, auth_data)
	if ( not(status) ) then
		return false, ("ERROR: Failed to authenticate using SASL %s"):format(mech)
	end
	
	if ( mech == "DIGEST-MD5" ) then
		local rspauth = response:match("^334 (.*)")
		if ( rspauth ) then
			rspauth = base64.dec(rspauth)
			status, response = query(socket,"")
		end
	end
	
	if ( response:match("^235") ) then return true, "Login success"	end
		
	return false, response
end

return _ENV;
