---
-- A library providing functions for collecting SSL certificates and storing
-- them in the host-based registry.
--
-- The library is largely based on code (copy-pasted) from David Fifields
-- ssl-cert script in an effort to allow certs to be cached and shared among
-- other scripts.
--
-- STARTTLS functions are included for several protocols:
--
-- * FTP
-- * IMAP
-- * LDAP
-- * POP3
-- * SMTP
-- * XMPP
--
-- @author "Patrik Karlsson <patrik@cqure.net>"

local asn1 = require "asn1"
local bin = require "bin"
local comm = require "comm"
local ftp = require "ftp"
local ldap = require "ldap"
local nmap = require "nmap"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local xmpp = require "xmpp"
_ENV = stdnse.module("sslcert", stdnse.seeall)

--- Parse an X.509 certificate from DER-encoded string
--@name parse_ssl_certificate
--@class function
--@param der DER-encoded certificate
--@return table containing decoded certificate
--@see nmap.get_ssl_certificate
_ENV.parse_ssl_certificate = nmap.socket.parse_ssl_certificate

StartTLS = {

  -- TODO: Implement STARTTLS for NNTP

  ftp_prepare_tls_without_reconnect = function(host, port)
    -- Attempt to negotiate TLS over FTP for services that support it
    -- Works for FTP (21)

    -- Open a standard TCP socket
    local s, err = comm.opencon(host, port)
    if not s then
      return false, string.format("Failed to connect to FTP server: %s", err)
    end
    local buf = stdnse.make_buffer(s, "\r?\n")

    local code, result = ftp.read_reply(buf)
    if code ~= 220 then
      return false, string.format("FTP protocol error: %s", code or result)
    end

    -- Send AUTH TLS command, ask the service to start encryption
    s:send("AUTH TLS\r\n")
    code, result = ftp.read_reply(buf)
    if code ~= 234 then
      stdnse.debug1("AUTH TLS failed or unavailable.  Enable --script-trace to see what is happening.")

      -- Send QUIT to clean up server side connection
      s:send("QUIT\r\n")

      return false, string.format("FTP AUTH TLS error: %s", code or result)
    end
    -- Should have a solid TLS over FTP session now...
    return true, s
  end,

  ftp_prepare_tls = function(host, port)
    local err
    local status, s = StartTLS.ftp_prepare_tls_without_reconnect(host, port)
    if status then
      status,err = s:reconnect_ssl()
      if not status then
        stdnse.debug1("Could not establish SSL session after STARTTLS command.")
        s:close()
        return false, "Failed to connect to FTP server"
      else
        return true, s
      end
    end
    return false, "Failed to connect to FTP server"
  end,

  imap_prepare_tls_without_reconnect = function(host, port)
    -- Attempt to negotiate TLS over IMAP for services that support it
    -- Works for IMAP (143)

    -- Open a standard TCP socket
    local s, err, result = comm.opencon(host, port, "", {lines=1, recv_before=true})
    if not s then
      return false, string.format("Failed to connect to IMAP server: %s", err)
    end

    if not string.match(result, "^%* OK") then
      return false, "IMAP protocol mismatch"
    end

    -- Check for STARTTLS support.
    local status = s:send("A001 CAPABILITY\r\n")
    status, result = s:receive_lines(1)

    if not (string.match(result, "STARTTLS")) then
      stdnse.debug1("Server doesn't support STARTTLS")
      return false, "Failed to connect to IMAP server"
    end

    -- Send the STARTTLS message
    status = s:send("A002 STARTTLS\r\n")
    status, result = s:receive_lines(1)

    if not (string.match(result, "^A002 OK")) then
      stdnse.debug1(string.format("Error: %s", result))
      return false, "Failed to connect to IMAP server"
    end

    -- Should have a solid TLS over IMAP session now...
    return true, s
  end,

  imap_prepare_tls = function(host, port)
    local err
    local status, s = StartTLS.imap_prepare_tls_without_reconnect(host, port)
    if status then
      status,err = s:reconnect_ssl()
      if not status then
        stdnse.debug1("Could not establish SSL session after STARTTLS command.")
        s:close()
        return false, "Failed to connect to IMAP server"
      else
        return true,s
      end
    end
    return false, "Failed to connect to IMAP server"
  end,

  ldap_prepare_tls_without_reconnect = function(host, port)
    local s = nmap.new_socket()
    -- Attempt to negotiate TLS over LDAP for services that support it
    -- Works for LDAP (389)

    -- Open a standard TCP socket
    local status, error = s:connect(host, port, "tcp")
    if not status then
      return false, "Failed to connect to LDAP server"
    end

    -- Create an ExtendedRequest and specify the OID for the
    -- Start TTLS operation (see http://www.ietf.org/rfc/rfc2830.txt)
    local ExtendedRequest = 23
    local ExtendedResponse = 24
    local oid, ldapRequest, ldapRequestId
    oid = ldap.encode("1.3.6.1.4.1.1466.20037")
    ldapRequest = ldap.encodeLDAPOp(ExtendedRequest, true, oid)
    ldapRequestId = ldap.encode(1)

    -- Send the STARTTLS request
    local encoder = asn1.ASN1Encoder:new()
    local data = encoder:encodeSeq(ldapRequestId .. ldapRequest)
    status = s:send(data)
    if not status then
      return false, "STARTTLS failed"
    end

    -- Decode the response
    local response
    status, response = s:receive()
    if not status then
      return false, "STARTTLS failed"
    end

    local decoder = asn1.ASN1Decoder:new()
    local len, pos, messageId, ldapOp, tmp = ""
    pos, len = decoder.decodeLength(response, 2)
    pos, messageId = ldap.decode(response, pos)
    pos, tmp = bin.unpack("C", response, pos)
    ldapOp = asn1.intToBER(tmp)

    if ldapOp.number ~= ExtendedResponse then
      stdnse.debug1(string.format(
        "STARTTLS failed (got wrong op number: %d)", ldapOp.number))
      return false, "STARTTLS failed"
    end

    local resultCode
    pos, len = decoder.decodeLength(response, pos)
    pos, resultCode = ldap.decode(response, pos)

    if resultCode ~= 0 then
      stdnse.debug1(string.format(
        "STARTTLS failed (LDAP error code is: %d)", resultCode))
      return false, "STARTTLS failed"
    end

    -- Should have a solid TLS over LDAP session now...
    return true,s
  end,

  ldap_prepare_tls = function(host, port)
    local err
    local status, s = StartTLS.ldap_prepare_tls_without_reconnect(host, port)
    if status then
      status,err = s:reconnect_ssl()
      if not status then
        stdnse.debug1("Could not establish SSL session after STARTTLS command.")
        s:close()
        return false, "Failed to connect to LDAP server"
      else
        return true,s
      end
    end
    return false, "Failed to connect to LDAP server"
  end,

  pop3_prepare_tls_without_reconnect = function(host, port)
    -- Attempt to negotiate TLS over POP3 for services that support it
    -- Works for POP3 (110)

    -- Open a standard TCP socket
    local s, err, result = comm.opencon(host, port, "", {lines=1, recv_before=true})
    if not s then
      return false, string.format("Failed to connect to POP3 server: %s", err)
    end

    if not string.match(result, "^%+OK") then
      return false, "POP3 protocol mismatch"
    end

    -- Send the STLS message
    local status = s:send("STLS\r\n")
    status, result = s:receive_lines(1)

    if not (string.match(result, "^%+OK")) then
      stdnse.debug1(string.format("Error: %s", result))
      status = s:send("QUIT\r\n")
      return false, "Failed to connect to POP3 server"
    end

    -- Should have a solid TLS over POP3 session now...
    return true, s
  end,

  pop3_prepare_tls = function(host, port)
    local err
    local status, s = StartTLS.pop3_prepare_tls_without_reconnect(host, port)
    if status then
      status,err = s:reconnect_ssl()
      if not status then
        stdnse.debug1("Could not establish SSL session after STARTTLS command.")
        s:close()
        return false, "Failed to connect to POP3 server"
      else
        return true,s
      end
    end
    return false, "Failed to connect to POP3 server"
  end,

  smtp_prepare_tls_without_reconnect = function(host, port)
    -- Attempt to negotiate TLS over SMTP for services that support it
    -- Works for SMTP (25) and SMTP Submission (587)

    -- Open a standard TCP socket
    local s, result = smtp.connect(host, port, {lines=1, recv_before=1, ssl=false})
    if not s then
      return false, string.format("Failed to connect to SMTP server: %s", result)
    end

    local status
    status, result = smtp.ehlo(s, "example.com")
    if not status then
      stdnse.debug1("EHLO with errors or timeout.  Enable --script-trace to see what is happening.")
      return false, string.format("Failed to connect to SMTP server: %s", result)
    end

    -- Send STARTTLS command ask the service to start encryption
    status, result = smtp.query(s, "STARTTLS")
    if status then
      status, result = smtp.check_reply("STARTTLS", result)
    end

    if not status then
      stdnse.debug1("STARTTLS failed or unavailable.  Enable --script-trace to see what is happening.")

      -- Send QUIT to clean up server side connection
      smtp.quit(s)
      return false, string.format("Failed to connect to SMTP server: %s", result)
    end
    -- Should have a solid TLS over SMTP session now...
    return true, s
  end,

  smtp_prepare_tls = function(host, port)
    local err
    local status,s = StartTLS.smtp_prepare_tls_without_reconnect(host, port)
    if status then
      status,err = s:reconnect_ssl()
      if not status then
        stdnse.debug1("Could not establish SSL session after STARTTLS command.")
        s:close()
        return false, "Failed to connect to SMTP server"
      else
        return true,s
      end
    end
    return false, "Failed to connect to SMTP server"
  end,

  xmpp_prepare_tls_without_reconnect = function(host,port)
    local sock,status,err,result
    local xmppStreamStart = string.format("<?xml version='1.0' ?>\r\n<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\r\n",host.name)
    local xmppStartTLS = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n"
    sock = nmap.new_socket()
    sock:set_timeout(5000)
    status, err = sock:connect(host, port)
    if not status then
      sock:close()
      stdnse.debug1("Can't send: %s", err)
      return false, "Failed to connect to XMPP server"
    end
    status, err = sock:send(xmppStreamStart)
    if not status then
      stdnse.debug1("Couldn't send: %s", err)
      sock:close()
      return false, "Failed to connect to XMPP server"
    end
    status, result = sock:receive()
    if not status then
      stdnse.debug1("Couldn't receive: %s", err)
      sock:close()
      return false, "Failed to connect to XMPP server"
    end
    status, err = sock:send(xmppStartTLS)
    if not status then
      stdnse.debug1("Couldn't send: %s", err)
      sock:close()
      return false, "Failed to connect to XMPP server"
    end
    status, result = sock:receive()
    if not status then
      stdnse.debug1("Couldn't receive: %s", err)
      sock:close()
      return false, "Failed to connect to XMPP server"
    end
    if string.find(result,"proceed") then
      return true,sock
    end

    status, result = sock:receive() -- might not be in the first reply
    if not status then
      stdnse.debug1("Couldn't receive: %s", err)
      sock:close()
      return false, "Failed to connect to XMPP server"
    end
    if string.find(result,"proceed") then
      return true,sock
    else
      return false, "Failed to connect to XMPP server"
    end
  end,

  xmpp_prepare_tls = function(host, port)
    local ls = xmpp.XMPP:new(host, port, { starttls = true } )
    ls.socket = nmap.new_socket()
    ls.socket:set_timeout(ls.options.timeout * 1000)

    local status, err = ls.socket:connect(host, port)
    if not status then
      return nil
    end

    status, err = ls:connect()
    if not(status) then
      return false, "Failed to connected"
    end
    return true, ls.socket
  end
}

-- A table mapping port numbers to specialized SSL negotiation functions.
local SPECIALIZED_PREPARE_TLS = {
  ftp = StartTLS.ftp_prepare_tls,
  [21] = StartTLS.ftp_prepare_tls,
  imap = StartTLS.imap_prepare_tls,
  [143] = StartTLS.imap_prepare_tls,
  [ldap] = StartTLS.ldap_prepare_tls,
  [389] = StartTLS.ldap_prepare_tls,
  pop3 = StartTLS.pop3_prepare_tls,
  [110] = StartTLS.pop3_prepare_tls,
  smtp = StartTLS.smtp_prepare_tls,
  [25] = StartTLS.smtp_prepare_tls,
  [587] = StartTLS.smtp_prepare_tls,
  xmpp = StartTLS.xmpp_prepare_tls,
  [5222] = StartTLS.xmpp_prepare_tls,
  [5269] = StartTLS.xmpp_prepare_tls
}

local SPECIALIZED_PREPARE_TLS_WITHOUT_RECONNECT = {
  ftp = StartTLS.ftp_prepare_tls_without_reconnect,
  [21] = StartTLS.ftp_prepare_tls_without_reconnect,
  imap = StartTLS.imap_prepare_tls_without_reconnect,
  [143] = StartTLS.imap_prepare_tls_without_reconnect,
  ldap = StartTLS.ldap_prepare_tls_without_reconnect,
  [389] = StartTLS.ldap_prepare_tls_without_reconnect,
  pop3 = StartTLS.pop3_prepare_tls_without_reconnect,
  [110] = StartTLS.pop3_prepare_tls_without_reconnect,
  smtp = StartTLS.smtp_prepare_tls_without_reconnect,
  [25] = StartTLS.smtp_prepare_tls_without_reconnect,
  [587] = StartTLS.smtp_prepare_tls_without_reconnect,
  xmpp = StartTLS.xmpp_prepare_tls_without_reconnect,
  [5222] = StartTLS.xmpp_prepare_tls_without_reconnect,
  [5269] = StartTLS.xmpp_prepare_tls_without_reconnect
}

--- Get a specialized SSL connection function without starting SSL
--
-- For protocols that require some sort of START-TLS setup, this function will
-- return a function that can be used to produce a socket that is ready for SSL
-- messages.
-- @param port A port table with 'number' and 'service' keys
-- @return A STARTTLS function or nil
function getPrepareTLSWithoutReconnect(port)
  if ( port.version and port.version.service_tunnel == 'ssl') then
    return nil
  end
  return (SPECIALIZED_PREPARE_TLS_WITHOUT_RECONNECT[port.number] or
    SPECIALIZED_PREPARE_TLS_WITHOUT_RECONNECT[port.service])
end

--- Get a specialized SSL connection function to create an SSL socket
--
-- For protocols that require some sort of START-TLS setup, this function will
-- return a function that can be used to produce an SSL-connected socket.
-- @param port A port table with 'number' and 'service' keys
-- @return A STARTTLS function or nil
function isPortSupported(port)
  if ( port.version and port.version.service_tunnel == 'ssl') then
    return nil
  end
  return (SPECIALIZED_PREPARE_TLS[port.number] or
    SPECIALIZED_PREPARE_TLS[port.service])
end

--- Gets a certificate for the given host and port
-- The function will attempt to START-TLS for the ports known to require it.
-- @param host table as received by the script action function
-- @param port table as received by the script action function
-- @return status true on success, false on failure
-- @return cert userdata containing the SSL certificate, or error message on
--         failure.
function getCertificate(host, port)
  local mutex = nmap.mutex("sslcert-cache-mutex")
  mutex "lock"

  if ( host.registry["ssl-cert"] and
    host.registry["ssl-cert"][port.number] ) then
    stdnse.debug2("sslcert: Returning cached SSL certificate")
    mutex "done"
    return true, host.registry["ssl-cert"][port.number]
  end

  -- Is there a specialized function for this port?
  local specialized = SPECIALIZED_PREPARE_TLS[port.number]
  local status
  local socket = nmap.new_socket()
  if specialized then
    status, socket = specialized(host, port)
    if not status then
      mutex "done"
      return false, "Failed to connect to server"
    end
  else
    local status
    status = socket:connect(host, port, "ssl")
    if ( not(status) ) then
      mutex "done"
      return false, "Failed to connect to server"
    end
  end
  local cert = socket:get_ssl_certificate()
  if ( cert == nil ) then
    return false, "Unable to get cert"
  end

  host.registry["ssl-cert"] = host.registry["ssl-cert"] or {}
  host.registry["ssl-cert"][port.number] = host.registry["ssl-cert"][port.number] or {}
  host.registry["ssl-cert"][port.number] = cert
  mutex "done"
  return true, cert
end



return _ENV;
