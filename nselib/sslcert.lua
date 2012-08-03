---
-- A library providing functions for collecting SSL certificates and storing
-- them in the host-based registry.
--
-- The library is largely based on code (copy-pasted) from David Fifields
-- ssl-cert script in an effort to allow certs to be cached and shared among
-- other scripts.
--
-- @author "Patrik Karlsson <patrik@cqure.net>"

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local xmpp = require "xmpp"
_ENV = stdnse.module("sslcert", stdnse.seeall)

StartTLS = {
	
	ftp_prepare_tls_without_reconnect = function(host, port)
		local s = nmap.new_socket()
	    -- Attempt to negotiate TLS over FTP for services that support it
	    -- Works for FTP (21)

	    -- Open a standard TCP socket
	    local status, error = s:connect(host, port, "tcp")
		local result
	    if not status then
	        return false, "Failed to connect to FTP server"
	    else

	        -- Loop until the service presents a banner to deal with server
	        -- load and timing issues.  There may be a better way to handle this.
	        local i = 0
	        repeat
	            status, result = s:receive_lines(1)
	            i = i + 1
	        until string.match(result, "^220") or i == 5

	        -- Send AUTH TLS command, ask the service to start encryption
	        local query = "AUTH TLS\r\n"
	        status = s:send(query)
	        status, result = s:receive_lines(1)

	        if not (string.match(result, "^234")) then
	            stdnse.print_debug("1","%s",result)
	            stdnse.print_debug("1","AUTH TLS failed or unavailable.  Enable --script-trace to see what is happening.")

	            -- Send QUIT to clean up server side connection
	            local query = "QUIT\r\n"
	            status = s:send(query)
	            result = ""

		        return false, "Failed to connect to FTP server"
	        end
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
	            stdnse.print_debug("1","Could not establish SSL session after STARTTLS command.")
	            s:close()
	            return false, "Failed to connect to SMTP server"
	        else 
				return true,s
			end
		end
		return false, "Failed to connect to FTP server"
	end,

	smtp_prepare_tls_without_reconnect = function(host, port)
		local s = nmap.new_socket()
	    -- Attempt to negotiate TLS over SMTP for services that support it
	    -- Works for SMTP (25) and SMTP Submission (587)

	    -- Open a standard TCP socket
	    local status, error = s:connect(host, port, "tcp")  

	    if not status then   
	        return nil
	    else 
			local resultEHLO
	        -- Loop until the service presents a banner to deal with server
	        -- load and timing issues.  There may be a better way to handle this.
	        local i = 0
	        repeat
	            status, resultEHLO = s:receive_lines(1)
	            i = i + 1
	        until string.match(resultEHLO, "^220") or i == 5

	        -- Send EHLO because the the server expects it
	        -- We are not going to check for STARTTLS in the capabilities
	        -- list, sometimes it is not advertised.
	        local query = "EHLO example.org\r\n"
	        status = s:send(query)
	        status, resultEHLO = s:receive_lines(1)

	        if not (string.match(resultEHLO, "^250")) then
	            stdnse.print_debug("1","%s",resultEHLO)
	            stdnse.print_debug("1","EHLO with errors or timeout.  Enable --script-trace to see what is happening.")
	            return false, "Failed to connect to SMTP server"
	        end

	        resultEHLO = ""

	        -- Send STARTTLS command ask the service to start encryption    
	        local query = "STARTTLS\r\n"
	        status = s:send(query)
	        status, resultEHLO = s:receive_lines(1)

	        if not (string.match(resultEHLO, "^220")) then
	            stdnse.print_debug("1","%s",resultEHLO)
	            stdnse.print_debug("1","STARTTLS failed or unavailable.  Enable --script-trace to see what is happening.")

	            -- Send QUIT to clean up server side connection
	            local query = "QUIT\r\n"
	            status = s:send(query)        
	            resultEHLO = ""

	            return false, "Failed to connect to SMTP server"
	        end
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
	            stdnse.print_debug("1","Could not establish SSL session after STARTTLS command.")
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
			stdnse.print_debug("Can't send: %s", err)
			return false, "Failed to connect to XMPP server"
		end	
		status, err = sock:send(xmppStreamStart)
		if not status then
			stdnse.print_debug("Couldn't send: %s", err)
			sock:close()
			return false, "Failed to connect to XMPP server"
		end
		status, result = sock:receive()
		if not status then
			stdnse.print_debug("Couldn't receive: %s", err)
			sock:close()
			return false, "Failed to connect to XMPP server"
		end	
		status, err = sock:send(xmppStartTLS)
		if not status then
			stdnse.print_debug("Couldn't send: %s", err)
			sock:close()
			return false, "Failed to connect to XMPP server"
		end
		status, result = sock:receive()
		if not status then
			stdnse.print_debug("Couldn't receive: %s", err)
			sock:close()
			return false, "Failed to connect to XMPP server"
		end	
		if string.find(result,"proceed") then
			return true,sock
		end 
		
		status, result = sock:receive() -- might not be in the first reply
		if not status then
			stdnse.print_debug("Couldn't receive: %s", err)
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
    [21] = StartTLS.ftp_prepare_tls,
    [25] = StartTLS.smtp_prepare_tls,
    [587] = StartTLS.smtp_prepare_tls,
    [5222] = StartTLS.xmpp_prepare_tls,
    [5269] = StartTLS.xmpp_prepare_tls
}

local SPECIALIZED_PREPARE_TLS_WITHOUT_RECONNECT = {
    [21] = StartTLS.ftp_prepare_tls_without_reconnect,
    [25] = StartTLS.smtp_prepare_tls_without_reconnect,
    [587] = StartTLS.smtp_prepare_tls_without_reconnect,
    [5222] = StartTLS.xmpp_prepare_tls_without_reconnect,
    [5269] = StartTLS.xmpp_prepare_tls_without_reconnect
}

function getPrepareTLSWithoutReconnect(port)
	return SPECIALIZED_PREPARE_TLS_WITHOUT_RECONNECT[port.number]
end

function isPortSupported(port)
	return SPECIALIZED_PREPARE_TLS[port.number]
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
		stdnse.print_debug(2, "sslcert: Returning cached SSL certificate")
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
