description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.

<code>
443/tcp open  https
|  ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
|  Not valid before: 2009-05-28 00:00:00
|_ Not valid after:  2010-05-01 23:59:59
</code>

With <code>-v</code> it adds the issuer name and fingerprints.

<code>
443/tcp open  https
|  ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
|  Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US
|  Not valid before: 2009-05-28 00:00:00
|  Not valid after:  2010-05-01 23:59:59
|  MD5:   c5b8 7ddd ccc7 537f 8861 b476 078d e8fd
|_ SHA-1: dc5a cb8b 9eb9 b5de 7117 c536 8c15 0e75 ba88 702e
</code>

With <code>-vv</code> it adds the PEM-encoded contents of the entire
certificate.

<code>
443/tcp open  https
|  ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US/serialNumber=3014267\
/1.3.6.1.4.1.311.60.2.1.3=US/streetAddress=2211 N 1st St\
/1.3.6.1.4.1.311.60.2.1.2=Delaware/postalCode=95131-2021\
/localityName=San Jose/organizationalUnitName=Information Systems\
/2.5.4.15=V1.0, Clause 5.(b)
|  Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US\
/organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06
|  Not valid before: 2009-05-28 00:00:00
|  Not valid after:  2010-05-01 23:59:59
|  MD5:   c5b8 7ddd ccc7 537f 8861 b476 078d e8fd
|  SHA-1: dc5a cb8b 9eb9 b5de 7117 c536 8c15 0e75 ba88 702e
|  -----BEGIN CERTIFICATE-----
|  MIIFxzCCBK+gAwIBAgIQX02QuADDB7CVjZdooVge+zANBgkqhkiG9w0BAQUFADCB
...
</code>
]]

---
-- @output
-- 443/tcp open  https
-- |  ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
-- /stateOrProvinceName=California/countryName=US
-- |  Not valid before: 2009-05-28 00:00:00
-- |_ Not valid after:  2010-05-01 23:59:59

author = "David Fifield"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = { "safe", "discovery" }

require("nmap")
require("nsedebug")
require("shortport")
require("stdnse")

local stringify_name
local date_to_string
local table_find
local s

local STARTTLS_PORTS = { 25, 587 }

portrule = function(host, port)
    return shortport.ssl(host, port) or table_find(STARTTLS_PORTS, port.number)
end

action = function(host, port)
    s = nmap.new_socket()

    if table_find(STARTTLS_PORTS, port.number) then
        local status = starttls_negotiate(host,port)

        if not status then
            return nil
        end
    else
        local status, error = s:connect(host, port, "ssl")
        
        if not status then
            if nmap.verbosity() > 0 then
                return error
            else
                return nil
            end
        end    

    end 

    local cert = s:get_ssl_certificate()
    s:close()

    local lines = {}
    lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)

    if nmap.verbosity() > 0 then
        lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)
    end

    if nmap.verbosity() > 0 then
        lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
        lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
    end

    lines[#lines + 1] = "Not valid before: " ..
        date_to_string(cert.validity.notBefore)
    lines[#lines + 1] = "Not valid after:  " ..
        date_to_string(cert.validity.notAfter)

    if nmap.verbosity() > 0 then
        lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
        lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
	end

    if nmap.verbosity() > 1 then
        lines[#lines + 1] = cert.pem
    end

    return stdnse.strjoin("\n", lines)
end

-- Find the index of a value in an array.
function table_find(t, value)
    local i, v
    for i, v in ipairs(t) do
        if v == value then
            return i
        end
    end
    return nil
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
    "stateOrProvinceName", "countryName" }

function stringify_name(name)
    local fields = {}
    local _, k, v
    if not name then
        return nil
    end
    for _, k in ipairs(NON_VERBOSE_FIELDS) do
        v = name[k]
        if v then
            fields[#fields + 1] = string.format("%s=%s", k, v)
        end
    end
    if nmap.verbosity() > 1 then
        for k, v in pairs(name) do
            -- Don't include a field twice.
            if not table_find(NON_VERBOSE_FIELDS, k) then
                if type(k) == "table" then
                    k = stdnse.strjoin(".", k)
                end
                fields[#fields + 1] = string.format("%s=%s", k, v)
            end
        end
    end
    return stdnse.strjoin("/", fields)
end

function date_to_string(date)
    if not date then
        return "MISSING"
    end
    if type(date) == "string" then
        return string.format("Can't parse; string is \"%s\"", date)
    else
        return os.date("%Y-%m-%d %H:%M:%S", os.time(date))
    end
end

function starttls_negotiate(host, port)
    -- Attempt to negotiate TLS over SMTP for services that support it
    -- Works for SMTP (25) and SMTP Submission (587)

    -- Open a standard TCP socket
    local status, error = s:connect(host, port, "tcp")  
        
    if not status then   
        return nil
    else 
    
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
            return nil
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
                
            return nil
        end
        
        -- Service supports STARTTLS, tell NSE start SSL negotiation
        status, error = s:reconnect_ssl()
        if not status then
            stdnse.print_debug("1","Could not establish SSL session after STARTTLS command.")
            s:close()
            return nil
        end 
                
    end    
    -- Should have a solid TLS over SMTP session now...
    return "Connected"
end 
