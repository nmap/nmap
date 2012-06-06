local nmap = require "nmap"
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to relay mail by issuing a predefined combination of SMTP commands. The goal
of this script is to tell if a SMTP server is vulnerable to mail relaying.

An SMTP server that works as an open relay, is a email server that does not verify if the
user is authorised to send email from the specified email address. Therefore, users would
be able to send email originating from any third-party email address that they want.

The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is
hardcoded in the source file. The script will output all the working combinations that the
server allows if nmap is in verbose mode otherwise the script will print the number of
successful tests. The script will not output if the server requires authentication. 

If debug is enabled and an error occurrs while testing the target host, the error will be
printed with the list of any combinations that were found prior to the error.
]]

---
-- @usage
-- nmap --script smtp-open-relay.nse [--script-args smtp-open-relay.domain=<domain>,smtp-open-relay.ip=<address>,...] -p 25,465,587 <host>
--
-- @output
-- Host script results:
-- | smtp-open-relay: Server is an open relay (1/16 tests)
-- |_MAIL FROM:<antispam@insecure.org> -> RCPT TO:<relaytest@insecure.org>
--
-- @args smtp.domain or smtp-open-relay.domain Define the domain to be used in the anti-spam tests and EHLO command (default
-- is nmap.scanme.org)
-- @args smtp-open-relay.ip Use this to change the IP address to be used (default is the target IP address)
-- @args smtp-open-relay.from Define the source email address to be used (without the domain, default is
-- antispam)
-- @args smtp-open-relay.to Define the destination email address to be used (without the domain, default is
-- relaytest)

-- changelog
-- 2007-05-16 Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar>
--   + Added some strings to return in different places
--   * Changed "HELO www.[ourdomain]" to "EHLO [ourdomain]"
--   * Fixed some API differences
--   * The "ourdomain" variable's contents are used instead of hardcoded "insecure.org". Settable by the user.
--   * Fixed tags -> categories (reported by Jason DePriest to nmap-dev)
-- 2009-09-20 Duarte Silva <duarte.silva@serializing.me>
--   * Rewrote the script
--   + Added documentation and some more comments
--   + Parameter to define the domain to be used instead of "ourdomain" variable
--   + Parameter to define the IP address to be used instead of the target IP address
--   * Script now detects servers that enforce authentication
--   * Changed script categories from demo to discovery and intrusive
--   * Renamed "spamtest" strings to "antispam"
-- 2010-02-20 Duarte Silva <duarte.silva@serializing.me>
--   * Renamed script parameters to follow the new naming convention
--   * Fixed problem with broken connections
--   * Changed script output to show all the successful tests
--   * Changed from string concatenation to string formatting
--   + External category
--   + Now the script will issue the QUIT message as specified in the SMTP RFC
-- 2010-02-27 Duarte Silva <duarte.silva@serializing.me>
--   + More information in the script description
--   + Script will output the reason for failed commands (at the connection level)
--   * If some combinations were already found before an error, the script will report them
-- 2010-03-07 Duarte Silva <duarte.silva@serializing.me>
--   * Fixed socket left open when receive_lines function call fails
--   * Minor comments changes
-- 2010-03-14 Duarte Silva <duarte.silva@serializing.me>
--   * Made the script a little more verbose
-- 2011-06-03
--   * Rewrite the script to use the smtp.lua library.

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive","external"}


portrule = shortport.port_or_service({ 25, 465, 587 },
                { "smtp", "smtps", "submission" })

---Gets the user specified parameters to be used in the tests.
--
--@param host Target host (used for the ip parameter default value)
--@return Domain, from, to and ip to be used in the tests
function get_parameters(host)
    -- call smtp.get_domain() without the host table to use the
    -- 'nmap.scanme.org' host name, we are scanning for open relays.
    local domain = stdnse.get_script_args('smtp-open-relay.domain') or
                        smtp.get_domain()

    local from = stdnse.get_script_args('smtp-open-relay.from') or "antispam"
  
    local to = stdnse.get_script_args('smtp-open-relay.to') or "relaytest"
    
    local ip = stdnse.get_script_args('smtp-open-relay.ip') or host.ip
      
    return domain, from, to, ip
end

function go(host, port)
    local options = {
        timeout = 10000,
        recv_before = true,
        ssl = true,
    }

    local result, status, index = {}

    local domain, from, to, ip = get_parameters(host)

    local socket, response = smtp.connect(host, port, options)
    if not socket then
        return false, string.format("Couldn't establish connection on port %i",
                          port.number)
    end

    local srvname = string.match(response, "%d+%s([%w]+[%w%.-]*)")

    local status, response = smtp.ehlo(socket, domain)
    if not status then
        return status, response
    end
       
    if not srvname then
        srvname = string.match(response, "%d+%-([%w]+[%w%.-]*)")
    end

    -- Antispam tests.
    local tests = {
      { 
        from = "",
        to = string.format("%s@%s", to, domain)
      },
      {
        from = string.format("%s@%s", from, domain),
        to = string.format("%s@%s", to, domain)
      },
      {
        from = string.format("%s@%s", from, srvname),
        to = string.format("%s@%s", to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s@%s", to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s%%%s@[%s]", to, domain, ip)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s%%%s@%s", to, domain, srvname)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("\"%s@%s\"", to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("\"%s%%%s\"", to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s@%s@[%s]", to, domain, ip)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("\"%s@%s\"@[%s]", to, domain, ip)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s@%s@%s", to, domain, srvname)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("@[%s]:%s@%s", ip, to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("@%s:%s@%s", srvname, to, domain)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s!%s", domain, to)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s!%s@[%s]", domain, to, ip)
      },
      {
        from = string.format("%s@[%s]", from, ip),
        to = string.format("%s!%s@%s", domain, to, srvname)
      },
    }
  
    -- This function is used when something goes wrong with the connection.
    -- It makes sure that if it found working combinations before the error
    -- occurred, they will be returned. If the debug flag is enabled the
    -- error message will be appended to the combinations list.
    local failure = function(message)
        if #result > 0 then
            table.insert(result, message)
            return true, result
        else
            return false, message
        end
    end

    for index = 1, #tests do
        status, response = smtp.reset(socket)
        if not status then
            if string.match(response, "530") then
                return false, "Server isn't an open relay, authentication needed"
            end
            return failure(response)
        end

        status, response = smtp.query(socket, "MAIL",
                                      string.format("FROM:<%s>",
                                      tests[index]["from"]))
        -- If this command fails to be sent, then something went
        -- wrong with the connection.
        if not status then
            return failure(string.format("Failed to issue %s command (%s)",
                          tests[index]["from"], response))
        end
                  
        if string.match(response, "530") then
            smtp.quit(socket)
            return false, "Server isn't an open relay, authentication needed"
        elseif smtp.check_reply("MAIL", response) then
            -- Lets try to actually relay.
            status, response = smtp.query(socket, "RCPT",
                                          string.format("TO:<%s>",
                                          tests[index]["to"]))
            if not status then
                return failure(string.format("Failed to issue %s command (%s)",
                               tests[index]["to"], response))
            end

            if string.match(response, "530") then
                smtp.quit(socket)
                return false, "Server isn't an open relay, authentication needed"
            elseif smtp.check_reply("RCPT", response) then
                -- Save the working from and to combination.
                table.insert(result,
                             string.format("MAIL FROM:<%s> -> RCPT TO:<%s>",
                             tests[index]["from"], tests[index]["to"]))
            end
        end
    end

    smtp.quit(socket)
    return true, result
end

action = function(host, port)
    local status, result = go(host, port)

    -- The go function returned false, this means that the result is
    -- a simple error message.
    if not status then
        return result
    else
        -- Combinations were found. If verbosity is active, the script
        -- will print all the successful tests. Otherwise it will only
        -- print the conclusion.
        if #result > 0 then
            local final = {}
            table.insert(final,
                        string.format("Server is an open relay (%i/16 tests)",
                        (#result)))

            if nmap.verbosity() > 1 then
                for index, test in ipairs(result) do
                    table.insert(final, test)
                end
            end

            return stdnse.strjoin("\n ", final)
        end

        return "Server doesn't seem to be an open relay, all tests failed"
    end
end
