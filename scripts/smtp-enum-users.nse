local nmap = require "nmap"
local shortport = require "shortport"
local smtp = require "smtp"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"

description = [[
Attempts to enumerate the users on a SMTP server by issuing the VRFY, EXPN or RCPT TO
commands. The goal of this script is to discover all the user accounts in the remote
system.

The script will output the list of user names that were found. The script will stop
querying the SMTP server if authentication is enforced. If an error occurrs while testing
the target host, the error will be printed with the list of any combinations that were
found prior to the error.

The user can specify which methods to use and in which order. The script will ignore
repeated methods. If not specified the script will use the RCPT first, then VRFY and EXPN.
An example of how to specify the methods to use and the order is the following:

<code>smtp-enum-users.methods={EXPN,RCPT,VRFY}</code>
]]

---
-- @usage
-- nmap --script smtp-enum-users.nse [--script-args smtp-enum-users.methods={EXPN,...},...] -p 25,465,587 <host>
--
-- @output
-- Host script results:
-- | smtp-enum-users:
-- |_  RCPT, root
--
-- @args smtp.domain or smtp-enum-users.domain Define the domain to be used in the SMTP commands
-- @args smtp-enum-users.methods Define the methods and order to be used by the script (EXPN, VRFY, RCPT)

-- changelog
-- 2010-03-07 Duarte Silva <duarte.silva@serializing.me>
--   * First version ;)
-- 2010-03-14 Duarte Silva
--   * Credits to David Fifield and Ron Bowes for the following changes
--   * Changed the way the user defines which method is used
--   + Script now handles 252 and 550 SMTP status codes
--   + Added the method that was used by the script to discover the users if verbosity is
--     enabled
-- 2011-06-03
--   * Rewrite the script to use the smtp.lua library.
-----------------------------------------------------------------------

author = "Duarte Silva <duarte.silva@serializing.me>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth","external","intrusive"}


portrule = shortport.port_or_service({ 25, 465, 587 },
                { "smtp", "smtps", "submission" })

STATUS_CODES = {
    ERROR = 1,
    NOTPERMITTED = 2,
    VALID = 3,
    INVALID = 4,
    UNKNOWN = 5
}

---Counts the number of occurrences in a table. Helper function
-- from LUA documentation http://lua-users.org/wiki/TableUtils.
--
-- @param from Source table
-- @param what What element to count
-- @return Number of occurrences
function table_count(from, what)
    local result = 0

    for index, item in ipairs(from) do
        if item == what then
            result = result + 1
        end
    end
    return result
end

---Creates a new table from a source without the duplicates. Helper
-- function from LUA documentation http://lua-users.org/wiki/TableUtils.
--
-- @param from Source table
-- @return New table without the duplicates
function table_unique(from)
    local result = {}

    for index, item in ipairs(from) do
        if (table_count(result, item) == 0) then
            result[#result + 1] = item
        end
    end

    return result
end

---Get the method or methods to be used. If the user didn't specify any
-- methods, the default order is RCPT, VRFY and then EXPN.
--
-- @return A table containing the methods to try
function get_method()
    local result = {}

    local methods = stdnse.get_script_args('smtp-enum-users.methods')
    if methods and type(methods) == "table" then
        -- For each method specified.
        for _, method in ipairs(methods) do
            -- Are the elements of the argument valid methods.
            local upper = string.upper(method)
      
            if (upper == "RCPT") or (upper == "EXPN") or
               (upper == "VRFY") then
                table.insert(result, upper)
            else
                return false, method
            end
        end
    end

    -- The methods weren't specified.
    if #result == 0 then
        result = { "RCPT", "VRFY", "EXPN" }
    else
        result = table_unique(result)
    end

    return true, result
end

---Generic function to perform user discovery.
--
-- @param socket Socket used to send the command
-- @param command Command to be used in the discovery
-- @param username User name to test
-- @param domain Domain to use in the command
-- @return Status and depending on the code, a error message
function do_gnrc(socket, command, username, domain)
    local combinations = {
        string.format("%s", username),
        string.format("%s@%s", username, domain)
    }

    for index, combination in ipairs(combinations) do
        -- Lets try to issue the command.
        local status, response = smtp.query(socket, command, combination)

        -- If this command fails to be sent, then something
        -- went wrong with the connection.
        if not status then
            return STATUS_CODES.ERROR,
                   string.format("Failed to issue %s %s command (%s)\n",
                                 command, combination, response)
        end

        if string.match(response, "^530") then
            -- If the command failed, check if authentication is
            -- needed because all the other attempts will fail.
            return STATUS_CODES.AUTHENTICATION
        elseif string.match(response, "^502") or
            string.match(response, "^252") or
            string.match(response, "^550") then
            -- The server doesn't implement the command or it is disallowed.
            return STATUS_CODES.NOTPERMITTED
        elseif smtp.check_reply(command, response) then
            -- User accepted.
            if nmap.verbosity() > 1 then
                return STATUS_CODES.VALID,
                       string.format("%s, %s", command, username)
            else
                return STATUS_CODES.VALID, username
            end
        end
    end

    return STATUS_CODES.INVALID
end

---Verify if a username is valid using the EXPN command (wrapper
-- function for do_gnrc).
--
-- @param socket Socket used to send the command
-- @param username User name to test
-- @param domain Domain to use in the command
-- @return Status and depending on the code, a error message
function do_expn(socket, username, domain)
    return do_gnrc(socket, "EXPN", username, domain)
end

---Verify if a username is valid using the VRFY command (wrapper
-- function for do_gnrc).
--
-- @param socket Socket used to send the command
-- @param username User name to test
-- @param domain Domain to use in the command
-- @return Status and depending on the code, a error message
function do_vrfy(socket, username, domain)
    return do_gnrc(socket, "VRFY", username, domain)
end

issued_from = false

--- Verify if a username is valid using the RCPT method. It will only issue
-- the MAIL FROM command if the issued_from flag is false. The MAIL FROM
-- command does not need to be issued each time an RCPT TO is used. Otherwise
-- it should also be issued a RSET command, and if there are many RSET
-- commands the server might disconnect.
--
-- @param socket Socket used to send the command
-- @param username User name to test
-- @param domain Domain to use in the command
-- @return Status and depending on the code, a error message
function do_rcpt(socket, username, domain)
    local status, response
    if not issued_from then
    -- Lets try to issue MAIL FROM command.
    status, response = smtp.query(socket, "MAIL",
                              string.format("FROM:<usertest@%s>", domain))

    if not status then
        -- If this command fails to be sent, then something went wrong
        -- with the connection.
        return STATUS_CODES.ERROR,
               string.format("Failed to issue MAIL FROM:<usertest@%s> command (%s)",
                             domain, response)
        elseif string.match(response, "^530") then
            -- If the command failed, check if authentication is needed
            -- because all the other attempts will fail.
            return STATUS_CODES.ERROR,
                  "Couldn't perform user enumeration, authentication needed"
        elseif not smtp.check_reply("MAIL", response) then
            -- Only accept 250 code as success.
            return STATUS_CODES.NOTPERMITTED,
                   "Server did not accept the MAIL FROM command"
        end
    end

    status, response = smtp.query(socket, "RCPT",
                              string.format("TO:<%s@%s>", username, domain))

    if not status then
        return STATUS_CODES.ERROR,
            string.format("Failed to issue RCPT TO:<%s@%s> command (%s)",
            username, domain, response)
    elseif string.match(response, "^550") then
        -- 550 User Unknown
        return STATUS_CODES.UNKNOWN
    elseif string.match(response, "^553") then
        -- 553 Relaying Denied
        return STATUS_CODES.NOTPERMITTED
    elseif string.match(response, "^530") then
        -- If the command failed, check if authentication is needed because
        -- all the other attempts will fail.
        return STATUS_CODES.AUTHENTICATION
    elseif smtp.check_reply("RCPT", response) then
        issued_from = true
        -- User is valid.
        if nmap.verbosity() > 1 then
            return STATUS_CODES.VALID, string.format("RCPT, %s", username)
        else
            return STATUS_CODES.VALID, username
        end
    end

    issued_from = true
    return STATUS_CODES.INVALID
end

---Script function that does all the work.
--
-- @param host Target host
-- @param port Target port
-- @return The user accounts or a error message.
function go(host, port)
    -- Get the current usernames list from the file.
    local status, nextuser = unpwdb.usernames()

    if not status then
        return false, "Failed to read the user names database"
    end

    local options = {
        timeout = 10000,
        recv_before = true,
        ssl = true,
    }
    local domain = stdnse.get_script_args('smtp-enum-users.domain') or
                        smtp.get_domain(host)
    
    local methods
    status, methods = get_method()
  
    if not status then
        return false, string.format("Invalid method found, %s", methods)
    end

    local socket, response = smtp.connect(host, port, options)

    -- Failed connection attempt.
    if not socket then
        return false, string.format("Couldn't establish connection on port %i",
                                    port.number)
    end

    status, response = smtp.ehlo(socket, domain)
    if not status then
        return status, response
    end

    local result = {}

    -- This function is used when something goes wrong with
    -- the connection. It makes sure that if it found users before
    -- the error occurred, they will be returned.
    local failure = function(message)
        if #result > 0 then
            table.insert(result, message)
            return true, result
        else
            return false, message
        end
    end

    -- Get the first user to be tested.
    local username = nextuser()

    for index, method in ipairs(methods) do
        while username do
            if method == "RCPT" then
                status, response = do_rcpt(socket, username, domain)
            elseif method == "VRFY" then
                status, response = do_vrfy(socket, username, domain)
            elseif method == "EXPN" then
                status, response = do_expn(socket, username, domain)
            end

            if status == STATUS_CODES.NOTPERMITTED then
                -- Invalid method. Don't test anymore users with
                -- the current method.
                break
            elseif status == STATUS_CODES.VALID then
                -- User found, lets save it.
                table.insert(result, response)
            elseif status == STATUS_CODES.ERROR then
                -- An error occurred with the connection.
                return failure(response)
            elseif status == STATUS_CODES.AUTHENTICATION then
                smtp.quit(socket)
                return false, "Couldn't perform user enumeration, authentication needed"
            elseif status == STATUS_CODES.INVALID then
                table.insert(result,
                      string.format("Method %s returned a unhandled status code.",
                      method))
                break
            end
            username = nextuser()
        end
    
        -- No more users to test, don't test with other methods.
        if username == nil then
            break
        end
    end

    smtp.quit(socket)
    return true, result
end

action = function(host, port)
    local status, result = go(host, port)

    -- The go function returned true, lets check if it
    -- didn't found any accounts.
    if status and #result == 0 then
        return stdnse.format_output(true, "Couldn't find any accounts")
    end

    return stdnse.format_output(true, result)
end
