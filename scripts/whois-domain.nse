local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

hostrule = function( host )
    local is_private, err = ipOps.isPrivate( host.ip )
    if is_private == nil then
      stdnse.print_debug( "%s Error in Hostrule: %s.", SCRIPT_NAME, err )
      return false
    end

    return not is_private
end


action = function( host )

    
    mutexes = {}

    if host.targetname then

        local referral_patterns = {"refer:%s*(.-)\n", "Whois%sServer:%s*(.-)\n"}

        -- Remove www prefix and add a newline.
        query_data = string.gsub(host.targetname, "^www%.", "") .. "\n"

        local result
        local referral = "whois.iana.org"

        while referral do

            if not mutexes[referral] then
                mutexes[referral] = nmap.mutex(referral)
            end

            mutexes[referral] "lock"

            result = {}
            local socket = nmap.new_socket()
            local catch = function()
                stdnse.print_debug( "fail")
                socket:close()
            end

            local status, line = {}
            local try = nmap.new_try( catch )

            socket:set_timeout( 50000 )

            try( socket:connect(referral, 43 ) )
            try( socket:send( query_data ) )

            while true do
                local status, lines = socket:receive_lines(1)
                if not status then
                    break
                else
                    result[#result+1] = lines
                end
            end

            socket:close()

            mutexes[referral] "done"

            if #result == 0 then
                return nil
            end

            table.insert(result, 1, "\n\nDomain name record found at " .. referral .. "\n")

            referral = false
            for _, p in ipairs(referral_patterns) do
                referral = referral or string.match(table.concat(result), p)
            end

        end

        result = table.concat( result )
        return result
    end
    return "You should provide a domain name."
end

