description = [[
Connect to XMPP server (port 5222) and collect server information such as:
supported auth mechanisms, compression methods and whether TLS is supported
and mandatory.
]]

---
-- @output
-- PORT     STATE SERVICE
-- 5222/tcp open  xmpp-client
-- | xmpp: 
-- |   mechanism: CRAM-MD5
-- |   mechanism: LOGIN
-- |   mechanism: PLAIN
-- |   mechanism: DIGEST-MD5
-- |   mechanism: SCRAM-SHA-1
-- |   compression: zlib
-- |   starttls
-- |_  Respects server name
--
-- @args xmpp.server_name If set, overwrites hello name sent to the server.
--       It can be necessary if XMPP server's name differs from DNS name.
-- @args xmpp.alt_server_name If set, overwrites alternative hello name sent to the server.
--       This name should differ from the real DNS name.  It is used to find out whether
--       the server refuses to talk if a wrong name is used.  Default is ".".


author = "Vasiliy Kulikov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}

require 'shortport'
require 'stdnse'
require 'dns'

-- This is a trivial XML processor.  It doesn't fully support XML, but it should
-- be sufficient for the basic XMPP stream handshake.  If you see stanzas with uncommon
-- symbols, feel free to enhance these regexps.
local parse_tag = function(s)
    local _, _, contents, empty, name = string.find(s, "([^<]*)\<(/?)([?:%w-]+)")
    local attrs = {}
    if not name then
        return
    end
    for k, v in string.gmatch(s, "%s([%w:]+)='([^']+)'") do
        attrs[k] = v
    end
    for k, v in string.gmatch(s, "%s([%w:]+)=\"([^\"]+)\"") do
        attrs[k] = v
    end

    local finish = (empty ~= "") or (s:sub(#s-1) == '/>')

    return { name = name,
             attrs = attrs,
             start = (empty == ""),
             contents = contents,
             finish = finish }
end

local log_tag = function(tag)
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "name=" .. tag.name)
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "finish=" .. tostring(tag.finish))
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "empty=" .. tostring(tag.empty))
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "contents=" .. tag.contents)
end

local receive_tag = function(conn)
    local status, data = conn:receive_buf(">", true)
    if data then
        stdnse.print_debug("%s %s", SCRIPT_NAME, data)
    end
    return status and parse_tag(data)
end

local scan = function(host, port, server_name)
    local client = nmap.new_socket()
    local catch = function()
        client:close()
    end
    local result = {}

    local try = nmap.new_try(catch)

    try(client:connect(host, port))
    local request = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' xml:lang='ru-RU' to='" .. server_name .. "' version='1.0'>"

    try(client:send(request))

    local is_starttls, tls_required, in_error
    while true do
        local tag = receive_tag(client)
        if not tag then break end
        log_tag(tag)
        if (tag.name == "stream:features" and tag.finish) then
            break
        end

        if tag.name == "starttls" then
            is_starttls = true
        elseif tag.name == "required" then
            tls_required = true
        elseif tag.name == "method" then
            if tag.finish then
                table.insert(result, "compression: " .. tag.contents)
            end
        elseif tag.name == "mechanism" then
            if tag.finish then
                table.insert(result, "mechanism: " .. tag.contents)
            end
        elseif tag.name == "c" then 
            if tag.attrs and tag.attrs.hash then
                table.insert(result, "hash: " .. tag.attrs.hash)
            end
        end

        if tag.name == "stream:error" then 
            in_error = tag.start
            if in_error then
                 table.insert(result, "Error:")
            end
        elseif in_error then
            if tag.name == "text" then
                if tag.finish then
                    table.insert(result, " text: " .. tag.contents)
                end
            else
                table.insert(result, " " .. tag.name)
            end
        end
    end

    if is_starttls then
        if tls_required then
            table.insert(result, "starttls (required)")
        else
            table.insert(result, "starttls")
        end
    end
    return result
end

local is_error = function(table)
    for i,v in ipairs(table) do
        if v == "Error:" then return true end
    end
end

portrule = shortport.port_or_service(5222, {"jabber", "xmpp-client"})
action = function(host, port)
    local server_name = stdnse.get_script_args("xmpp.server_name") or host.targetname
    local alt_server_name = stdnse.get_script_args("xmpp.alt_server_name") or "."
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "server = " .. server_name)

    local result = scan(host, port, server_name)
    local alt_result = scan(host, port, alt_server_name)
    if is_error(result) ~= is_error(alt_result) then
        table.insert(result, "Respects server name")
    else
        table.insert(result, "Ignores server name")
    end

    return stdnse.format_output(true, result)
end
