description = [[
Connects to XMPP server (port 5222) and collects server information such as:
supported auth mechanisms, compression methods, whether TLS is supported
and mandatory, stream management, language, support of In-Band registration,
server capabilities.  If possible, studies server vendor.
]]

---
-- @output
-- PORT     STATE SERVICE REASON  VERSION
-- 5222/tcp open  jabber  syn-ack ejabberd (Protocol 1.0)
-- | xmpp-info: 
-- |   XMPP
-- |     Lang
-- |       ru
-- |     v1.0
-- |   features
-- |     In-Band Registration
-- |     TLS (before TLS stream)
-- |   capabilities
-- |     node
-- |       http://www.process-one.net/en/ejabberd/
-- |     ver
-- |       rvAR01fKsc40hT0hOLGDuG25y9o=
-- |   COMPRESSION METHODS (1)
-- |     zlib
-- |   AUTH MECHANISMS (2)
-- |     DIGEST-MD5
-- |     PLAIN (in TLS stream)
-- |_  Ignores server name
--
-- @args xmpp-info.server_name If set, overwrites hello name sent to the server.
--       It can be necessary if XMPP server's name differs from DNS name.
-- @args xmpp-info.alt_server_name If set, overwrites alternative hello name sent to the server.
--       This name should differ from the real DNS name.  It is used to find out whether
--       the server refuses to talk if a wrong name is used.  Default is ".".
-- @args xmpp-info.no_starttls If set, disables TLS processing.


author = "Vasiliy Kulikov"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}

require 'shortport'
require 'stdnse'
require 'dns'
require 'xmpp'

local known_features = {
    ['starttls'] = true,
    ['compression'] = true,
    ['mechanisms'] = true,
    ['register'] = true,
    ['dialback'] = true,
    ['session'] = true,
    ['auth'] = true,
    ['bind'] = true,
    ['c'] = true,
    ['sm'] = true,
    ['amp'] = true,
    ['ver'] = true
}

local check_citadele = function(id1, id2)
    stdnse.print_debug("CHECK")
    local i1 = tonumber(id1, 16)
    local i2 = tonumber(id2, 16)
    return i2 - i1 < 20 and i2 > i1
end

-- Be carefull while adding fingerprints into the table - it must be well sorted
-- as some fingerprints are actually supersetted by another...
local id_database = {
    { 
                --f3af7012-5d06-41dc-b886-42521de4e198
                --''
            regexp1 = '^' .. string.rep('[0-9a-f]', 8) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 12) .. '$',
            regexp2 = '^$',
            name = 'prosody'
    },

    {
            regexp1 = '^' .. string.rep('[0-9a-f]', 8) .. '$',
            regexp2 = '^' .. string.rep('[0-9a-f]', 8) .. '$',
            name = 'Citidel',
            check = check_citadele
    },

    { 
                --1082952309
                --(no)
            regexp1 = '^' .. string.rep('[0-9]', 9) .. '$',
            regexp2 = nil,
            name = 'jabberd'
    },
    { 
                --1082952309
                --(no)
            regexp1 = '^' .. string.rep('[0-9]', 10) .. '$',
            regexp2 = nil,
            name = 'jabberd'
    },

    { 
                --8npnkiriy7ga6bak1bdpzn816tutka5sxvfhe70c
                --egnlry6t9ji87r9dk475ecxc8dtmkuyzalk2jrvt
            regexp1 = '^' .. string.rep('[0-9a-z]', 40) .. '$',
            regexp2 = '^' .. string.rep('[0-9a-z]', 40) .. '$',
            name = 'jabberd2'
    },

    { 
                --4c9e369a841db417
                --fc0a60b82275289e
            regexp1 = '^' .. string.rep('[0-9a-f]', 16) .. '$',
            regexp2 = '^' .. string.rep('[0-9a-f]', 16) .. '$',
            name = 'Isode M-Link'
    },

    { 
                --1114798225
                --494549622
            regexp1 = '^' .. string.rep('[0-9]', 8) .. string.rep('[0-9]?', 2) .. '$',
            regexp2 = '^' .. string.rep('[0-9]', 8) .. string.rep('[0-9]?', 2) .. '$',
            name = 'ejabberd'
    },

    { 
                --5f049d72
                --3b5b40b
            regexp1 = '^' .. string.rep('[0-9a-f]', 6) .. string.rep('[0-9a-f]?', 2) .. '$',
            regexp2 = '^' .. string.rep('[0-9a-f]', 6) .. string.rep('[0-9a-f]?', 2) .. '$',
            name = 'Openfire'
    },


    { 
                --c7cd895f-e006-473b-9623-c0aae85f17fc
                --tigase-error-tigase
            regexp1 = '^' .. string.rep('[0-9a-f]', 8) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 4) .. '[-]' ..
                             string.rep('[0-9a-f]', 12) .. '$',
            regexp2 = '^tigase[-]error[-]tigase$',
            name = 'Tigase'
    },
    { 
                -- tigase.org (in case of bad DNS name):
                --tigase-error-tigase
                --tigase-error-tigase
            regexp1 = '^tigase[-]error[-]tigase$',
            regexp2 = '^tigase[-]error[-]tigase$',
            name = 'Tigase'
    },

    { 
                --4c9e369a841db417
                --fc0a60b82275289e
            regexp1 = '^' .. string.rep('[0-9a-f]', 16) .. '$',
            regexp2 = '^' .. string.rep('[0-9a-f]', 16) .. '$',
            name = 'Isode M-Link'
    },

    {
            regexp1 = "^c2s_",
            regexp2 = "^c2s_",
            name = 'VKontakte/XMPP'
    }
}

local receive_tag = function(conn)
    local status, data = conn:receive_buf(">", true)
    if data then stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, data) end
    return status and xmpp.XML.parse_tag(data)
end

local log_tag = function(tag)
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "name=" .. tag.name)
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "finish=" .. tostring(tag.finish))
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "empty=" .. tostring(tag.empty))
    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "contents=" .. tag.contents)
end

local make_request = function(server_name, xmlns)
    local request = "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams'" ..
                    " xmlns=" .. xmlns .." xml:lang='ru-RU' to='" .. server_name .. "' version='1.0'>"
    return request
end

local connect_tls = function(s, xmlns, server_name)
    local request = make_request(server_name, xmlns)
    request = request .. "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    s:send(request)
    while true do
        local tag = receive_tag(s)
        if not tag then break end
        log_tag(tag)
        if tag.name == "proceed" and tag.finish then
            local status, error = s:reconnect_ssl()
            if status then return true end
            break
        elseif tag.name == "failure" then
            return false
        end
    end
end

local caps = {{}, {}}
local err = {{}, {}}
local features = {{}, {}}
local features_list = {{}, {}}
local mechanisms = {{}, {}}
local methods = {{}, {}}
local tag_stack = {{}, {}}
local t_xmpp = {{}, {}}
local unknown = {}

local scan = function(host, port, server_name, tls, n)
    local data, status
    local client = nmap.new_socket()
    local tls_text
    local result = {}
    local stream_id

    -- Looks like 10 seconds is enough for non RFC-compliant servers...
    client:set_timeout(10 * 1000);

    caps[n] = {}
    err[n] = {}
    features[n] = {}
    features_list[n] = {}
    mechanisms[n] = {}
    methods[n] = {}
    tag_stack[n] = {}
    t_xmpp[n] = {}

    local xmlns
    stdnse.print_debug(port.version.name)
    if port.version.name == 'xmpp-client' then
        xmlns = "'jabber:client'"
    else
        xmlns = "'jabber:server'"
    end
    if tls then tls_text = ", tls" else tls_text = "" end
    stdnse.print_debug("name '" .. server_name .. "', ns '" .. xmlns .. "'" .. tls_text)

    status, data = client:connect(host, port)
    if not status then
        client:close()
        return
    end
    if tls and not connect_tls(client, xmlns, server_name) then
        client:close()
        return
    end

    local request = make_request(server_name, xmlns)

    if not client:send(request) then
        client:close()
        return
    end

    local tag_stack = {}
    table.insert(tag_stack, "")
    local _inside = function(...)
        local v = select('#',...)
        for n = 1, v do
            local e = select(v - n + 1,...)
            if e ~= tag_stack[#tag_stack - n + 1] then return nil end
        end
        return true
    end
    local inside = function(...) return _inside('stream:features', ...) end

    local is_starttls, tls_required, in_error, got_text
    while true do
        local tag = receive_tag(client)
        if not tag then 
            table.insert(err[n], "(timeout)")
            break 
        end
        log_tag(tag)
        if tag.name == "stream:features" and tag.finish then
            break
        end

        if inside() and not known_features[tag.name] then
            stdnse.print_debug(tag.name)
            unknown[tag.name] = true
        end

        if tag.name == "stream:stream" and tag.start then
            --http://xmpp.org/extensions/xep-0198.html#ns
            if tag.attrs['xmlns:ack'] and
               tag.attrs['xmlns:ack'] == 'http://www.xmpp.org/extensions/xep-0198.html#ns' then
                table.insert(t_xmpp[n], "Stream Management")
            end
            if tag.attrs['xml:lang'] then
                table.insert(t_xmpp[n], { name = "Lang", tag.attrs['xml:lang']})
            end
            if tag.attrs.from and tag.attrs.from ~= server_name then
                table.insert(t_xmpp[n], { name = "Server name", tag.attrs.from})
            end

            stream_id = tag.attrs.id

            if tag.attrs.version then
                table.insert(t_xmpp[n], 'v' .. tag.attrs.version)
            else
                -- Alarm! Not an RFC-compliant server...
                -- sample: chirimoyas.es
                table.insert(t_xmpp[n], "(no version)")
            end
        end

        if tag.name == "sm" and tag.start and inside() then
            stdnse.print_debug("OK")
            --http://xmpp.org/extensions/xep-0198.html
            --sample: el-tramo.be
            local version = string.match(tag.attrs.xmlns, "^urn:xmpp:sm:(%.)")
            table.insert(features_list[n], 'Stream management v' .. version)
        end

        if tag.name == "starttls" and inside() then
            is_starttls = true
        elseif tag.name == "address" and tag.finish and inside() then
            --http://delta.affinix.com/specs/xmppstream.html
            table.insert(features_list[n], "MY IP: " .. tag.contents )
        elseif tag.name == "ver" and inside() then
            --http://xmpp.org/extensions/xep-0237.html
            table.insert(features_list[n], "Roster Versioning")
        elseif tag.name == "dialback" and inside() then
            --http://xmpp.org/extensions/xep-0220.html
            table.insert(features_list[n], "Server Dialback")
        elseif tag.name == "session" and inside() then
            --http://www.ietf.org/rfc/rfc3921.txt
            table.insert(features_list[n], "IM Session Establishment")
        elseif tag.name == "bind" and inside() then
            --http://www.ietf.org/rfc/rfc3920.txt
            table.insert(features_list[n], "Resource Binding")
        elseif tag.name == "amp" and inside() then
            --http://xmpp.org/extensions/xep-0079.html
            table.insert(features_list[n], "Advanced Message Processing")
        elseif tag.name == "register" and inside() then
            --http://xmpp.org/extensions/xep-0077.html
            --sample: jabber.ru
            table.insert(features_list[n], "In-Band Registration")
        elseif tag.name == "auth" and inside() then
            --http://xmpp.org/extensions/xep-0078.html
            table.insert(mechanisms[n], "Non-SASL")
        elseif tag.name == "required" and inside('starttls') then
            tls_required = true
        elseif tag.name == "method" and inside('compression', 'method') then
            --http://xmpp.org/extensions/xep-0138.html
            if tag.finish then
                table.insert(methods[n], tag.contents)
            end
        elseif tag.name == "mechanism" and inside('mechanisms', 'mechanism') then
            if tag.finish then
                table.insert(mechanisms[n], tag.contents)
            end
        elseif tag.name == "c" and inside() then 
            --http://xmpp.org/extensions/xep-0115.html
            --sample: jabber.ru
            if tag.attrs and tag.attrs.node then
                table.insert(caps[n], { name = "node", tag.attrs.node})

                -- It is a table of well-known node values of "c" tag
                -- If it matched then the server software is determined
                --TODO: Add more hints
                --      I cannot find any non-ejabberd public server publishing its <c> :(
                local hints = {
                    ["http://www.process-one.net/en/ejabberd/"] = "ejabberd"
                }
                local hint = hints[tag.attrs.node]
                if hint then
                    port.state = "open"
                    port.version.product = hint
                    port.version.name_confidence = 100
                    nmap.set_port_version(host, port, "hardmatched")
                end

                -- Funny situation: we have a hash of server capabilities list,
                -- but we cannot explicitly ask him about the list because we have no name before the authentication.
                -- The ugly solution is checking the hash against the most popular capability sets...
                table.insert(caps[n], { name = "ver", tag.attrs.ver})
            end
        end

        if tag.name == "stream:error" then 
            if tag.start then
                in_error = tag.start
            elseif not got_text then -- non-RFC compliant server!
                if tag.contents ~= "" then 
                    table.insert(err[n], { name = "text", tag.contents })
                end
                in_error = false
            end
        elseif in_error then
            if tag.name == "text" then
                if tag.finish then
                    got_text = true
                    table.insert(err[n], { name = "text", tag.contents })
                end
            else
                table.insert(err[n], tag.name)
            end
        end

        if tag.start and not tag.finish then
            table.insert(tag_stack, tag.name)
        elseif not tag.start and tag.finish and #tag_stack > 1 then
            table.remove(tag_stack, #tag_stack)
        end
    end

    if is_starttls then
        if tls_required then
            table.insert(features_list[n], "TLS (required)")
        else
            table.insert(features_list[n], "TLS")
        end
    end

    return stream_id
end

local server_info = function(host, port, id1, id2)
    for s, v in pairs(id_database) do
        if ((not id1 and not v.regexp1) or (id1 and v.regexp1 and string.find(id1, v.regexp1))) and
           ((not id2 and not v.regexp2) or (id2 and v.regexp2 and string.find(id2, v.regexp2))) then
            if not v.check or v.check(id1, id2) then
                stdnse.print_debug("MATCHED")
                port.version.product = v.name
                stdnse.print_debug("  " .. v.name)
                port.version.name_confidence = 60
                nmap.set_port_version(host, port, "hardmatched")
                break
            end
        end
    end
end

local copy_table = function(to, from)
    for _,f in pairs(from) do table.insert(to, f) end
end


--Some stuff to transform two tables into one

local cmp = function(a, b)
    if type(a) == "table" then
        return a['name'] == b['name'] and a[1] == b[1]
    else
        return a == b
    end
end

local get_10_ = function(arr, s)
    local r = {}
    for _,f in ipairs(arr[1]) do
        local seen = 0
        for _,ff in ipairs(arr[2]) do
            if cmp(f, ff) then seen = 1 end
        end
        if seen == s then table.insert(r, f) end
    end
    return r
end
local get_10 = function(arr) return get_10_(arr, 0) end
local get_01 = function(arr) return get_10({ arr[2], arr[1] }) end
local get_11 = function(arr) return get_10_(arr, 1) end
local get_any = function(arr)
    local tmp = {}
    copy_table(tmp, arr[1])
    local a01 = get_01(arr)
    copy_table(tmp, a01)
    return tmp
end

local format_el = function(el, comment)
    if el['name'] then
        return { name = el['name'] .. comment, el[1] }
    else
        return el .. comment
    end
end

local format_block_12 = function(t, name)
    local t11 = get_11(t)
    local t10 = get_10(t)
    local t01 = get_01(t)
    local r = { name = name }

    if #t11 == 0 and #t10 == 0 and #t01 == 0 then return {} end

    for _, el in ipairs(t11) do table.insert(r, el) end
    for _, el in ipairs(t10) do table.insert(r, format_el(el, ' (before TLS stream)')) end
    for _, el in ipairs(t01) do table.insert(r, format_el(el, ' (in TLS stream)')) end
    return r
end

local format_block_1 = function(t, name)
    local res = { name = name }
    if #t[1] == 0 then return {} end
    copy_table(res, t[1])
    return res
end

portrule = shortport.port_or_service({5222, 5269}, {"jabber", "xmpp-client", "xmpp-server"})
action = function(host, port)
    local server_name = stdnse.get_script_args("xmpp-info.server_name") or host.targetname
    local alt_server_name = stdnse.get_script_args("xmpp-info.alt_server_name") or "."
    local err_tmp = { {}, {} }
    local id_tls
    local starttls_failed

    stdnse.print_debug(2, "%s: %s", SCRIPT_NAME, "server = " .. server_name)

    local id2 = scan(host, port, alt_server_name, false, 1)
    copy_table(err_tmp[1], err[1])

    local id1 = scan(host, port, server_name, false, 1)
    copy_table(err_tmp[2], err[1])

    server_info(host, port, id1, id2)

    if not stdnse.get_script_args("xmpp-info.no_starttls") then
        id_tls = scan(host, port, server_name, true, 2)
        if not id_tls then starttls_failed = 1 end
    end


    local r = {}

    format_block = format_block_12
    if not id_tls then
        format_block = format_block_1
        if starttls_failed then table.insert(r, "STARTTLS Failed") end
    end

    table.insert(r, format_block(t_xmpp, "XMPP"))
    table.insert(r, format_block(features_list, "features"))
    table.insert(r, format_block(caps, "capabilities"))
    table.insert(r, format_block(methods, "COMPRESSION METHODS (" .. #(get_any(methods)) .. ")"))
    table.insert(r, format_block(mechanisms, "AUTH MECHANISMS (" .. #get_any(mechanisms) .. ")"))
    table.insert(r, format_block(err, "errors"))

    local l = { name = 'Unknown features (please report about it on nmap-dev@)' }
    copy_table(l, unknown)
    table.insert(r, l)

    if #err_tmp[1] == 0 or #err_tmp[2] == 0 then
        if (#err_tmp[1] > 0) ~= (#err_tmp[2] > 0) then
            table.insert(r, "Respects server name")
        else
            table.insert(r, "Ignores server name")
        end
    end

    return stdnse.format_output(true, r)
end
