local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local xmpp = require "xmpp"

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
-- |   Respects server name
-- |   info:
-- |     xmpp:
-- |       lang: en
-- |       version: 1.0
-- |     capabilities:
-- |       node: http://www.process-one.net/en/ejabberd/
-- |       ver: TQ2JFyRoSa70h2G1bpgjzuXb2sU=
-- |     features:
-- |       In-Band Registration
-- |     auth_mechanisms:
-- |       DIGEST-MD5
-- |       SCRAM-SHA-1
-- |       PLAIN
-- |   pre_tls:
-- |     features:
-- |_      TLS
--@xmloutput
-- <elem>Respects server name</elem>
-- <table key="info">
--   <table key="xmpp">
--     <elem key="lang">en</elem>
--     <elem key="version">1.0</elem>
--   </table>
--   <table key="capabilities">
--     <elem key="node">http://www.process-one.net/en/ejabberd/</elem>
--     <elem key="ver">TQ2JFyRoSa70h2G1bpgjzuXb2sU=</elem>
--   </table>
--   <table key="features">
--     <elem>In-Band Registration</elem>
--   </table>
--   <table key="auth_mechanisms">
--     <elem>DIGEST-MD5</elem>
--     <elem>SCRAM-SHA-1</elem>
--     <elem>PLAIN</elem>
--   </table>
-- </table>
-- <table key="pre_tls">
--   <table key="features">
--     <elem>TLS</elem>
--   </table>
-- </table>
--
-- @args xmpp-info.server_name If set, overwrites hello name sent to the server.
--       It can be necessary if XMPP server's name differs from DNS name.
-- @args xmpp-info.alt_server_name If set, overwrites alternative hello name sent to the server.
--       This name should differ from the real DNS name.  It is used to find out whether
--       the server refuses to talk if a wrong name is used.  Default is ".".
-- @args xmpp-info.no_starttls If set, disables TLS processing.


author = "Vasiliy Kulikov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery", "version"}


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

local check_citadel = function(id1, id2)
  stdnse.debug1("CHECK")
  local i1 = tonumber(id1, 16)
  local i2 = tonumber(id2, 16)
  return i2 - i1 < 20 and i2 > i1
end

-- Be careful while adding fingerprints into the table - it must be well sorted
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
    name = 'Citadel',
    check = check_citadel
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
  if data then stdnse.debug2("%s", data) end
  return status and xmpp.XML.parse_tag(data)
end

local log_tag = function(tag)
  stdnse.debug2("%s", "name=" .. tag.name)
  stdnse.debug2("%s", "finish=" .. tostring(tag.finish))
  stdnse.debug2("%s", "empty=" .. tostring(tag.empty))
  stdnse.debug2("%s", "contents=" .. tag.contents)
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

local scan = function(host, port, server_name, tls)
  local data, status
  local client = nmap.new_socket()
  local tls_text
  local stream_id

  -- Looks like 10 seconds is enough for non RFC-compliant servers...
  client:set_timeout(10 * 1000);

  local caps = stdnse.output_table()
  local err = {}
  local features_list = {}
  local mechanisms = {}
  local methods = {}
  local unknown = {}
  local t_xmpp = stdnse.output_table()

  local xmlns
  stdnse.debug1(port.version.name)
  if port.version.name == 'xmpp-client' then
    xmlns = "'jabber:client'"
  else
    xmlns = "'jabber:server'"
  end
  if tls then tls_text = ", tls" else tls_text = "" end
  stdnse.debug1("name '" .. server_name .. "', ns '" .. xmlns .. "'" .. tls_text)

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
      table.insert(err, "(timeout)")
      break
    end
    log_tag(tag)
    if tag.name == "stream:features" and tag.finish then
      break
    end

    if inside() and not known_features[tag.name] then
      stdnse.debug1(tag.name)
      table.insert(unknown, tag.name)
    end

    if tag.name == "stream:stream" and tag.start then
      --http://xmpp.org/extensions/xep-0198.html#ns
      if tag.attrs['xmlns:ack'] and
        tag.attrs['xmlns:ack'] == 'http://www.xmpp.org/extensions/xep-0198.html#ns' then
        table.insert(t_xmpp, "Stream Management")
      end
      if tag.attrs['xml:lang'] then
        t_xmpp["lang"] = tag.attrs['xml:lang']
      end
      if tag.attrs.from and tag.attrs.from ~= server_name then
        t_xmpp["server name"] = tag.attrs.from
      end

      stream_id = tag.attrs.id

      if tag.attrs.version then
        t_xmpp["version"] = tag.attrs.version
      else
        -- Alarm! Not an RFC-compliant server...
        -- sample: chirimoyas.es
        t_xmpp["version"] = "(none)"
      end
    end

    if tag.name == "sm" and tag.start and inside() then
      stdnse.debug1("OK")
      --http://xmpp.org/extensions/xep-0198.html
      --sample: el-tramo.be
      local version = string.match(tag.attrs.xmlns, "^urn:xmpp:sm:(%.)")
      table.insert(features_list, 'Stream management v' .. version)
    end

    if tag.name == "starttls" and inside() then
      is_starttls = true
    elseif tag.name == "address" and tag.finish and inside() then
      --http://delta.affinix.com/specs/xmppstream.html
      table.insert(features_list, "MY IP: " .. tag.contents )
    elseif tag.name == "ver" and inside() then
      --http://xmpp.org/extensions/xep-0237.html
      table.insert(features_list, "Roster Versioning")
    elseif tag.name == "dialback" and inside() then
      --http://xmpp.org/extensions/xep-0220.html
      table.insert(features_list, "Server Dialback")
    elseif tag.name == "session" and inside() then
      --http://www.ietf.org/rfc/rfc3921.txt
      table.insert(features_list, "IM Session Establishment")
    elseif tag.name == "bind" and inside() then
      --http://www.ietf.org/rfc/rfc3920.txt
      table.insert(features_list, "Resource Binding")
    elseif tag.name == "amp" and inside() then
      --http://xmpp.org/extensions/xep-0079.html
      table.insert(features_list, "Advanced Message Processing")
    elseif tag.name == "register" and inside() then
      --http://xmpp.org/extensions/xep-0077.html
      --sample: jabber.ru
      table.insert(features_list, "In-Band Registration")
    elseif tag.name == "auth" and inside() then
      --http://xmpp.org/extensions/xep-0078.html
      table.insert(mechanisms, "Non-SASL")
    elseif tag.name == "required" and inside('starttls') then
      tls_required = true
    elseif tag.name == "method" and inside('compression', 'method') then
      --http://xmpp.org/extensions/xep-0138.html
      if tag.finish then
        table.insert(methods, tag.contents)
      end
    elseif tag.name == "mechanism" and inside('mechanisms', 'mechanism') then
      if tag.finish then
        table.insert(mechanisms, tag.contents)
      end
    elseif tag.name == "c" and inside() then
      --http://xmpp.org/extensions/xep-0115.html
      --sample: jabber.ru
      if tag.attrs and tag.attrs.node then
        caps["node"] = tag.attrs.node

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
          port.version.name_confidence = 10
          nmap.set_port_version(host, port)
        end

        -- Funny situation: we have a hash of server capabilities list,
        -- but we cannot explicitly ask him about the list because we have no name before the authentication.
        -- The ugly solution is checking the hash against the most popular capability sets...
        caps["ver"] = tag.attrs.ver
      end
    end

    if tag.name == "stream:error" then
      if tag.start then
        in_error = tag.start
      elseif not got_text then -- non-RFC compliant server!
        if tag.contents ~= "" then
          table.insert(err, {text= tag.contents})
        end
        in_error = false
      end
    elseif in_error then
      if tag.name == "text" then
        if tag.finish then
          got_text = true
          table.insert(err, {text= tag.contents})
        end
      else
        table.insert(err, tag.name)
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
      table.insert(features_list, "TLS (required)")
    else
      table.insert(features_list, "TLS")
    end
  end

  return {
    stream_id=stream_id,
    xmpp=t_xmpp,
    features=features_list,
    capabilities=caps,
    compression_methods=methods,
    auth_mechanisms=mechanisms,
    errors=err,
    unknown=unknown,
  }
end

local server_info = function(host, port, id1, id2)
  for s, v in pairs(id_database) do
    if ((not id1 and not v.regexp1) or (id1 and v.regexp1 and string.find(id1, v.regexp1))) and
      ((not id2 and not v.regexp2) or (id2 and v.regexp2 and string.find(id2, v.regexp2))) then
      if not v.check or v.check(id1, id2) then
        stdnse.debug1("MATCHED")
        port.version.product = v.name
        stdnse.debug1("  " .. v.name)
        port.version.name_confidence = 6
        nmap.set_port_version(host, port)
        break
      end
    end
  end
end

local factor = function( t1, t2 )
  local both = stdnse.output_table()
  local t1only = stdnse.output_table()
  local t2only = stdnse.output_table()
  --ordered key-value categories
  for _, cat in ipairs({"xmpp", "capabilities"}) do
    local both_c = stdnse.output_table()
    local t1only_c = stdnse.output_table()
    local t2only_c = stdnse.output_table()
    local t1c = t1[cat]
    local t2c = t2[cat]
    for k,v in pairs(t1c) do
      if t2c[k] then
        if t2c[k] == v then
          both_c[k] = v
        else
          t1only_c[k] = v
          t2only_c[k] = t2c[k]
        end
      else
        t1only_c[k] = v
      end
    end
    for k, v in pairs(t2c) do
      if not t1c[k] then
        t2only_c[k] = v
      end
    end
    both[cat] = (#both_c and both_c) or nil
    t1only[cat] = (#t1only_c and t1only_c) or nil
    t2only[cat] = (#t2only_c and t2only_c) or nil
  end
  --ordered list categories
  for _, cat in ipairs({"features", "compression_methods", "auth_mechanisms", "errors", "unknown"}) do
    local t1only_c = {}
    local t2only_c = {}
    local both_c = {}
    local t1c = t1[cat]
    local t2c = t2[cat]
    local union = {}
    for _, v in ipairs(t1c) do
      union[v] = 1
    end
    for _, v in ipairs(t2c) do
      if union[v] then
        union[v] = 2
      else
        table.insert(t2only_c, v)
      end
    end
    for v, num in pairs(union) do
      if num == 1 then
        table.insert(t1only_c, v)
      else
        table.insert(both_c, v)
      end
    end
    both[cat] = (next(both_c) and both_c) or nil
    t1only[cat] = (next(t1only_c) and t1only_c) or nil
    t2only[cat] = (next(t2only_c) and t2only_c) or nil
  end
  return both, t1only, t2only
end

portrule = shortport.version_port_or_service({5222, 5269}, {"jabber", "xmpp-client", "xmpp-server"})
action = function(host, port)
  local server_name = stdnse.get_script_args("xmpp-info.server_name") or host.targetname or host.name
  local alt_server_name = stdnse.get_script_args("xmpp-info.alt_server_name") or "."
  local tls_result
  local starttls_failed

  stdnse.debug2("%s", "server = " .. server_name)

  local altname_result = scan(host, port, alt_server_name, false)

  local plain_result = scan(host, port, server_name, false)

  server_info(host, port, altname_result["stream_id"], plain_result["stream_id"])

  if not stdnse.get_script_args("xmpp-info.no_starttls") then
    tls_result = scan(host, port, server_name, true)
    if not tls_result then starttls_failed = 1 end
  end


  local r = stdnse.output_table()

  if #altname_result["errors"] == 0 and #plain_result["errors"] == 0 then
    table.insert(r, "Ignores server name")
  elseif #altname_result["errors"] ~= #plain_result["errors"] then
    table.insert(r, "Respects server name")
  end

  if not tls_result then
    if starttls_failed then table.insert(r, "STARTTLS Failed") end
    r["info"] = plain_result
  else
    local i,p,t = factor(plain_result, tls_result)
    r["info"] = (#i and i) or nil
    r["pre_tls"] = (#p and p) or nil
    r["post_tls"] = (#t and t) or nil
  end

  return r
end
