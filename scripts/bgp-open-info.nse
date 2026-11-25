local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Reads what a BGP speaker on TCP 179 reveals, and decodes every BGP message it sends: OPEN (version, My AS,
4-byte AS, hold time, BGP identifier, every capability incl. FQDN hostname/domain) and NOTIFICATION
(code/subcode with names, RFC 8203/9003 shutdown communication text).

PASSIVE by default: connect, read for a bounded time, parse, close. Nothing is sent at the BGP layer. Many
speakers send their OPEN as soon as a configured neighbour connects; others send NOTIFICATION Cease 6/5
(connection rejected) or just close.

ACTIVE only on explicit opt-in (bgp-open-info.send-open=true plus bgp-open-info.asn): send one OPEN
(4-byte AS capability, AS_TRANS 23456 in the 2-byte field when the AS is above 65535, MP ipv4-unicast, route
refresh), read the reply, and if the remote OPENs back send ONE NOTIFICATION Cease 6/2 (administrative
shutdown) and close. KEEPALIVE and UPDATE are never sent, so the session never reaches Established.
]]

---
-- @usage
-- nmap -Pn -p 179 --script ./bgp-open-info.nse <target>
-- nmap -Pn -p 179 --script ./bgp-open-info.nse --script-args bgp-open-info.send-open=true,bgp-open-info.asn=64513 <target>
--
-- @args bgp-open-info.timeout    total time budget for the read (default 5s)
-- @args bgp-open-info.send-open  true = ACTIVE mode (send one OPEN, then Cease). Default false (PASSIVE)
-- @args bgp-open-info.asn        our AS for the OPEN (required in ACTIVE mode, 1..4294967295)
-- @args bgp-open-info.router-id  our BGP identifier, dotted quad (default 192.0.2.1)
-- @args bgp-open-info.holdtime   hold time in the OPEN, 0 or 3..65535 (default 180)
-- @args bgp-open-info.capabilities comma list from mp-ipv4-unicast,route-refresh,as4 (default all three;
--                                  as4 is always sent when the AS is above 65535)
--
-- @output
-- PORT    STATE SERVICE
-- 179/tcp open  bgp
-- | bgp-open-info:
-- |   mode: passive (nothing sent)
-- |   received: OPEN
-- |   OPEN: version 4, My AS 64512, hold time 9, BGP identifier 192.0.2.2
-- |   AS (4-byte capability): 64512
-- |   capabilities:
-- |     1 multiprotocol: ipv4 unicast
-- |     2 route refresh
-- |     73 FQDN: hostname lab-bgpd, domain (empty)
-- |_  sent: nothing
--
-- @xmloutput
-- <elem key="mode">passive</elem>
-- <elem key="version">4</elem>
-- <elem key="as">64512</elem>
-- <elem key="as4">64512</elem>
-- <elem key="holdtime">9</elem>
-- <elem key="bgp_id">192.0.2.2</elem>
-- <table key="capabilities"><table><elem key="code">1</elem><elem key="name">multiprotocol</elem>...</table></table>

author = "Nikolay Spiridonov v@offsec.pz.it 2026-11-25"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service(179, "bgp", "tcp", "open")

local TYPE_OPEN, TYPE_UPDATE, TYPE_NOTIFICATION, TYPE_KEEPALIVE, TYPE_ROUTE_REFRESH = 1, 2, 3, 4, 5
local TYPE_NAMES = {[1] = "OPEN", [2] = "UPDATE", [3] = "NOTIFICATION", [4] = "KEEPALIVE", [5] = "ROUTE-REFRESH"}
local MARKER = string.rep("\255", 16)
local HEADER_LEN = 19
local MAX_MSG = 4096
local MAX_MSG_EXTENDED = 65535
local MAX_MESSAGES = 16
local MAX_BUFFER = 2 * MAX_MSG_EXTENDED + 4096
local AS_TRANS = 23456

-- Every fixed-size read from untrusted bytes goes through here: the length is checked BEFORE string.unpack.
local function u(fmt, s, pos, need)
  if pos < 1 or pos + need - 1 > #s then
    return nil
  end
  return string.unpack(fmt, s, pos)
end

local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function ipv4(n)
  return string.format("%d.%d.%d.%d", (n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255)
end

local AFI = {[1] = "ipv4", [2] = "ipv6", [25] = "l2vpn"}
local SAFI = {[1] = "unicast", [2] = "multicast", [4] = "labeled-unicast", [5] = "mcast-vpn", [65] = "vpls",
  [70] = "evpn", [73] = "sr-te", [128] = "vpn", [129] = "vpn-multicast", [132] = "route-target",
  [133] = "flowspec", [134] = "flowspec-vpn"}

local function afisafi(afi, safi)
  return string.format("%s %s", AFI[afi] or ("afi " .. afi), SAFI[safi] or ("safi " .. safi))
end

local CAP_NAMES = {[1] = "multiprotocol", [2] = "route refresh", [5] = "extended next hop", [6] = "extended message",
  [9] = "BGP role", [64] = "graceful restart", [65] = "4-byte AS", [69] = "add-path", [70] = "enhanced route refresh",
  [71] = "long-lived graceful restart", [73] = "FQDN", [76] = "paths-limit", [128] = "route refresh (old)"}

-- Decode one capability value. Returns (structured table, human text). Never errors on short data.
local function decode_capability(code, value)
  local t = {code = code, name = CAP_NAMES[code] or "unknown", length = #value}
  local text
  if code == 1 then
    local afi, safi = u(">I2", value, 1, 2), u("B", value, 4, 1)
    if afi and safi and #value == 4 then
      t.afi, t.safi = afi, safi
      text = "multiprotocol: " .. afisafi(afi, safi)
    end
  elseif code == 2 or code == 6 or code == 70 or code == 128 then
    if #value == 0 then text = t.name end
  elseif code == 65 then
    local as4 = u(">I4", value, 1, 4)
    if as4 and #value == 4 then
      t.as4 = as4
      text = "4-byte AS: " .. as4
    end
  elseif code == 64 then
    local ft = u(">I2", value, 1, 2)
    if ft and (#value - 2) % 4 == 0 then
      t.restart_flag = (ft & 0x8000) ~= 0
      t.notification_flag = (ft & 0x4000) ~= 0
      t.restart_time = ft & 0x0fff
      local fams = {}
      local pos = 3
      while pos + 3 <= #value do
        local afi, safi, fl = u(">I2", value, pos, 2), u("B", value, pos + 2, 1), u("B", value, pos + 3, 1)
        fams[#fams + 1] = afisafi(afi, safi) .. (((fl & 0x80) ~= 0) and " (forwarding preserved)" or "")
        pos = pos + 4
      end
      t.families = fams
      text = string.format("graceful restart: restart time %ds%s%s%s", t.restart_time,
        t.restart_flag and ", R" or "", t.notification_flag and ", N" or "",
        #fams > 0 and (", " .. table.concat(fams, "; ")) or "")
    end
  elseif code == 69 then
    if #value % 4 == 0 then
      local fams, pos = {}, 1
      local dir = {[1] = "receive", [2] = "send", [3] = "send/receive"}
      while pos + 3 <= #value do
        local afi, safi, sr = u(">I2", value, pos, 2), u("B", value, pos + 2, 1), u("B", value, pos + 3, 1)
        fams[#fams + 1] = afisafi(afi, safi) .. " " .. (dir[sr] or ("mode " .. sr))
        pos = pos + 4
      end
      t.families = fams
      text = "add-path: " .. table.concat(fams, "; ")
    end
  elseif code == 71 then
    if #value % 7 == 0 then
      local fams, pos = {}, 1
      while pos + 6 <= #value do
        local afi, safi = u(">I2", value, pos, 2), u("B", value, pos + 2, 1)
        local hi, lo = u("B", value, pos + 4, 1), u(">I2", value, pos + 5, 2)
        fams[#fams + 1] = string.format("%s stale time %ds", afisafi(afi, safi), (hi << 16) | lo)
        pos = pos + 7
      end
      t.families = fams
      text = "long-lived graceful restart: " .. (#fams > 0 and table.concat(fams, "; ") or "no families")
    end
  elseif code == 73 then
    local hlen = u("B", value, 1, 1)
    if hlen and 1 + hlen + 1 <= #value then
      local host = value:sub(2, 1 + hlen)
      local dlen = u("B", value, 2 + hlen, 1)
      if dlen and 2 + hlen + dlen == #value then
        local dom = value:sub(3 + hlen, 2 + hlen + dlen)
        t.hostname, t.domain = host, dom
        text = string.format("FQDN: hostname %s, domain %s", host ~= "" and host or "(empty)",
          dom ~= "" and dom or "(empty)")
      end
    end
  elseif code == 76 then
    -- Paths-Limit: draft-abraitis-idr-addpath-paths-limit (draft only; the name is FRR's, not a final IANA
    -- assignment). Value = one or more 5-byte tuples: AFI (2), SAFI (1), paths limit (2); 0 = no limit.
    if #value > 0 and #value % 5 == 0 then
      local fams, pos = {}, 1
      while pos + 4 <= #value do
        local afi, safi, limit = u(">I2", value, pos, 2), u("B", value, pos + 2, 1), u(">I2", value, pos + 3, 2)
        fams[#fams + 1] = string.format("%s, limit %s", afisafi(afi, safi),
          limit == 0 and "0 (no limit)" or tostring(limit))
        pos = pos + 5
      end
      t.families = fams
      text = "paths-limit: " .. table.concat(fams, "; ")
    end
  elseif code == 9 then
    local role = u("B", value, 1, 1)
    local roles = {[0] = "provider", [1] = "rs", [2] = "rs-client", [3] = "customer", [4] = "peer"}
    if role and #value == 1 then
      t.role = roles[role] or tostring(role)
      text = "BGP role: " .. t.role
    end
  end
  if not text then
    t.hex = hex(value)
    text = string.format("%s (length %d)%s", CAP_NAMES[code] or "unknown", #value,
      #value > 0 and (" hex " .. t.hex) or "")
  end
  return t, string.format("%d %s", code, text)
end

local function parse_capabilities(params, caps, lines)
  local pos = 1
  while pos <= #params do
    local code, len = u("B", params, pos, 1), u("B", params, pos + 1, 1)
    if not code or not len or pos + 1 + len > #params then
      return "capability truncated at offset " .. (pos - 1)
    end
    local t, line = decode_capability(code, params:sub(pos + 2, pos + 1 + len))
    caps[#caps + 1] = t
    lines[#lines + 1] = line
    pos = pos + 2 + len
  end
  return nil
end

local function decode_open(body, out)
  local version, myas, hold, bgpid = u("B", body, 1, 1), u(">I2", body, 2, 2), u(">I2", body, 4, 2), u(">I4", body, 6, 4)
  local optlen = u("B", body, 10, 1)
  if not (version and myas and hold and bgpid and optlen) then
    return "OPEN shorter than 10 bytes"
  end
  out.result.version, out.result.as, out.result.holdtime, out.result.bgp_id = version, myas, hold, ipv4(bgpid)
  out.lines[#out.lines + 1] = string.format("OPEN: version %d, My AS %d, hold time %d, BGP identifier %s",
    version, myas, hold, ipv4(bgpid))
  local pos, stop, wide = 11, 10 + optlen, false
  local nonext = u("B", body, 11, 1)
  if optlen == 255 and nonext == 255 then   -- RFC 9072 extended optional parameters length
    local ext = u(">I2", body, 12, 2)
    if not ext then return "OPEN extended parameters length truncated" end
    pos, stop, wide = 14, 13 + ext, true
  end
  if stop ~= #body then
    return string.format("OPEN optional parameters length %d does not match the message", stop - 10)
  end
  local caps, caplines = {}, {}
  while pos <= stop do
    local ptype = u("B", body, pos, 1)
    local plen = wide and u(">I2", body, pos + 1, 2) or u("B", body, pos + 1, 1)
    local hlen = wide and 3 or 2
    if not ptype or not plen or pos + hlen - 1 + plen > stop then
      return "OPEN optional parameter truncated at offset " .. (pos - 1)
    end
    local pval = body:sub(pos + hlen, pos + hlen - 1 + plen)
    if ptype == 2 then
      local err = parse_capabilities(pval, caps, caplines)
      if err then return err end
    else
      caps[#caps + 1] = {param_type = ptype, length = plen, hex = hex(pval)}
      caplines[#caplines + 1] = string.format("optional parameter %d (length %d) hex %s", ptype, plen, hex(pval))
    end
    pos = pos + hlen + plen
  end
  for _, c in ipairs(caps) do
    if c.code == 65 and c.as4 then
      out.result.as4 = c.as4
      out.lines[#out.lines + 1] = string.format("AS (4-byte capability): %d%s", c.as4,
        (myas == AS_TRANS and c.as4 > 65535) and " (My AS field is AS_TRANS 23456)" or "")
    end
    if c.code == 6 and c.length == 0 then
      out.extended_message = true
    end
  end
  if out.result.as4 == nil then
    out.lines[#out.lines + 1] = "AS (4-byte capability): not advertised"
  end
  out.result.capabilities = caps
  out.lines[#out.lines + 1] = "capabilities:"
  out.lines[#out.lines + 1] = caplines
  return nil
end

local NOTIF = {
  [1] = {"Message Header Error", {"Connection Not Synchronized", "Bad Message Length", "Bad Message Type"}},
  [2] = {"OPEN Message Error", {"Unsupported Version Number", "Bad Peer AS", "Bad BGP Identifier",
    "Unsupported Optional Parameter", "Authentication Failure (deprecated)", "Unacceptable Hold Time",
    "Unsupported Capability", nil, nil, nil, "Role Mismatch"}},
  [3] = {"UPDATE Message Error", {"Malformed Attribute List", "Unrecognized Well-known Attribute",
    "Missing Well-known Attribute", "Attribute Flags Error", "Attribute Length Error", "Invalid ORIGIN Attribute",
    "AS Routing Loop (deprecated)", "Invalid NEXT_HOP Attribute", "Optional Attribute Error",
    "Invalid Network Field", "Malformed AS_PATH"}},
  [4] = {"Hold Timer Expired", {}},
  [5] = {"Finite State Machine Error", {"Unexpected Message in OpenSent State",
    "Unexpected Message in OpenConfirm State", "Unexpected Message in Established State"}},
  [6] = {"Cease", {"Maximum Number of Prefixes Reached", "Administrative Shutdown", "Peer De-configured",
    "Administrative Reset", "Connection Rejected", "Other Configuration Change",
    "Connection Collision Resolution", "Out of Resources", "Hard Reset", "BFD Down"}},
  [7] = {"ROUTE-REFRESH Message Error", {"Invalid Message Length"}},
}

local function decode_notification(body, out)
  local code, sub = u("B", body, 1, 1), u("B", body, 2, 1)
  if not code or not sub then
    return "NOTIFICATION shorter than 2 bytes"
  end
  local entry = NOTIF[code]
  local cname = entry and entry[1] or "unknown"
  local sname = (entry and entry[2][sub]) or (sub == 0 and "unspecific") or "unknown"
  out.result.notification_code, out.result.notification_subcode = code, sub
  out.result.notification_name = cname .. " / " .. sname
  out.lines[#out.lines + 1] = string.format("NOTIFICATION: %d/%d %s / %s", code, sub, cname, sname)
  local data = body:sub(3)
  if code == 6 and (sub == 2 or sub == 4) and #data >= 1 then
    local mlen = u("B", data, 1, 1)
    if mlen and mlen > 0 and 1 + mlen <= #data then   -- RFC 8203 / 9003 shutdown communication
      out.result.shutdown_message = data:sub(2, 1 + mlen)
      out.lines[#out.lines + 1] = string.format("shutdown communication: %q", out.result.shutdown_message)
      data = data:sub(2 + mlen)
    elseif mlen == 0 then
      data = data:sub(2)
    end
  end
  if #data > 0 then
    out.result.notification_data = hex(data)
    out.lines[#out.lines + 1] = "NOTIFICATION data hex " .. hex(data)
  end
  return nil
end

-- Split a buffer into complete BGP messages. Returns (messages, consumed, problem). Bounded by MAX_MESSAGES.
local function split_messages(buf, maxlen)
  local msgs, pos = {}, 1
  while #msgs < MAX_MESSAGES and #buf - pos + 1 >= HEADER_LEN do
    if buf:sub(pos, pos + 15) ~= MARKER then
      return msgs, pos - 1, string.format("malformed: bad marker at offset %d", pos - 1)
    end
    local len, typ = u(">I2", buf, pos + 16, 2), u("B", buf, pos + 18, 1)
    if len < HEADER_LEN or len > maxlen then
      return msgs, pos - 1, string.format("malformed: message length %d out of range %d..%d", len, HEADER_LEN, maxlen)
    end
    if #buf - pos + 1 < len then
      break
    end
    msgs[#msgs + 1] = {type = typ, length = len, body = buf:sub(pos + HEADER_LEN, pos + len - 1)}
    pos = pos + len
  end
  return msgs, pos - 1, nil
end

-- Build a BGP message. Only OPEN and NOTIFICATION may ever be built: this script never sends KEEPALIVE or UPDATE.
local function bgp_message(typ, body)
  assert(typ == TYPE_OPEN or typ == TYPE_NOTIFICATION, "bgp-open-info only ever sends OPEN or NOTIFICATION")
  return MARKER .. string.pack(">I2 B", HEADER_LEN + #body, typ) .. body
end

local function build_open(asn, router_id, holdtime, capnames)
  local caps = ""
  local want = {}
  for _, c in ipairs(capnames) do want[c] = true end
  if want["mp-ipv4-unicast"] then caps = caps .. string.pack(">B B I2 B B", 1, 4, 1, 0, 1) end
  if want["route-refresh"] then caps = caps .. string.pack(">B B", 2, 0) end
  if want["as4"] or asn > 65535 then caps = caps .. string.pack(">B B I4", 65, 4, asn) end
  local params = caps ~= "" and string.pack(">B B", 2, #caps) .. caps or ""
  local my = asn > 65535 and AS_TRANS or asn
  return bgp_message(TYPE_OPEN, string.pack(">B I2 I2 I4 B", 4, my, holdtime, router_id, #params) .. params)
end

local function build_cease_admin_shutdown()
  return bgp_message(TYPE_NOTIFICATION, string.pack(">B B", 6, 2))
end

local function new_out(mode)
  local out = {result = stdnse.output_table(), lines = {}, sent = {}, received = {}}
  out.result.mode = mode
  return out
end

-- Read until: an OPEN or NOTIFICATION is decoded (and stop_after_open), EOF/RST, the deadline, or the caps.
-- state.buf carries undecoded bytes between calls. Returns (status_text or nil).
local function read_and_decode(sock, out, state, deadline, stop_on_open)
  while true do
    local maxlen = out.extended_message and MAX_MSG_EXTENDED or MAX_MSG
    local msgs, consumed, problem = split_messages(state.buf, maxlen)
    state.buf = state.buf:sub(consumed + 1)
    for _, m in ipairs(msgs) do
      local name = TYPE_NAMES[m.type] or ("type " .. m.type)
      out.received[#out.received + 1] = name
      local err
      if m.type == TYPE_OPEN then
        err = decode_open(m.body, out)
        state.got_open = true
      elseif m.type == TYPE_NOTIFICATION then
        err = decode_notification(m.body, out)
        state.got_notification = true
      end
      if err then
        out.result.malformed = err
        out.lines[#out.lines + 1] = "malformed: " .. err
        return "malformed"
      end
    end
    if problem then
      out.result.malformed = problem
      out.lines[#out.lines + 1] = problem
      return "malformed"
    end
    if #out.received >= MAX_MESSAGES then return "message limit" end
    if state.got_notification then return "notification" end
    if stop_on_open and state.got_open then return "open" end
    local remaining = deadline - nmap.clock_ms()
    if remaining <= 0 then return "timeout" end
    if #state.buf > MAX_BUFFER then
      out.result.malformed = "more than " .. MAX_BUFFER .. " undecoded bytes"
      return "malformed"
    end
    sock:set_timeout(remaining)
    local ok, data = sock:receive()
    if not ok then
      local e = tostring(data)
      if e:find("TIMEOUT") then return "timeout" end
      if e:lower():find("reset") or e == "ERROR" then return "reset" end   -- nsock reports an RST as ERROR
      if e:find("EOF") then return "closed" end
      return "error: " .. e
    end
    state.buf = state.buf .. data
  end
end

local function render(out, text)
  out.result.status = text
  out.result.received = #out.received > 0 and out.received or {"nothing"}
  out.result.sent = #out.sent > 0 and out.sent or {"nothing"}
  local lines = {"mode: " .. (out.result.mode == "passive" and "passive (nothing sent)" or
    "active (OPEN sent; Cease 6/2 after a remote OPEN; never KEEPALIVE/UPDATE)"),
    "status: " .. text, "received: " .. table.concat(out.result.received, ", ")}
  for _, l in ipairs(out.lines) do lines[#lines + 1] = l end
  lines[#lines + 1] = "sent: " .. table.concat(out.result.sent, ", ")
  return out.result, stdnse.format_output(true, lines)
end

local function finish(out, status, state)
  if #state.buf > 0 and not out.result.malformed then
    out.result.malformed = string.format("truncated: %d trailing bytes do not form a complete message", #state.buf)
    out.lines[#out.lines + 1] = "malformed: " .. out.result.malformed
  end
  local text = ({closed = "closed by the remote", reset = "connection reset by peer (RST) or socket error",
    timeout = "read time budget reached", open = "OPEN received", notification = "NOTIFICATION received",
    malformed = "malformed BGP data"})[status] or status
  if #out.received == 0 then
    if status == "closed" then text = "closed without BGP message"
    elseif status == "reset" then text = "connection reset by peer (RST) or socket error, without BGP message"
    elseif status == "timeout" then text = "no BGP message within the time budget" end
  end
  return render(out, text)
end

local function fail(out, msg)
  return render(out, msg)
end

local function connect(host, port, deadline)
  local sock = nmap.new_socket()
  sock:set_timeout(math.max(1, deadline - nmap.clock_ms()))
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then
    return nil, err
  end
  return sock
end

-- PASSIVE: connect, read, decode, close. This function never sends.
local function run_passive(host, port, deadline)
  local out = new_out("passive")
  local sock, err = connect(host, port, deadline)
  if not sock then return fail(out, "connect failed: " .. tostring(err)) end
  local state = {buf = ""}
  local status = read_and_decode(sock, out, state, deadline, true)
  sock:close()
  return finish(out, status, state)
end
-- end run_passive

local function parse_router_id(s)
  local a, b, c, d = (s or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if not (a and b and c and d) or a > 255 or b > 255 or c > 255 or d > 255 then return nil end
  return (a << 24) | (b << 16) | (c << 8) | d
end

-- ACTIVE: one OPEN out; if the remote OPENs back, one NOTIFICATION Cease 6/2 out; close.
local function run_active(host, port, deadline, asn, router_id, holdtime, capnames)
  local out = new_out("active")
  local sock, err = connect(host, port, deadline)
  if not sock then return fail(out, "connect failed: " .. tostring(err)) end
  local ok, serr = sock:send(build_open(asn, router_id, holdtime, capnames))
  if not ok then
    sock:close()
    return fail(out, "send failed: " .. tostring(serr))
  end
  out.sent[#out.sent + 1] = string.format("OPEN (AS %d%s, hold %d, id %s)", asn,
    asn > 65535 and ", My AS AS_TRANS 23456" or "", holdtime, ipv4(router_id))
  local state = {buf = ""}
  local status = read_and_decode(sock, out, state, deadline, true)
  if status == "open" then
    -- give the remote a short moment to answer our OPEN (KEEPALIVE or a NOTIFICATION such as 2/2 Bad Peer AS)
    local grace = math.min(deadline, nmap.clock_ms() + 1000)
    local status2 = read_and_decode(sock, out, state, grace, false)
    if status2 == "notification" or status2 == "malformed" or status2 == "closed" or status2 == "reset" then
      status = status2
    end
    if not state.got_notification and status ~= "closed" and status ~= "reset" then
      if sock:send(build_cease_admin_shutdown()) then
        out.sent[#out.sent + 1] = "NOTIFICATION 6/2 Cease / Administrative Shutdown"
      end
    end
  end
  sock:close()
  return finish(out, status, state)
end

action = function(host, port)
  local budget = stdnse.parse_timespec(stdnse.get_script_args("bgp-open-info.timeout") or "5s")
  if not budget or budget <= 0 or budget > 60 then
    return stdnse.format_output(false, "bgp-open-info.timeout must be between 0 and 60 seconds")
  end
  local deadline = nmap.clock_ms() + math.floor(budget * 1000)
  local send_open = tostring(stdnse.get_script_args("bgp-open-info.send-open") or "false"):lower()
  if send_open ~= "true" and send_open ~= "1" and send_open ~= "yes" then
    return run_passive(host, port, deadline)
  end
  local asn = tonumber(stdnse.get_script_args("bgp-open-info.asn") or "")
  if not asn or asn < 1 or asn > 4294967295 or asn ~= math.floor(asn) then
    return stdnse.format_output(false, "ACTIVE mode needs bgp-open-info.asn (1..4294967295); nothing was sent")
  end
  asn = math.floor(asn)
  local rid = parse_router_id(stdnse.get_script_args("bgp-open-info.router-id") or "192.0.2.1")
  if not rid then
    return stdnse.format_output(false, "bgp-open-info.router-id must be a dotted quad; nothing was sent")
  end
  local hold = tonumber(stdnse.get_script_args("bgp-open-info.holdtime") or "180")
  if not hold or hold ~= math.floor(hold) or hold > 65535 or (hold ~= 0 and hold < 3) then
    return stdnse.format_output(false, "bgp-open-info.holdtime must be 0 or 3..65535; nothing was sent")
  end
  local capnames = {}
  local capargs = stdnse.get_script_args("bgp-open-info.capabilities") or "mp-ipv4-unicast,route-refresh,as4"
  for c in capargs:gmatch("[^,]+") do
    c = c:match("^%s*(.-)%s*$")
    if c ~= "mp-ipv4-unicast" and c ~= "route-refresh" and c ~= "as4" then
      return stdnse.format_output(false, "unknown capability " .. c .. "; nothing was sent")
    end
    capnames[#capnames + 1] = c
  end
  return run_active(host, port, deadline, asn, rid, math.floor(hold), capnames)
end
