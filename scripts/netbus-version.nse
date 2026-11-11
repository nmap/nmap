local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Attempts to identify NetBuster from an explicit response. The default
GetInfo message observed in 1.12 identifies the product without a version.
The version query identifies 1.30 and 1.31 from eight response bytes.
An unavailable or incomplete response is not positive evidence.
]]

---
-- @usage
-- nmap -sV -p 12345 --script netbus-version <target>
--
-- @output
-- 12345/tcp open  netbus  NetBuster 1.31 (honeypot)

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.version_port_or_service ({}, "netbus", {"tcp"})

-- Add a version only after checking its explicit response in a real sample.
local supported_versions = { ["1.30"] = true, ["1.31"] = true }
local default_info =
  "Info;Your IP is logged and you will be nuked VERY soon!\r"
local apps_prefix = "AppNames;"

-- A read must succeed before any returned bytes can be used as evidence.
local function receive_banner(socket, deadline)
  local data = ""
  while #data < 4096 do
    local remaining = math.min(5000, deadline - nmap.clock_ms())
    if remaining < 10 then return false, "TIMEOUT" end
    socket:set_timeout(remaining)
    local status, chunk = socket:receive()
    if not status then return false, chunk end
    if nmap.clock_ms() > deadline then return false, "TIMEOUT" end
    if chunk == "" then return false, "EOF" end
    data = data .. chunk:sub(1, 4096 - #data)
    local ending = data:find("\r", 1, true)
    if ending then return true, data:sub(1, ending - 1) end
  end
  return false, "BANNER_TOO_LONG"
end

-- Inspect only the record at the start; never search a body for a version.
local function parse_response(data, allow_apps)
  if data:sub(1, 1) == "1" then
    if #data < 8 then return "more" end
    return "version", data:sub(1, 8)
  end
  if allow_apps and data:sub(1, 1) == "A" then
    local checked = math.min(#data, #apps_prefix)
    if data:sub(1, checked) ~= apps_prefix:sub(1, checked) then
      return false, "INVALID_APPNAMES"
    end
    local ending = data:find("\r", 1, true)
    if ending and ending <= 4096 then return "apps", ending end
    if #data >= 4096 then return false, "APPNAMES_TOO_LONG" end
    return "more"
  end
  local checked = math.min(#data, #default_info)
  if data:sub(1, checked) ~= default_info:sub(1, checked) then
    return "mismatch", data
  end
  if #data < #default_info then return "more" end
  return "info", default_info
end

local function send_version(socket, budget, state)
  local remaining = budget.deadline - nmap.clock_ms()
  if remaining < 10 then return false, "TIMEOUT" end
  socket:set_timeout(remaining)
  state.barrier = state.apps_sent
  return socket:send("nbver\rGetInfo\r")
end

-- Only called while no partial response is buffered. Keep Info's existing
-- retry opportunities; a later Apps retry falls between two Info retries.
local function retry_queries(socket, budget, state)
  local now = nmap.clock_ms()
  if budget.deadline - now < 10 then return end
  if state.next_info and now >= state.next_info then
    socket:set_timeout(budget.deadline - now)
    local sent, err = socket:send("GetInfo\r")
    state.info_attempts = state.info_attempts + 1
    state.next_info = nmap.clock_ms() + 400
    if not sent then
      stdnse.debug1("info_retry_send_failed: %s", err)
      state.next_info = nil
    elseif state.info_attempts <= 2 and state.apps_sent == 0
        and budget.apps_attempts < 6 and state.allow_requery then
      state.next_apps = nmap.clock_ms()
        + (state.info_attempts == 1 and 430 or 30)
    elseif state.next_apps then
      state.next_apps = math.max(state.next_apps, nmap.clock_ms() + 200)
    end
  end
  now = nmap.clock_ms()
  if state.next_apps and now >= state.next_apps then
    if budget.deadline - now < 10 then return end
    socket:set_timeout(budget.deadline - now)
    budget.apps_attempts = budget.apps_attempts + 1
    state.apps_sent = state.apps_sent + 1
    local sent, err = socket:send("GetApps\r")
    if not sent then
      -- A failed send may still deliver bytes. Keep the original reader,
      -- but no later Apps record may authorize another query on this socket.
      stdnse.debug1("boundary_query_send_failed: %s", err)
      state.allow_requery, state.next_apps = false, nil
    elseif budget.apps_attempts >= 6 then
      state.next_apps = nil
    elseif state.apps_sent == 1 then
      state.next_apps = state.next_info and (state.next_info + 200)
        or (nmap.clock_ms() + 570)
    else
      state.next_apps = nmap.clock_ms() + 400
    end
  end
end

local function receive_response(socket, budget, state)
  local data = ""
  while true do
    local previous_replies = state.apps_received
    while data ~= "" do
      -- Before a new query, all remaining bytes must be complete Apps
      -- records. Do not discard a fragment or accept pre-query version text.
      if state.allow_requery and state.apps_received > state.barrier
          and data:sub(1, 1) ~= "A" then
        return false, "MIXED_APPNAMES"
      end
      local kind, value = parse_response(data, state.apps_sent > 0)
      if kind == "more" then break end
      if not kind then return false, value end
      if kind ~= "apps" then return true, value, kind end
      state.apps_received = state.apps_received + 1
      if state.apps_received > state.apps_sent then
        return false, "UNREQUESTED_APPNAMES"
      end
      data = data:sub(value + 1)
    end
    -- Old replies cannot authorize a requery; request a fresh boundary.
    if data == "" and state.allow_requery
        and state.apps_received > previous_replies
        and state.apps_received <= state.barrier and budget.apps_attempts < 6 then
      state.next_apps = nmap.clock_ms()
    end
    if data == "" and state.allow_requery
        and state.apps_received > state.barrier then
      if budget.deadline - nmap.clock_ms() < 10 then return false, "TIMEOUT" end
      if budget.version_retries >= 2 then return false, "RETRY_LIMIT" end
      budget.version_retries = budget.version_retries + 1
      -- Each synchronous GetApps handler sends at most one CR record.
      -- More replies than Apps sent before the last version query proves
      -- a boundary after that query, even if earlier requests were lost.
      local sent, err = send_version(socket, budget, state)
      if not sent then return false, err, "transport" end
    end
    local now = nmap.clock_ms()
    local remaining = math.min(5000, budget.deadline - now)
    if remaining < 10 then return false, "TIMEOUT" end
    local polling = data == "" and (state.next_info or state.next_apps)
    local timeout = remaining
    if polling then
      if state.next_info then
        timeout = math.min(timeout, math.max(10, state.next_info - now))
      end
      if state.next_apps then
        timeout = math.min(timeout, math.max(10, state.next_apps - now))
      end
    end
    socket:set_timeout(timeout)
    local status, chunk = socket:receive()
    if not status then
      if not polling or chunk ~= "TIMEOUT" then return false, chunk end
      if budget.deadline - nmap.clock_ms() < 10 then
        return false, "TIMEOUT"
      end
      retry_queries(socket, budget, state)
    else
      if nmap.clock_ms() > budget.deadline then return false, "TIMEOUT" end
      if chunk == "" then return false, "EOF" end
      -- The parser bounds incomplete records; complete evidence may have a tail.
      data = data .. chunk
    end
  end
end

local function connect(host, port, budget)
  if budget.attempts >= 4 then return nil end
  local socket = nmap.new_socket()
  budget.attempts = budget.attempts + 1
  local function fail(reason, err)
    socket:close()
    stdnse.debug1("%s: %s", reason, err)
    return nil
  end
  local remaining = budget.deadline
    and math.min(5000, budget.deadline - nmap.clock_ms()) or 5000
  if remaining < 10 then return fail("probe_deadline_exceeded", "TIMEOUT") end
  socket:set_timeout(remaining)
  local status, response = socket:connect(host, port)
  if not status then return fail("connection_failed", response) end
  status, response = receive_banner(socket,
    budget.deadline or (nmap.clock_ms() + 5000))
  if not status then return fail("banner_receive_failed", response) end
  if not response:match("^NetBus ") then
    return fail("unrelated_banner", response)
  end
  return socket
end

local function probe(host, port, budget)
  local socket = connect(host, port, budget)
  if not socket then return nil end
  local function finish(reason, err)
    socket:close()
    if err then stdnse.debug1("%s: %s", reason, err)
    else stdnse.debug1("%s", reason) end
    return nil
  end
  local now = nmap.clock_ms()
  if not budget.deadline then budget.deadline = now + 5000 end
  local state = { info_attempts = 0,
    apps_sent = 0, apps_received = 0, barrier = 0, allow_requery = true }
  local status, response = send_version(socket, budget, state)
  if not status then
    finish("query_send_failed", response)
    return nil, nil, "transport"
  end
  now = nmap.clock_ms()
  state.next_info = now + 100
  state.next_apps = budget.apps_attempts < 6 and (now + 530) or nil
  local response_kind
  status, response, response_kind = receive_response(socket, budget, state)
  if not status then
    finish("query_receive_failed", response)
    return nil, nil, (response_kind == "transport"
      or response == "EOF" or response == "ERROR") and "transport"
  end
  local version
  if response_kind == "version" then
    version = response:match("^(%d%.%d%d)%-[0-4]%-%d$")
    if not supported_versions[version] then
      finish("fingerprint_mismatch")
      return nil, nil, "mismatch"
    end
  elseif response ~= default_info then
    finish("fingerprint_mismatch")
    return nil, nil, "mismatch"
  end
  socket:close()
  return true, version
end

action = function(host, port)
  local budget = { attempts = 0, transport_retries = 0, mismatch_retries = 0,
    apps_attempts = 0, version_retries = 0 }
  while budget.attempts < 4 do
    local matched, version, retry = probe(host, port, budget)
    if matched then
      port.version.name = "netbus"
      port.version.product = "NetBuster"
      port.version.version = version
      port.version.extrainfo = "honeypot"
      nmap.set_port_version(host, port)
      return
    end
    if retry == "transport" and budget.transport_retries < 2
        and budget.attempts < 4 then
      budget.transport_retries = budget.transport_retries + 1
    elseif retry == "mismatch" and budget.mismatch_retries < 1 then
      budget.mismatch_retries = budget.mismatch_retries + 1
    else
      return
    end
  end
end
