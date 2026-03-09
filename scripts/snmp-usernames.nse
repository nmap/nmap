local nmap      = require "nmap"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local creds     = require "creds"
local unpwdb    = require "unpwdb"
local io        = require "io"

description = [[
Enumerates valid SNMPv3 usernames by exploiting the difference in Report PDUs
returned by SNMPv3 agents when a probe is sent with noAuthNoPriv security level.

When an UNKNOWN username is used, the agent returns a Report PDU containing:
  1.3.6.1.6.3.15.1.1.3.0  (usmStatsUnknownUserNames)

When a VALID username is used (but auth fails because we send no key), the
agent returns a Report PDU containing:
  1.3.6.1.6.3.15.1.1.5.0  (usmStatsWrongDigests)

Some permissive agents reply with a normal GetResponse-PDU (tag 0xA2) for
noAuthNoPriv-configured users — those are detected as valid too.

The SNMPv3 wire packet is built from scratch in pure Lua using BER/ASN.1
primitives, because Nmap's bundled snmp.lua library only supports v1/v2c.
Valid usernames are saved to Nmap's credentials database with state USERNAME
so scripts like snmp-brute can automatically chain password attacks on them.

References:
  * RFC 3412 - Message Processing and Dispatching for SNMP
  * RFC 3414 - User-based Security Model (USM) for SNMPv3
  * https://github.com/hatlord/snmpwn
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-usernames <target>
-- nmap -sU -p 161 --script snmp-usernames \
--      --script-args snmp-usernames.userdb=/path/to/users.txt <target>
-- nmap -sU -p 161 --script snmp-usernames \
--      --script-args snmp-usernames.maxusers=50 <target>
--
-- @args snmp-usernames.userdb   Path to a file with one username per line.
--                               Lines starting with # are treated as comments.
--                               Defaults to Nmap's built-in usernames.lst.
-- @args snmp-usernames.maxusers Maximum number of usernames to try (default: unlimited).
--                               Must be a positive integer; invalid values are ignored.
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- | snmp-usernames:
-- |   admin    - Valid SNMPv3 username
-- |   monitor  - Valid SNMPv3 username
-- |_  readonly - Valid SNMPv3 username

author     = "Your Name"
license    = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "brute"}

-- ── Port rule ─────────────────────────────────────────────────────────────
portrule = shortport.port_or_service(161, "snmp", "udp", {"open", "open|filtered"})

-- ═════════════════════════════════════════════════════════════════════════
-- BER / ASN.1 HELPERS
-- ═════════════════════════════════════════════════════════════════════════

local function encode_len(n)
  if n < 128 then
    return string.char(n)
  elseif n < 256 then
    return "\x81" .. string.char(n)
  else
    return "\x82" .. string.char(math.floor(n / 256)) .. string.char(n % 256)
  end
end

-- INTEGER (tag 0x02) — handles any non-negative value correctly.
-- A naive one-byte version breaks for values like 65507 (msgMaxSize).
local function ber_int(n)
  if n == 0 then return "\x02\x01\x00" end
  local bytes = {}
  local v = n
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  -- BER integers are signed; prepend 0x00 if high bit would look negative.
  if bytes[1]:byte() >= 0x80 then
    table.insert(bytes, 1, "\x00")
  end
  local content = table.concat(bytes)
  return "\x02" .. string.char(#content) .. content
end

-- OCTET STRING (tag 0x04)
local function ber_octet(s)
  s = s or ""
  return "\x04" .. encode_len(#s) .. s
end

-- SEQUENCE (tag 0x30)
local function ber_seq(payload)
  return "\x30" .. encode_len(#payload) .. payload
end

-- Context-specific constructed tag (0xA0 + ctx)
-- ctx=0 → GetRequest-PDU, ctx=2 → GetResponse-PDU
local function ber_ctx(ctx, payload)
  return string.char(0xA0 + ctx) .. encode_len(#payload) .. payload
end

-- ═════════════════════════════════════════════════════════════════════════
-- SNMPv3 PACKET BUILDER
-- ═════════════════════════════════════════════════════════════════════════
--
-- SNMPv3 wire format (RFC 3412 §6 + RFC 3414 §3):
--
--  SEQUENCE {
--    INTEGER  msgVersion      (3)
--    SEQUENCE msgGlobalData {
--      INTEGER  msgID                  ← unique per probe (avoids dedup)
--      INTEGER  msgMaxSize    (65507)
--      OCTET STRING msgFlags  (0x04)   ← reportable | noAuthNoPriv
--      INTEGER  msgSecurityModel (3)   ← USM
--    }
--    OCTET STRING msgSecurityParameters {
--      SEQUENCE {
--        OCTET STRING engineID   ("")  ← empty = engine-discovery probe
--        INTEGER  engineBoots    (0)
--        INTEGER  engineTime     (0)
--        OCTET STRING userName         ← *** the username under test ***
--        OCTET STRING authParams ("")
--        OCTET STRING privParams ("")
--      }
--    }
--    SEQUENCE scopedPDU {
--      OCTET STRING contextEngineID ("")
--      OCTET STRING contextName     ("")
--      GetRequest-PDU [0] {
--        INTEGER  requestID
--        INTEGER  error-status  (0)
--        INTEGER  error-index   (0)
--        SEQUENCE varBindList {
--          SEQUENCE varBind {
--            OID  1.3.6.1.2.1.1.3.0   ← sysUpTime (harmless read-only OID)
--            NULL
--          }
--        }
--      }
--    }
--  }

local msg_id_counter = 1000

local function build_probe(username)
  msg_id_counter = msg_id_counter + 1
  local msg_id     = msg_id_counter
  local request_id = msg_id_counter + 50000

  local global = ber_seq(
    ber_int(msg_id)   ..
    ber_int(65507)    ..    -- msgMaxSize
    ber_octet("\x04") ..    -- msgFlags: reportable, noAuthNoPriv
    ber_int(3)              -- msgSecurityModel = USM
  )

  local usm = ber_seq(
    ber_octet("")       ..  -- engineID (empty = discovery probe)
    ber_int(0)          ..  -- engineBoots
    ber_int(0)          ..  -- engineTime
    ber_octet(username) ..  -- *** username under test ***
    ber_octet("")       ..  -- authenticationParameters (none)
    ber_octet("")           -- privacyParameters (none)
  )
  local sec_params = ber_octet(usm)

  -- sysUpTime OID 1.3.6.1.2.1.1.3.0 pre-encoded in BER.
  -- Tag=0x06, Length=0x08, Value=2b 06 01 02 01 01 03 00
  local sysuptime_oid = "\x06\x08\x2b\x06\x01\x02\x01\x01\x03\x00"

  local varbind = ber_seq(
    sysuptime_oid ..
    "\x05\x00"        -- NULL
  )

  local pdu = ber_ctx(0,
    ber_int(request_id) ..
    ber_int(0)          ..  -- error-status
    ber_int(0)          ..  -- error-index
    ber_seq(varbind)
  )

  local scoped = ber_seq(
    ber_octet("") ..    -- contextEngineID
    ber_octet("") ..    -- contextName
    pdu
  )

  return ber_seq(
    ber_int(3)   ..     -- msgVersion = 3
    global       ..
    sec_params   ..
    scoped
  )
end

-- ═════════════════════════════════════════════════════════════════════════
-- RESPONSE CLASSIFIER
-- ═════════════════════════════════════════════════════════════════════════
--
--   usmStatsUnknownUserNames  OID tail: 0f 01 01 03 00  → user NOT found
--   usmStatsWrongDigests      OID tail: 0f 01 01 05 00  → user EXISTS
--
--   GetResponse-PDU fallback (tag 0xA2): some permissive agents skip the
--   Report PDU entirely and return real data for noAuthNoPriv users.
--   We also verify data:byte(1) == 0x30 (valid outer SEQUENCE tag) before
--   trusting the 0xA2 match, reducing false positives from stray bytes.

local OID_UNKNOWN = "\x0f\x01\x01\x03\x00"   -- usmStatsUnknownUserNames
local OID_DIGEST  = "\x0f\x01\x01\x05\x00"   -- usmStatsWrongDigests

local function classify(data)
  if not data then return "unknown" end
  if data:find(OID_DIGEST,  1, true) then return "valid"   end
  if data:find(OID_UNKNOWN, 1, true) then return "invalid" end
  -- Only treat 0xA2 as a GetResponse if the outer frame is a valid SEQUENCE.
  if data:byte(1) == 0x30 and data:find("\xa2", 1, true) then
    return "valid"
  end
  return "unknown"
end

-- ═════════════════════════════════════════════════════════════════════════
-- USERNAME WORDLIST LOADER
-- ═════════════════════════════════════════════════════════════════════════
--
-- Always returns (true, iterator) or (nil, error_string).
-- The maxusers cap wraps the iterator so it stops early automatically.

local function load_usernames()
  local path     = stdnse.get_script_args("snmp-usernames.userdb")
  local maxusers = tonumber(stdnse.get_script_args("snmp-usernames.maxusers"))

  -- Validate maxusers — ignore non-positive or non-numeric values silently.
  if maxusers and maxusers < 1 then
    stdnse.debug1("snmp-usernames.maxusers invalid (%s), ignoring", tostring(maxusers))
    maxusers = nil
  end

  local iter

  if path then
    -- Load from user-supplied file.
    local f = io.open(path, "r")
    if not f then
      return nil, "Cannot open username file: " .. path
    end
    local list = {}
    for line in f:lines() do
      line = line:match("^%s*(.-)%s*$")            -- trim whitespace
      if line ~= "" and not line:match("^#") then  -- skip blanks and comments
        list[#list + 1] = line
      end
    end
    f:close()
    if #list == 0 then
      return nil, "Username file is empty: " .. path
    end
    stdnse.debug1("Loaded %d usernames from %s", #list, path)
    local i = 0
    iter = function() i = i + 1; return list[i] end
  else
    -- Fall back to Nmap's built-in username list via unpwdb.
    stdnse.debug1("No userdb specified — falling back to Nmap default username list")
    local ok, raw_iter = unpwdb.usernames()
    if not ok or not raw_iter then
      return nil, "Failed to load Nmap default username list"
    end
    iter = raw_iter
  end

  -- Wrap iterator with maxusers cap if requested.
  if maxusers then
    stdnse.debug1("Username cap: %d", maxusers)
    local count = 0
    local base  = iter
    iter = function()
      if count >= maxusers then return nil end
      count = count + 1
      return base()
    end
  end

  return true, iter
end

-- ═════════════════════════════════════════════════════════════════════════
-- PROBE WITH RETRY
-- ═════════════════════════════════════════════════════════════════════════
--
-- UDP is lossy — retry once before giving up on a username.

local RETRIES = 2

local function probe(sock, pkt)
  for i = 1, RETRIES do
    local sent, send_err = sock:send(pkt)
    if not sent then
      stdnse.debug1("Send error (attempt %d): %s", i, send_err or "")
    else
      local recv_ok, data = sock:receive()
      if recv_ok then
        return data
      end
      stdnse.debug2("No response on attempt %d", i)
    end
  end
  return nil
end

-- ═════════════════════════════════════════════════════════════════════════
-- MAIN ACTION
-- ═════════════════════════════════════════════════════════════════════════

action = function(host, port)

  local ok, next_user = load_usernames()
  if not ok then
    return stdnse.format_output(false, next_user)
  end

  local sock = nmap.new_socket("udp")
  sock:set_timeout(3000)

  -- Using UDP connect so send()/receive() can be used instead of sendto().
  local conn_ok, conn_err = sock:connect(host, port)
  if not conn_ok then
    return stdnse.format_output(false, "Connect failed: " .. (conn_err or "unknown"))
  end

  -- creds.State.USERNAME = username confirmed, password NOT tested.
  -- This lets snmp-brute and other scripts chain attacks automatically.
  local found = creds.Credentials:new(SCRIPT_NAME, host, port)
  local total = 0
  local hits  = 0

  -- Preferred style: pull username at top of loop, break on nil.
  while true do
    local username = next_user()
    if not username then break end

    stdnse.debug2("Trying: %s", username)
    total = total + 1

    local data   = probe(sock, build_probe(username))
    local result = classify(data)
    stdnse.debug2("%-25s → %s", username, result)

    if result == "valid" then
      found:add(username, nil, creds.State.USERNAME)
      hits = hits + 1
      stdnse.debug1("FOUND: %s", username)
    end

    -- 50 ms pause — prevents flooding the agent and avoids triggering
    -- rate-limiting or account lockout on sensitive devices.
    stdnse.sleep(0.05)
  end

  sock:close()
  stdnse.debug1("Done — probes: %d | found: %d", total, hits)

  -- Returns nil when nothing found (Nmap convention = no output block shown).
  return found:getTable()
end