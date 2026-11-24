local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects the MikroTik RouterOS version from the WinBox service (TCP 8291)
without credentials.

WinBox serves its GUI manifests before login. The script asks for "list"
(served by RouterOS 6 and 7) and falls back to "index" (RouterOS 6 only),
then reports the newest build recorded in the manifest.

Each manifest record names the build that last produced that GUI file, not
the running version, and records can disagree (6.40 mixes 6.40rc19..rc43).
The newest record is therefore used. Patch releases rebuild every file, so
a final version is exact. A first release of a branch (X.Y) can ship its
last pre-release's files unchanged (7.5, 7.2 and 7.4 serve manifests
byte-identical to 7.5rc1, 7.2rc5 and 7.4rc2), so a pre-release result is
reported as a range: "7.5rc1..7.5" means 7.5rc1, a later 7.5 pre-release,
or 7.5.

Tested on every release of RouterOS 6.40-6.49 and 7.1-7.25 as CHR images.
]]

---
-- @usage
-- nmap -p 8291 --script mikrotik-routeros-version <target>
-- nmap -sV -p 8291 <target>
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 8291/tcp open  winbox  MikroTik WinBox (RouterOS 7.24.6)
-- | mikrotik-routeros-version:
-- |   version: 7.24.6
-- |_  source: list
--
-- @output
-- | mikrotik-routeros-version:
-- |   version: 7.5rc1..7.5
-- |   version_min: 7.5rc1
-- |   version_max: 7.5
-- |_  source: list
--
-- @xmloutput
-- <elem key="version">7.24.6</elem>
-- <elem key="source">list</elem>
--
-- @args mikrotik-routeros-version.files Show every manifest record (also
--       shown at verbosity 2 or higher).

author = {"deauther890", "Daniel Miller", "Yehonatan Kazarski"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "version", "discovery", "safe"}

portrule = shortport.version_port_or_service(8291, "winbox", "tcp")

-- A legacy mproxy file request is <len> 0x02 <name:12, NUL padded> <trailer>,
-- where <len> is the request length minus two. This trailer asks for the
-- whole file; the reply is chunked.
local NAME_FIELD = 12
local TRAILER = "\xff\xed\x00\x00\x00\x00\x00"

-- Reply payload, after de-chunking: name[11] flags[1] size[2] offset[4] data.
local HEADER_LEN = 18
local FLAG_OK = 1
local MAX_REPLY = 1024 * 1024 -- the largest real reply is one ~64 KiB frame

local function build_request(name)
  local body = "\x02" .. name .. string.rep("\0", NAME_FIELD - #name) .. TRAILER
  return string.char(#body - 1) .. body
end

-- Reads one file reply. Framing is [len:1][tag:1][payload:len]; a chunk with
-- len < 255 ends the packet. RouterOS keeps the socket open afterwards, so
-- the end is decided from the framing and the declared size, never from EOF.
local function read_reply(sock)
  local parts, total = {}, 0
  local flags, size
  while true do
    local ok, hdr = sock:receive_buf(match.numbytes(2), true)
    if not ok then
      return nil, "chunk header: " .. tostring(hdr)
    end
    local n = hdr:byte(1)
    if n > 0 then
      local ok2, chunk = sock:receive_buf(match.numbytes(n), true)
      if not ok2 then
        return nil, "chunk payload: " .. tostring(chunk)
      end
      parts[#parts + 1] = chunk
      total = total + n
      if total > MAX_REPLY then
        return nil, "reply too large"
      end
    end
    if not flags and total >= HEADER_LEN then
      local head = table.concat(parts)
      flags = head:byte(12)
      size = string.unpack(">I2", head, 13)
    end
    if n < 0xff then
      break
    end
    -- An error reply is a single frame; a good one is done once the
    -- declared size has arrived, even without a short terminating chunk.
    if flags and (flags ~= FLAG_OK or total >= HEADER_LEN + size) then
      break
    end
  end

  local p = table.concat(parts)
  if #p < HEADER_LEN then
    return nil, ("reply too short (%d bytes)"):format(#p)
  end
  if flags ~= FLAG_OK then
    return nil, ("file not served (flags=%d)"):format(flags)
  end
  return p:sub(HEADER_LEN + 1, HEADER_LEN + size)
end

local function fetch(host, port, name)
  local sock = nmap.new_socket()
  sock:set_timeout(stdnse.get_timeout(host, 5000, 1500))
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then
    return nil, "connect: " .. tostring(err)
  end
  local data
  ok, err = sock:send(build_request(name))
  if ok then
    data, err = read_reply(sock)
  end
  sock:close()
  return data, err
end

-- RouterOS versions: X.Y[.Z][(alpha|beta|rc)N].
local PRE_RANK = {alpha = 0, beta = 1, rc = 2, [""] = 3}

local function parse_version(s)
  local major, minor, rest = s:match("^(%d+)%.(%d+)(.*)$")
  if not major then
    return nil
  end
  local v = {major = tonumber(major), minor = tonumber(minor), patch = 0,
             pre = "", prenum = 0, text = s}
  local patch, tail = rest:match("^%.(%d+)(.*)$")
  if patch then
    v.patch, rest = tonumber(patch), tail
  end
  if rest ~= "" then
    local pre, num = rest:match("^(%a+)(%d+)$")
    if not pre or not PRE_RANK[pre] then
      return nil
    end
    v.pre, v.prenum = pre, tonumber(num)
  end
  return v
end

-- Pre-releases precede the X.Y they lead to; patches (X.Y.Z) follow it.
local function newer(a, b)
  for _, k in ipairs({"major", "minor", "patch"}) do
    if a[k] ~= b[k] then
      return a[k] > b[k]
    end
  end
  if a.pre ~= b.pre then
    return PRE_RANK[a.pre] > PRE_RANK[b.pre]
  end
  return a.prenum > b.prenum
end

-- Each probe names a manifest and how its records look. "list" works on
-- RouterOS 6 and 7, so it goes first; v7 answers "index" with flags=2.
local PROBES = {
  {name = "list", pattern = 'name:%s*"([^"]+)".-version:%s*"([^"]+)"'},
  {name = "index", pattern = "(%S+%.dll)%s+([%w.%-]+)"},
}

action = function(host, port)
  local errors = {}
  for _, probe in ipairs(PROBES) do
    local data, err = fetch(host, port, probe.name)
    if not data then
      stdnse.debug1("%s: %s", probe.name, err)
      errors[#errors + 1] = probe.name .. ": " .. err
      -- A connect failure will not change for the next manifest.
      if err:match("^connect:") then
        break
      end
    else
      local best
      local files = {}
      for file, ver in data:gmatch(probe.pattern) do
        local v = parse_version(ver)
        if v then
          files[#files + 1] = ("%s %s"):format(file, ver)
          if not best or newer(v, best) then
            best = v
          end
        end
      end
      if best then
        local out = stdnse.output_table()
        local lo, hi = best.text, nil
        if best.pre ~= "" then
          hi = ("%d.%d"):format(best.major, best.minor)
          out.version = lo .. ".." .. hi
          out.version_min = lo
          out.version_max = hi
        else
          out.version = lo
        end
        out.source = probe.name
        if nmap.verbosity() >= 2 or stdnse.get_script_args(SCRIPT_NAME .. ".files") then
          out.files = files
        end

        port.version.name = "winbox"
        port.version.name_confidence = 10
        port.version.product = "MikroTik WinBox"
        port.version.extrainfo = "RouterOS " .. out.version
        port.version.ostype = "RouterOS"
        port.version.devicetype = "router"
        port.version.cpe = port.version.cpe or {}
        -- Only claim an exact OS CPE when the version is exact.
        if hi then
          table.insert(port.version.cpe, "cpe:/o:mikrotik:routeros")
        else
          table.insert(port.version.cpe, "cpe:/o:mikrotik:routeros:" .. lo)
        end
        table.insert(port.version.cpe, "cpe:/a:mikrotik:winbox")
        nmap.set_port_version(host, port)
        return out
      end
      errors[#errors + 1] = probe.name .. ": no version records"
    end
  end
  stdnse.debug1("no version: %s", table.concat(errors, "; "))
  return nil
end
