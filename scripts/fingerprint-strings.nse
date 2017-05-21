local stdnse = require "stdnse"
local nmap = require "nmap"
local lpeg = require "lpeg"
local U = require "lpeg-utility"
local table = require "table"

description = [[
Prints the readable strings from service fingerprints of unknown services.
]]

---
--@usage
-- nmap -sV --script fingerprint-strings <target>
--
--@output
--| fingerprint-strings:
--|   DNSStatusRequest, GenericLines, LANDesk-RC, TLSSessionReq:
--|     bobo
--|     bobobo
--|   GetRequest, HTTPOptions, LPDString, NULL, RTSPRequest, giop, oracle-tns:
--|     bobobo
--|   Help, LDAPSearchReq, TerminalServer:
--|     bobobo
--|     bobobo
--|   Kerberos, NotesRPC, SIPOptions:
--|     bobo
--|   LDAPBindReq:
--|     bobobo
--|     bobo
--|     bobobo
--|   SSLSessionReq, SSLv23SessionReq:
--|     bobo
--|     bobobo
--|     bobo
--|   afp:
--|     bobo
--|_    bobo
--
--@args fingerprint-strings.n The number of printable ASCII characters required to make up a "string" (Default: 4)

author = "Daniel Miller"
categories = {"version"}

portrule = function (host, port)
  -- Run for any port that has a service fingerprint indicating an unknown service
  return port.version and port.version.service_fp
end

-- Create a table if necessary and append to it
local function safe_append (t, v)
  if t then
    t[#t+1] = v
  else
    t = {v}
  end
  return t
end

-- Extract strings of length n or greater.
local function strings (blob, n)
  local pat = lpeg.P {
    (lpeg.V "plain" + lpeg.V "skip")^1,
    -- Collect long-enough string of printable and space characters
    plain = (lpeg.R "\x21\x7e" + lpeg.V "space")^n,
    -- Collapse white space
    space = (lpeg.S " \t"^1)/" ",
    -- Skip anything else
    skip = ((lpeg.R "\x21\x7e"^-(n-1) * (lpeg.R "\0 " + lpeg.R "\x7f\xff")^1)^1)/"\n    ",
  }
  return lpeg.match(lpeg.Cs(pat), blob)
end

action = function(host, port)
  -- Get the table of probe responses
  local responses = U.parse_fp(port.version.service_fp)
  -- extract the probe names
  local probes = stdnse.keys(responses)
  -- If there were no probes (WEIRD!) we're done.
  if #probes <= 0 then
    return nil
  end

  local min = stdnse.get_script_args(SCRIPT_NAME .. ".n") or 4

  -- Ensure probes show up in the same order every time
  table.sort(probes)
  local invert = {}
  for i=1, #probes do
    -- Extract the strings from this probe
    local plain = strings(responses[probes[i]], min)
    if plain then
      stdnse.debug1("%s:>>>%s<<<", probes[i], plain)
      -- rearrange some whitespace to look nice
      plain = plain:gsub("^[\n ]*", "\n    "):gsub("[\n ]+$", "")
      -- Gather all the probes that had this same set of strings.
      if plain ~= "" then
        invert[plain] = safe_append(invert[plain], probes[i])
      end
    end
  end

  -- If none of the probes had sufficiently long strings, then we're done.
  if not next(invert) then
    return nil
  end

  -- Now reverse the representation so that strings are listed under probes
  local labels = {}
  local lookup = {}
  for plain, plist in pairs(invert) do
    local label = table.concat(plist, ", ")
    labels[#labels+1] = label
    lookup[label] = plain
  end
  -- Always keep sorted order!
  table.sort(labels)
  local out = stdnse.output_table()
  for i=1, #labels do
    out[labels[i]] = lookup[labels[i]]
  end
  -- XML output will not be very useful because this is intended for users eyes only.
  return out
end
