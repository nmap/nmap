local local_port_rule
local validated_timeout_ms = 3000
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local U = require "lpeg-utility"

description = [[
A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.

Additionally provides host-level comparison of collected service banners across multiple
ports to identify suspicious identical responses indicative of honeypots or generic service listeners.

Arguments include: sample_size=5 (2..64), min_responses=2, timeout=3s (0.05..60 seconds),
ports=common or a TCP port list.
]]

---
-- @usage
-- nmap -sV --script banner <target>
-- nmap -sT -p 8000-8004 --script banner <target>
--
-- @output
-- 21/tcp open  ftp
-- |_ banner: 220 FTP version 1.0\x0D\x0A
--
-- @args banner.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @args banner.timeout How long to wait for a banner. Default: 3s
-- @args banner.sample_size Maximum number of open ports to sample for cross-port comparison (2..64). Default: 5.
-- @args banner.min_responses Minimum number of responses required for honeypot verdict. Default: 2.


author = {"jah", "SUDHARSAN M (enhancements)"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}



local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg then
  if portarg == "common" then
    portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
  end
  -- ensure TCP
  portarg = portarg:gsub("^[T:]*", "T:")
  local_port_rule = shortport.port_range(portarg)
else
  local_port_rule = function(host, port) return port.protocol == "tcp" end
end


---
-- Grabs a banner and outputs it nicely formatted.
local original_banner_action = function( host, port )

  local out = grab_banner(host, port)
  return output( out )

end



---
-- Connects to the target on the given port and returns any data issued by a listening service.
-- @param host  Host Table.
-- @param port  Port Table.
-- @return      String or nil if data was not received.
function grab_banner(host, port)
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    local response = U.get_response(port.version.service_fp, "NULL")
    if response then
      return response:match("^%s*(.-)%s*$");
    end
  end

  local opts = {timeout = validated_timeout_ms}

  local status, response = comm.get_banner(host, port, opts)

  if not status then
    local errlvl = { ["EOF"]=3,["TIMEOUT"]=3,["ERROR"]=2 }
    stdnse.debug(errlvl[response] or 1, "failed for %s on %s port %s. Message: %s", host.ip, port.protocol, port.number, response or "No Message.")
    return nil
  end

  return response:match("^%s*(.-)%s*$");

end


---
-- Formats the banner for printing to the port script result.
--
-- Non-printable characters are hex encoded and the banner is
-- then truncated to fit into the number of lines of output desired.
-- @param out  String banner issued by a listening service.
-- @return     String formatted for output.
function output( out )

  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75    -- The character width of command/shell prompt window.
  local fline_offset = 5 -- number of chars excluding script id not available to the script on the first line

  -- number of chars available on the first line of output
  -- we'll skip the first line of output if the filename is looong
  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len -1 -filename:len() -fline_offset
  else
    fline_len = 0
  end

  -- number of chars allowed on subsequent lines
  local sline_len = line_len -1 -(fline_offset-2)

  -- total number of chars allowed for output (based on verbosity)
  local total_out_chars
  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output()*sline_len)
  else
    -- skipped the first line so we'll have an extra lines worth of chars
    total_out_chars = (1+extra_output())*sline_len
  end

  -- replace non-printable ascii chars - no need to do the whole string
  out = replace_nonprint(out, 1+total_out_chars) -- 1 extra char so we can truncate below.

  -- truncate banner to total_out_chars ensuring we remove whole hex encoded chars
  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if (out:sub(-4,-1)):match("\\x%x%x") then
        out = out:sub(1,-1-4)
      else
        out = out:sub(1,-1-1)
      end
    end
    out = ("%s..."):format(out:sub(1,total_out_chars-3)) -- -3 for ellipsis
  end

  -- break into lines - this will look awful if line_len is more than the actual space available on a line...
  local ptr = fline_len
  local t = {}
  while true do
    if out:len() >= ptr then
      t[#t+1] = (ptr > 0 and out:sub(1,ptr)) or " "  -- single space if we skipped the first line
      out = out:sub(ptr+1,-1)
      ptr = sline_len
    else
      t[#t+1] = out
      break
    end
  end

  return table.concat(t,"\n")

end



---
-- Replaces characters with ASCII values outside of the range of standard printable
-- characters (decimal 32 to 126 inclusive) with hex encoded equivalents.
--
-- The second parameter dictates the number of characters to return, however, if the
-- last character before the number is reached is one that needs replacing then up to
-- three characters more than this number may be returned.
-- If the second parameter is nil, no limit is applied to the number of characters
-- that may be returned.
-- @param s    String on which to perform substitutions.
-- @param len  Number of characters to return.
-- @return     String.
function replace_nonprint( s, len )

  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format( ("0%s"):format( ( (stdnse.tohex( c:byte() )):upper() ) ):sub(-2,-1) ) -- capiche
      count = count+4
    else
      t[#t+1] = c
      count = count+1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)

end



---
-- Returns a number for each level of verbosity specified on the command line.
--
-- Ignores level increases resulting from debugging level.
-- @return Number
function extra_output()
  return (nmap.verbosity()-nmap.debugging()>0 and nmap.verbosity()-nmap.debugging()) or 0
end

-- ENHANCEMENT: validated host-level evidence and cross-port comparison.
local function integer_arg(name, default, lower, upper)
  local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. name)
  if raw == nil then return default end
  local n = tonumber(raw)
  if not n or n ~= n or n % 1 ~= 0 or n < lower or n > upper then
    return nil, name .. " must be an integer in " .. lower .. ".." .. upper
  end
  return n
end

hostrule = function(host)
  return nmap.get_ports(host, nil, "tcp", "open") ~= nil
end

action = function(host)
  local sample, err = integer_arg("sample_size", 5, 2, 64)
  if not sample then return "ERROR: " .. err end
  local minimum
  minimum, err = integer_arg("min_responses", 2, 2, sample)
  if not minimum then return "ERROR: " .. err end
  local raw = stdnse.get_script_args(SCRIPT_NAME .. ".timeout")
  local ok, timeout = pcall(stdnse.parse_timespec, raw or "3s")
  if not ok or not timeout or timeout ~= timeout or timeout < 0.05 or timeout > 60 then
    return "ERROR: timeout must be 0.05..60 seconds, e.g. 3000ms or 3s"
  end
  -- Passed to the inherited banner collector. Every host uses the same arguments.
  validated_timeout_ms = timeout * 1000
  local result = stdnse.output_table()
  result.requested_ports = sample
  result.minimum_responses = minimum
  local observations, banners, selected = {}, {}, {}
  local port = nmap.get_ports(host, nil, "tcp", "open")
  while port and #selected < sample do
    if local_port_rule(host, port) then
      selected[#selected + 1] = port.number
      local banner = grab_banner(host, port)
      local row = stdnse.output_table()
      row.port = port.number
      if banner and #banner > 0 then
        banners[#banners + 1] = banner
        row.bytes = #banner
        row.banner = output(banner)
        row.status = "response received"
      else
        row.status = "no usable banner (silent, timeout, or connection failure)"
      end
      observations[#observations + 1] = row
    end
    port = nmap.get_ports(host, port, "tcp", "open")
  end
  result.sampled_ports = table.concat(selected, ", ")
  result.responding_ports = #banners
  result.missing_responses = #selected - #banners
  result.observations = observations
  if #banners < minimum or #banners < #selected then
    result.verdict = "INCONCLUSIVE: insufficient usable responses"
  else
    local same = true
    for i = 2, #banners do
      if banners[i] ~= banners[1] then same = false; break end
    end
    result.identical_responses = same
    result.verdict = same
      and "IDENTICAL BANNERS: possible honeypot pattern; verify manually"
      or "DIFFERENT BANNERS: no identical-response pattern in this sample"
  end
  result.interpretation = "Compared collected banners after trimming surrounding whitespace; this does not confirm or exclude a honeypot."
  return result
end
