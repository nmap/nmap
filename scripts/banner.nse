local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local U = require "lpeg-utility"

description = [[
A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.

The banner will be truncated to fit into a single line, but an extra line may be printed for every
increase in the level of verbosity requested on the command line.
]]

---
-- @output
-- 21/tcp open  ftp
-- |_ banner: 220 FTP version 1.0\x0D\x0A
-- @arg banner.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @arg banner.timeout How long to wait for a banner. Default: 5s


author = "jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}



local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg == "common" then
  portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
end

---
-- Script is executed for any TCP port.
portrule = function( host, port )
  if port.protocol == "tcp" then
    if portarg then
      return stdnse.in_port_range(port, portarg)
    end
    return true
  end
  return false
end


---
-- Grabs a banner and outputs it nicely formatted.
action = function( host, port )

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

  local opts = {}
  opts.timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  opts.timeout = (opts.timeout or 5) * 1000

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
