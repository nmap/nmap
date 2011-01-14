description = [[
Tries to find hostnames that resolve to the target's IP address by querying the online database at http://www.bfk.de/bfk_dnslogger.html.

The script is in the "external" category because it sends target IPs to a third party in order to query their database.
]]

---
-- @args hostmap.prefix If set, saves the output for each host in a file
-- called "<prefix><target>". The file contains one entry per line.
-- @args newtargets If set, add the new hostnames to the scanning queue.
-- This the names presumably resolve to the same IP address as the
-- original target, this is only useful for services such as HTTP that
-- can change their behavior based on hostname.
--
-- @usage
-- nmap --script hostmap --script-args hostmap.prefix=hostmap- <targets>
--
-- @output
-- Host script results:
-- | hostmap: Saved to hostmap-nmap.org
-- | insecure.org
-- | 74.207.254.18
-- | web.insecure.org
-- | download.insecure.org
-- | images.insecure.org
-- | www.insecure.org
-- | nmap.org
-- | www.nmap.org
-- | sectools.org
-- | mirror.sectools.org
-- | www.sectools.org
-- |_seclists.org

author = "Ange Gutek"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"external", "discovery", "intrusive"}

require "dns"
require "ipOps"
require "http"
require "stdnse"
require "target"

local HOSTMAP_SERVER = "www.bfk.de"

local filename_escape, write_file

hostrule = function(host)
  return not ipOps.isPrivate(host.ip)
end

action = function(host)
  local query = "/bfk_dnslogger.html?query=" .. host.ip
  local response

  response = http.get(HOSTMAP_SERVER, 80, query)
  if not response.status then
    return string.format("Error: could not GET http://%s%s", HOSTMAP_SERVER, query)
  end

  local hostnames = {}
  for entry in string.gmatch(response.body, "#result\">([^<]-)</a>") do
    if not hostnames[entry] then
      if target.ALLOW_NEW_TARGETS then
        local status, err = target.add(entry)
      end
      hostnames[entry] = true
      if string.match(entry, "%d+%.%d+%.%d+%.%d+") or dns.query(entry) then
        hostnames[#hostnames + 1] = entry
      else
        hostnames[#hostnames + 1] = entry .. " (cannot resolve)"
      end
    end
  end

  if #hostnames == 0 then
    if not string.find(response.body, "<p>The server returned no hits.</p>") then
      return "Error: found no hostnames but not the marker for \"no hostnames found\" (pattern error?)"
    end
    return
  end

  local hostnames_str = stdnse.strjoin("\n", hostnames)
  local output_str

  local filename_prefix = stdnse.get_script_args("hostmap.prefix")
  if filename_prefix then
    local filename = filename_prefix .. filename_escape(host.targetname or host.ip)
    local status, err = write_file(filename, hostnames_str .. "\n")
    if status then
      output_str = string.format("Saved to %s\n", filename)
    else
      output_str = string.format("Error saving to %s: %s\n", filename, err)
    end
  else
    output_str = "\n"
  end
  output_str = output_str .. stdnse.strjoin("\n", hostnames)

  return output_str
end

-- Escape some potentially unsafe characters in a string meant to be a filename.
function filename_escape(s)
  return string.gsub(s, "[%z/=]", function(c)
    return string.format("=%02X", string.byte(c))
  end)
end

function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end
