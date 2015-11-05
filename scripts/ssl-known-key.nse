local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"
local bin = require "bin"

-- -*- mode: lua -*-
-- vim: set filetype=lua :

description = [[
Checks whether the SSL certificate used by a host has a fingerprint
that matches an included database of problematic keys.

The only databases currently checked are the LittleBlackBox 0.1
database of compromised keys from various devices and some keys
reportedly used by the Chinese state-sponsored hacking division APT1
(https://www.mandiant.com/blog/md5-sha1/).  However, any file of
fingerprints will serve just as well. For example, this could be used
to find weak Debian OpenSSL keys using the widely available (but too
large to include with Nmap) list.
]]

---
-- @usage
-- nmap --script ssl-known-key -p 443 <host>
--
-- @args ssl-known-key.fingerprintfile  Specify a different file to read
--       fingerprints from.
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- |_ssl-known-key: Found in Little Black Box 0.1 (SHA-1: 0028 e7d4 9cfa 4aa5 984f e497 eb73 4856 0787 e496)
--
-- @xmloutput
-- <table>
--   <elem key="section">Little Black Box 0.1</elem>
--   <elem key="sha1">0028e7d49cfa4aa5984fe497eb7348560787e496</elem>
-- </table>

author = "Mak Kolybabi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln", "default"}


local FINGERPRINT_FILE = "ssl-fingerprints"

local get_fingerprints = function(path)
  -- Check registry for cached fingerprints.
  if nmap.registry.ssl_fingerprints then
    stdnse.debug2("Using cached SSL fingerprints.")
    return true, nmap.registry.ssl_fingerprints
  end

  -- Attempt to resolve path if it is relative.
  local full_path = nmap.fetchfile("nselib/data/" .. path)
  if not full_path then
    full_path = path
  end
  stdnse.debug2("Loading SSL fingerprints from %s.", full_path)

  -- Open database.
  local file = io.open(full_path, "r")
  if not file then
    return false, "Failed to open file " .. full_path
  end

  -- Parse database.
  local section = nil
  local fingerprints = {}
  for line in file:lines() do
    line = line:gsub("#.*", "")
    line = line:gsub("^%s*", "")
    line = line:gsub("%s*$", "")
    if line ~= "" then
      if line:sub(1,1) == "[" then
        -- Start a new section.
        line = line:sub(2, #line - 1)
        stdnse.debug4("Starting new section %s.", line)
        section = line
      elseif section ~= nil then
        -- Add fingerprint to section.
        local fingerprint = bin.pack("H", line)
        if #fingerprint == 20 then
          fingerprints[fingerprint] = section
          stdnse.debug4("Added key %s to database.", line)
        else
          stdnse.debug0("Cannot parse presumed fingerprint %q in section %q.", line, section)
        end
      else
        -- Key found outside of section.
        stdnse.debug1("Key %s is not in a section.", line)
      end
    end
  end

  -- Close database.
  file:close()

  -- Cache fingerprints in registry for future runs.
  nmap.registry.ssl_fingerprints = fingerprints

  return true, fingerprints
end

portrule = shortport.ssl

action = function(host, port)
  -- Get script arguments.
  local path = stdnse.get_script_args("ssl-known-key.fingerprintfile") or FINGERPRINT_FILE
  local status, result = get_fingerprints(path)
  if not status then
    stdnse.debug1("%s", result)
    return
  end
  local fingerprints = result

  -- Get SSL certificate.
  local status, cert = sslcert.getCertificate(host, port)
  if not status then
    stdnse.debug1("sslcert.getCertificate error: %s", cert)
    return
  end
  local fingerprint = cert:digest("sha1")
  local fingerprint_fmt = stdnse.tohex(fingerprint, {separator=" ", group=4})

  -- Check SSL fingerprint against database.
  local section = fingerprints[fingerprint]
  if not section then
    stdnse.debug2("%s was not in the database.", fingerprint_fmt)
    return
  end

  return {section=section, sha1=stdnse.tohex(fingerprint)}, "Found in " .. section .. " (SHA-1: " .. fingerprint_fmt  .. ")"
end
