local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local ipOps = require "ipOps"
local pcre = require "pcre"

description = [[
Reports any private (RFC1918) IPv4 addresses found in the various fields of
an SSL service's certificate.  These will only be reported if the target
address itself is not private.  Nmap v7.30 or later is required.
]]

---
-- @usage
-- nmap -p 443 --script ssl-cert-intaddr <target>
--
-- @output
-- 443/tcp open  https
-- | ssl-cert-intaddr: 
-- |   Subject commonName: 
-- |     10.5.5.5
-- |   Subject organizationName: 
-- |     10.0.2.1
-- |     10.0.2.2
-- |   Issuer emailAddress: 
-- |_    10.6.6.6
-- |   X509v3 Subject Alternative Name: 
-- |_    10.3.4.5
--
--@xmloutput
-- <table key="X509v3 Subject Alternative Name">
--   <elem>10.3.4.5</elem>
-- </table>
---

author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

-- only run this script if the target host is NOT a private (RFC1918) IP address)
-- and the port is an open SSL service
portrule = function(host, port)
  if ipOps.isPrivate(host["ip"]) then
    stdnse.debug1(host["ip"].." is a private address - skipping.")
    return false
  else
    -- same criteria as ssl-cert.nse
    return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
  end
end

-- extracts any valid private (RFC1918) IPv4 addresses from any given string
-- returns a table containing them or nil if there were none found
local extractPrivateIPv4Addr = function(s)
  stdnse.debug2(" extractIPv4Addr: " .. s)
  
  local addrs = {}
  
  local matchFound = function(match, groups)
    stdnse.debug2("  regex match: " .. match)
    local isValid = (
      tonumber(groups[1]) < 256 and 
      tonumber(groups[2]) < 256 and
      tonumber(groups[3]) < 256 and
      tonumber(groups[4]) < 256
    )
    if isValid then
      stdnse.debug2("  valid IPv4 address: " .. match)
      if ipOps.isPrivate(match) then
        stdnse.debug2("  and is private (HIT): " .. match)
        addrs[#addrs + 1] = match
      end
    end
  end

  re = pcre.new("([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})", 0, "C")
  re:gmatch(s, matchFound)
  
  if #addrs>0 then
    return addrs
  else
    return nil
  end
end

local stripNewLines = function(s)
  s = string.gsub(s, "\n", " ")
  s = string.gsub(s, "\r", " ")
  return s
end

-- search the Subject or Issuer fields for leaked private IP addresses
local searchCertField = function(certField, certFieldName)
  local k,v
  local leaks = {}
  
  if certField then
    for k,v in pairs(certField) do

      -- if the name of this X509 field is numeric object identifier
      -- (i.e.  "1.2.33.4..")
      if type(k)=="table" then
        k = stdnse.strjoin(".", k)
      end
      
      v = stripNewLines(v)
      
      stdnse.debug2("search "..certFieldName.." "..k.." = "..v)
      leaks[certFieldName.." "..k] = extractPrivateIPv4Addr(v)
    end
  end

  return leaks
end

-- search the X509v3 extensions for leaked private IP addresses
local searchCertExtensions = function(cert)
  if not cert.extensions then
    stdnse.debug1("X509v3 extensions not present in certificate or the extensions are not supported by this nmap version (7.30 or later needed)")
    return {}
  end

  local exti, ext, _
  local leaks = {}
  
  for _ ,ext in pairs(cert.extensions) do
    if ext.value then
      ext.value = stripNewLines(ext.value)
      stdnse.debug2("search ext " .. ext.name .. " = " .. ext.value)
      local addrsInThisField = extractPrivateIPv4Addr(ext.value)
      leaks[ext.name] = extractPrivateIPv4Addr(ext.value)
    else
      stdnse.debug2("nosearch nil ext: " .. ext.name)
    end
  end
  
  return leaks
end

action = function(host, port)
  local output = stdnse.output_table()
  local leaks = {}
  
  local ok, cert = sslcert.getCertificate(host, port)
  if not ok then
    stdnse.debug1("failed to obtain SSL certificate")
    return nil
  end

  local leaks = {}
  
  for k,v in pairs(searchCertField(cert.subject, "Subject")) do
    leaks[k] = v
  end
  
  for k,v in pairs(searchCertField(cert.issuer, "Issuer")) do
    leaks[k] = v
  end
  
  for k,v in pairs(searchCertExtensions(cert)) do
    leaks[k] = v
  end
  
  if #(stdnse.keys(leaks)) > 0 then
    return leaks
  else
    return nil
  end
end
