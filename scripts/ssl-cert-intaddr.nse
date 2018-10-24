local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"

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
-- |     10.6.6.6
-- |   X509v3 Subject Alternative Name:
-- |_    10.3.4.5
--
--@xmloutput
-- <table key="X509v3 Subject Alternative Name">
--   <elem>10.3.4.5</elem>
-- </table>
--
-- @see http-internal-ip-disclosure.nse
-- @see ssl-cert.nse

author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}
dependencies = {"https-redirect"}

-- only run this script if the target host is NOT a private (RFC1918) IP address)
-- and the port is an open SSL service
portrule = function(host, port)
  if ipOps.isPrivate(host.ip) then
    stdnse.debug1("%s is a private address - skipping.", host.ip)
    return false
  else
    -- same criteria as ssl-cert.nse
    return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
  end
end

-- extracts any valid private (RFC1918) IPv4 addresses from any given string
-- returns a table containing them or nil if there were none found
local extractPrivateIPv4Addr = function(s)
  stdnse.debug2(" extractIPv4Addr: %s", s)

  local addrs = {}

  string.gsub(s, "%f[%d][12]?%d?%d%.[12]?%d?%d%.[12]?%d?%d%.[12]?%d?%d%f[^%d]",
    function(match)
      stdnse.debug2("  pattern match: %s", match)
      if ipOps.isPrivate(match) then
        stdnse.debug2("  is private (HIT): %s", match)
        addrs[#addrs + 1] = match
      end
    end)

  if #addrs>0 then
    return addrs
  else
    return nil
  end
end

-- search the Subject or Issuer fields for leaked private IP addresses
local searchCertField = function(certField, certFieldName)
  local k,v
  local leaks = stdnse.output_table()

  if certField then
    for k,v in pairs(certField) do

      -- if the name of this X509 field is numeric object identifier
      -- (i.e.  "1.2.33.4..")
      if type(k)=="table" then
        k = table.concat(k, ".")
      end

      stdnse.debug2("search %s %s", certFieldName, k)
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
  local leaks = stdnse.output_table()

  for _ ,ext in pairs(cert.extensions) do
    if ext.value then
      stdnse.debug2("search ext %s", ext.name)
      leaks[ext.name] = extractPrivateIPv4Addr(ext.value)
    else
      stdnse.debug2("nosearch nil ext: %s", ext.name)
    end
  end

  return leaks
end

action = function(host, port)
  local ok, cert = sslcert.getCertificate(host, port)
  if not ok then
    stdnse.debug1("failed to obtain SSL certificate")
    return nil
  end

  local leaks = stdnse.output_table()

  for k,v in pairs(searchCertField(cert.subject, "Subject")) do
    leaks[k] = v
  end

  for k,v in pairs(searchCertField(cert.issuer, "Issuer")) do
    leaks[k] = v
  end

  for k,v in pairs(searchCertExtensions(cert)) do
    leaks[k] = v
  end

  if #leaks > 0 then
    return leaks
  else
    return nil
  end
end
