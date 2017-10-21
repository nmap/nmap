local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local tls = require "tls"
local unicode = require "unicode"

description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Not valid before: 2011-03-23 00:00:00
|_Not valid after:  2013-04-01 23:59:59
</code>

With <code>-v</code> it adds the issuer name and fingerprints.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
|_SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
</code>

With <code>-vv</code> it adds the PEM-encoded contents of the entire
certificate.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US/1.3.6.1.4.1.311.60.2.1.2=Delaware\
/postalCode=95131-2021/localityName=San Jose/serialNumber=3014267\
/streetAddress=2211 N 1st St/1.3.6.1.4.1.311.60.2.1.3=US\
/organizationalUnitName=PayPal Production/businessCategory=Private Organization
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US\
/organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
| SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
| -----BEGIN CERTIFICATE-----
| MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
...
| 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
|_-----END CERTIFICATE-----
</code>
]]

---
-- @see ssl-cert-intaddr
--
-- @output
-- 443/tcp open  https
-- | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
-- /stateOrProvinceName=California/countryName=US
-- | Not valid before: 2011-03-23 00:00:00
-- |_Not valid after:  2013-04-01 23:59:59
--
-- @xmloutput
-- <table key="subject">
--   <elem key="1.3.6.1.4.1.311.60.2.1.2">Delaware</elem>
--   <elem key="1.3.6.1.4.1.311.60.2.1.3">US</elem>
--   <elem key="postalCode">95131-2021</elem>
--   <elem key="localityName">San Jose</elem>
--   <elem key="serialNumber">3014267</elem>
--   <elem key="countryName">US</elem>
--   <elem key="stateOrProvinceName">California</elem>
--   <elem key="streetAddress">2211 N 1st St</elem>
--   <elem key="organizationalUnitName">PayPal Production</elem>
--   <elem key="commonName">www.paypal.com</elem>
--   <elem key="organizationName">PayPal, Inc.</elem>
--   <elem key="businessCategory">Private Organization</elem>
-- </table>
-- <table key="issuer">
--   <elem key="organizationalUnitName">Terms of use at https://www.verisign.com/rpa (c)06</elem>
--   <elem key="organizationName">VeriSign, Inc.</elem>
--   <elem key="commonName">VeriSign Class 3 Extended Validation SSL CA</elem>
--   <elem key="countryName">US</elem>
-- </table>
-- <table key="pubkey">
--   <elem key="type">rsa</elem>
--   <elem key="bits">2048</elem>
-- </table>
-- <elem key="sig_algo">sha1WithRSAEncryption</elem>
-- <table key="validity">
--   <elem key="notBefore">2011-03-23T00:00:00+00:00</elem>
--   <elem key="notAfter">2013-04-01T23:59:59+00:00</elem>
-- </table>
-- <elem key="md5">bf47cecad861efa77d1488ad4a73cb5b</elem>
-- <elem key="sha1">d8465221467a0d153df09f2eaf6d439002139a68</elem>
-- <elem key="pem">-----BEGIN CERTIFICATE-----
-- MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
-- ...
-- 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
-- -----END CERTIFICATE-----
-- </elem>

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }


portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return stdnse.format_timestamp(date)
  end
end

-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }

-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end

function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = stdnse.strjoin(".", k)
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return stdnse.strjoin("/", fields)
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = stdnse.strjoin(".", k)
    end
    output[k] = v
  end
  return output
end

local function output_tab(cert)
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)
  o.pubkey = cert.pubkey
  o.extensions = cert.extensions
  o.sig_algo = cert.sig_algorithm
  o.validity = {}
  for k, v in pairs(cert.validity) do
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = stdnse.format_timestamp(v)
    end
  end
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  o.pem = cert.pem
  return o
end

local function output_str(cert)
  local lines = {}

  lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)
  end

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
    lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
    lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm
  end

  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end
  return stdnse.strjoin("\n", lines)
end

action = function(host, port)
  host.targetname = tls.servername(host)
  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end

  return output_tab(cert), output_str(cert)
end



