local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")

description = [[
Retrieves a server's SSL certificate. The amount of information printed about
the certificate depends on the verbosity level. With no extra verbosity, the
script prints the validity period and the commonName, organizationName,
stateOrProvinceName, and countryName of the subject. When present, it also
outputs all the subject alternative names.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.
/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:www.paypal.com, DNS:fastlane.paypal.com,
DNS:secure.paypal.com, DNS:www-st.paypal.com, DNS:connect.paypal.com,
...
DNS:es.paypal-qrc.com, DNS:www.fastlane.paypal.com
| Not valid before: 2024-02-08T00:00:00
|_Not valid after:  2025-02-08T23:59:59
</code>

With <code>-v</code> it adds the issuer name and fingerprints.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.
/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:www.paypal.com, DNS:fastlane.paypal.com,
DNS:secure.paypal.com, DNS:www-st.paypal.com, DNS:connect.paypal.com,
...
DNS:es.paypal-qrc.com, DNS:www.fastlane.paypal.com
| Issuer: commonName=DigiCert SHA2 Extended Validation Server CA
/organizationName=DigiCert Inc/countryName=US/organizationalUnitName=www.digicert.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-08T00:00:00
| Not valid after:  2025-02-08T23:59:59
| MD5:     7cc7 a345 a164 dfb1 4690 0277 a540 f636
| SHA-1:   9269 a100 8f61 aa60 1706 fc85 fd47 d277 66c0 f591
|_SHA-256: d76b 791c e89c 043a c25d 19f3 97b2 91d5 5d94 b1c2 72df 8d1f 4bab fdc1 91a7 413b
</code>

With <code>-vv</code> it adds the PEM-encoded contents of the entire
certificate.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.
/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:www.paypal.com, DNS:fastlane.paypal.com,
DNS:secure.paypal.com, DNS:www-st.paypal.com, DNS:connect.paypal.com,
...
DNS:es.paypal-qrc.com, DNS:www.fastlane.paypal.com
| Issuer: commonName=DigiCert SHA2 Extended Validation Server CA
/organizationName=DigiCert Inc/countryName=US/organizationalUnitName=www.digicert.com
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-02-08T00:00:00
| Not valid after:  2025-02-08T23:59:59
| MD5:     7cc7 a345 a164 dfb1 4690 0277 a540 f636
| SHA-1:   9269 a100 8f61 aa60 1706 fc85 fd47 d277 66c0 f591
|_SHA-256: d76b 791c e89c 043a c25d 19f3 97b2 91d5 5d94 b1c2 72df 8d1f 4bab fdc1 91a7 413b
| -----BEGIN CERTIFICATE-----
| MIINmjCCDIKgAwIBAgIQDSuPFewZcdj2USYg2ZUIJzANBgkqhkiG9w0BAQsFADB1
...
| 6BlCzB65H3ngMIyKoeBQJyV9skuM/mHY/hUsQVIE
|_-----END CERTIFICATE-----
</code>
]]

---
-- @see ssl-cert-intaddr.nse
--
-- @output
-- 443/tcp open  https
-- | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.
-- /stateOrProvinceName=California/countryName=US
-- | Subject Alternative Name: DNS:www.paypal.com, DNS:fastlane.paypal.com,
-- DNS:secure.paypal.com, DNS:www-st.paypal.com, DNS:connect.paypal.com,
-- ...
-- DNS:es.paypal-qrc.com, DNS:www.fastlane.paypal.com
-- | Not valid before: 2024-02-08T00:00:00
-- |_Not valid after:  2025-02-08T23:59:59
--
-- @xmloutput
-- <table key="subject">
--   <elem key="businessCategory">Private Organization</elem>
--   <elem key="commonName">www.paypal.com</elem>
--   <elem key="countryName">US</elem>
--   <elem key="jurisdictionCountryName">US</elem>
--   <elem key="jurisdictionStateOrProvinceName">Delaware</elem>
--   <elem key="localityName">San Jose</elem>
--   <elem key="organizationName">PayPal, Inc.</elem>
--   <elem key="serialNumber">3014267</elem>
--   <elem key="stateOrProvinceName">California</elem>
-- </table>
-- <table key="issuer">
--   <elem key="commonName">DigiCert SHA2 Extended Validation Server CA</elem>
--   <elem key="countryName">US</elem>
--   <elem key="organizationName">DigiCert Inc</elem>
--   <elem key="organizationalUnitName">www.digicert.com</elem>
-- </table>
-- <table key="pubkey">
--   <elem key="type">rsa</elem>
--   <elem key="bits">2048</elem>
--   <elem key="modulus">DC8F8DADDF5E33F8...5A873998377D7DAF</elem>
--   <elem key="exponent">65537</elem>
-- </table>
-- <table key="extensions">
--   <table>
--     <elem key="name">X509v3 Authority Key Identifier</elem>
--     <elem key="value">3D:D3:50:A5:D6:A0:AD:EE:F3:4A:60:0A:65:D3:21:D4:F8:F8:D6:0F</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Subject Key Identifier</elem>
--     <elem key="value">35:04:FA:12:18:AA:18:01:EC:C7:87:49:7A:02:77:98:7C:DF:BC:5F</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Subject Alternative Name</elem>
--     <elem key="value">DNS:www.paypal.com, ..., DNS:www.fastlane.paypal.com</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Certificate Policies</elem>
--     <elem key="value">Policy: 2.16.840.1.114412.2.1&#xa;Policy: 2.23.140.1.1&#xa;  CPS: http://www.digicert.com/CPS</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Key Usage</elem>
--     <elem key="value">Digital Signature, Key Encipherment</elem>
--     <elem key="critical">true</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Extended Key Usage</elem>
--     <elem key="value">TLS Web Server Authentication, TLS Web Client Authentication</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 CRL Distribution Points</elem>
--     <elem key="value">Full Name:&#xa;  URI:http://crl3.digicert.com/sha2-ev-server-g3.crl&#xa;Full Name:&#xa;  URI:http://crl4.digicert.com/sha2-ev-server-g3.crl</elem>
--   </table>
--   <table>
--     <elem key="name">Authority Information Access</elem>
--     <elem key="value">OCSP - URI:http://ocsp.digicert.com&#xa;CA Issuers - URI:http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt</elem>
--   </table>
--   <table>
--     <elem key="name">X509v3 Basic Constraints</elem>
--     <elem key="value">CA:FALSE</elem>
--     <elem key="critical">true</elem>
--   </table>
--   <table>
--     <elem key="name">CT Precertificate SCTs</elem>
--     <elem key="value">Signed Certificate Timestamp:... D:1C:0C:93:8C:6A:33:93</elem>
--   </table>
-- </table>
-- <elem key="sig_algo">sha256WithRSAEncryption</elem>
-- <table key="validity">
--   <elem key="notBefore">2024-02-08T00:00:00</elem>
--   <elem key="notAfter">2025-02-08T23:59:59</elem>
-- </table>
-- <elem key="md5">7cc7a345a164dfb146900277a540f636</elem>
-- <elem key="sha1">9269a1008f61aa601706fc85fd47d27766c0f591</elem>
-- <elem key="sha256">d76b791ce89c043ac25d19f397b291d55d94b1c272df8d1f4babfdc191a7413b</elem>
-- <elem key="pem">-&#45;&#45;&#45;&#45;BEGIN CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;MIINmjCC
-- ...
-- /hUsQVIE&#xa;-&#45;&#45;&#45;&#45;END CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;</elem>

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}

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
    return datetime.format_timestamp(date)
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
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end

local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return outlib.sorted_by_key(output)
end

local function output_tab(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return {pem = cert.pem}
  end
  local o = stdnse.output_table()
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)

  o.pubkey = stdnse.output_table()
  o.pubkey.type = cert.pubkey.type
  o.pubkey.bits = cert.pubkey.bits
  -- The following fields are set in nse_ssl_cert.cc and mirror those in tls.lua
  if cert.pubkey.type == "rsa" then
    o.pubkey.modulus = openssl.bignum_bn2hex(cert.pubkey.modulus)
    o.pubkey.exponent = openssl.bignum_bn2dec(cert.pubkey.exponent)
  elseif cert.pubkey.type == "ec" then
    local params = stdnse.output_table()
    o.pubkey.ecdhparams = {curve_params=params}
    params.ec_curve_type = cert.pubkey.ecdhparams.curve_params.ec_curve_type
    params.curve = cert.pubkey.ecdhparams.curve_params.curve
  end

  if cert.extensions and #cert.extensions > 0 then
    o.extensions = {}
    for i, v in ipairs(cert.extensions) do
      local ext = stdnse.output_table()
      ext.name = v.name
      ext.value = v.value
      ext.critical = v.critical
      o.extensions[i] = ext
    end
  end
  o.sig_algo = cert.sig_algorithm

  o.validity = stdnse.output_table()
  for i, k in ipairs({"notBefore", "notAfter"}) do
    local v = cert.validity[k]
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = datetime.format_timestamp(v)
    end
  end
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  o.sha256 = stdnse.tohex(cert:digest("sha256"))
  o.pem = cert.pem
  return o
end

local function output_str(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
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
    lines[#lines + 1] = "MD5:     " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1:   " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-256: " .. stdnse.tohex(cert:digest("sha256"), { separator = " ", group = 4 })
  end

  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end
  return table.concat(lines, "\n")
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



