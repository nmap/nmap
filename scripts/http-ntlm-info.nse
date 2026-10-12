local os = require "os"
local asn1 = require "asn1"
local datetime = require "datetime"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local smbauth = require "smbauth"
local string = require "string"
local stringaux = require "stringaux"


description = [[
This script enumerates information from remote HTTP services with NTLM
authentication enabled.

By sending a HTTP NTLM authentication request with null domain and user
credentials (passed in the 'Authorization' header), the remote service will
respond with a NTLMSSP message (encoded within the 'WWW-Authenticate' header)
and disclose information to include NetBIOS, DNS, and OS build version if
available.

Services that only accept the Negotiate (SPNEGO) scheme, as described in
RFC 4559 and [MS-N2HT], are also supported. If the server does not answer
the plain NTLM request with an NTLM challenge but advertises Negotiate, the
script retries with an NTLMSSP token wrapped in an SPNEGO NegTokenInit and
extracts the NTLM challenge from the server's NegTokenResp. Windows Remote
Management (WinRM, ports 5985/5986, path /wsman) is such a service; it also
rejects GET requests, so the script switches to a SOAP POST when a server
answers "405 Method Not Allowed" and allows POST.
]]


---
-- @usage
-- nmap -p 80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ <target>
-- nmap -sV -p 5985 --script http-ntlm-info
--      --script-args http-ntlm-info.root=/wsman <target>
--
-- @args http-ntlm-info.root The URI path to request
--
-- @output
-- 80/tcp   open     http
-- | http-ntlm-info:
-- |   Target_Name: ACTIVEWEB
-- |   NetBIOS_Domain_Name: ACTIVEWEB
-- |   NetBIOS_Computer_Name: WEB-TEST2
-- |   DNS_Domain_Name: somedomain.com
-- |   DNS_Computer_Name: web-test2.somedomain.com
-- |   DNS_Tree_Name: somedomain.com
-- |_  Product_Version: 6.1.7601
--
--@xmloutput
-- <elem key="Target_Name">TELME</elem>
-- <elem key="NetBIOS_Domain_Name">TELME</elem>
-- <elem key="NetBIOS_Computer_Name">GT4</elem>
-- <elem key="DNS_Domain_Name">telme.somedomain.com</elem>
-- <elem key="DNS_Computer_Name">gt4.telme.somedomain.com</elem>
-- <elem key="Product_Version">5.0.2195</elem>


author = {"Justin Cacak", "Rajarshi Pattanayak"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.http

local NTLMSSP_SIGNATURE = "NTLMSSP\0"

local ntlm_negotiate = select( 2,
  smbauth.get_security_blob(nil, nil, nil, nil, nil, nil,
    0x00000001 + -- Negotiate Unicode
    0x00000002 + -- Negotiate OEM strings
    0x00000004 + -- Request Target
    0x00000200 + -- Negotiate NTLM
    0x00008000 + -- Negotiate Always Sign
    0x00080000 + -- Negotiate NTLM2 Key
    0x20000000 + -- Negotiate 128
    0x80000000 -- Negotiate 56
    ))

-- Wraps an NTLMSSP NEGOTIATE message in an SPNEGO NegTokenInit
-- (RFC 4178) offering NTLMSSP (1.3.6.1.4.1.311.2.2.10) as the only mechanism.
local function spnego_wrap (token)
  local enc = asn1.ASN1Encoder:new()
  local function tlv (tag, value)
    return enc:encode({type = tag, value = value})
  end
  local spnego_oid = tlv("06", stdnse.fromhex("2b0601050502"))
  local ntlmssp_oid = tlv("06", stdnse.fromhex("2b06010401823702020a"))
  local mech_types = tlv("A0", tlv("30", ntlmssp_oid))
  local mech_token = tlv("A2", enc:encode(token))
  local neg_token_init = tlv("30", mech_types .. mech_token)
  return tlv("60", spnego_oid .. tlv("A0", neg_token_init))
end

local auth_blobs = {
  NTLM = base64.enc(ntlm_negotiate),
  Negotiate = base64.enc(spnego_wrap(ntlm_negotiate)),
}

-- Reads one DER TLV starting at pos.
-- Returns tag, value start, value end (inclusive) and the position after the
-- element, or nil if the data is truncated or malformed.
local function read_tlv (data, pos)
  if pos + 1 > #data then return nil end
  local tag, len
  tag, len, pos = string.unpack(">BB", data, pos)
  if len >= 0x80 then
    local nbytes = len & 0x7f
    if nbytes == 0 or nbytes > 4 or pos + nbytes - 1 > #data then
      return nil
    end
    len, pos = string.unpack(">I" .. nbytes, data, pos)
  end
  local vend = pos + len - 1
  if vend > #data then return nil end
  return tag, pos, vend, vend + 1
end

-- Returns the value of the first child of the constructed element spanning
-- [first, last] that has the given tag.
local function find_child (data, first, last, want)
  local pos = first
  while pos <= last do
    local tag, vstart, vend, nextpos = read_tlv(data, pos)
    if not tag or vend > last then return nil end
    if tag == want then return vstart, vend end
    pos = nextpos
  end
  return nil
end

-- Extracts the NTLMSSP message carried by a Negotiate token. The token is
-- either a raw NTLMSSP message ([MS-N2HT] permits this) or an SPNEGO
-- NegTokenResp ([1] SEQUENCE) / NegTokenInit (APPLICATION 0) whose
-- responseToken/mechToken ([2] OCTET STRING) holds the NTLMSSP message.
local function ntlm_from_negotiate (blob)
  if blob:sub(1, #NTLMSSP_SIGNATURE) == NTLMSSP_SIGNATURE then
    return blob
  end

  local tag, vstart, vend = read_tlv(blob, 1)
  if tag == 0x60 then
    -- GSS-API InitialContextToken: skip mechanism OID, then [0] NegTokenInit
    local oidtag, _, _, nextpos = read_tlv(blob, vstart)
    if oidtag ~= 0x06 then return nil end
    tag, vstart, vend = read_tlv(blob, nextpos)
    if tag ~= 0xA0 then return nil end
  elseif tag ~= 0xA1 then
    return nil
  end

  tag, vstart, vend = read_tlv(blob, vstart)
  if tag ~= 0x30 then return nil end

  -- negState [0] ENUMERATED: 2 = reject
  local sstart, send = find_child(blob, vstart, vend, 0xA0)
  if sstart then
    local etag, estart, eend = read_tlv(blob, sstart)
    if etag == 0x0A and eend == estart and blob:byte(estart) == 2 then
      stdnse.debug1("SPNEGO negotiation rejected by server")
      return nil
    end
  end

  local tstart, tend = find_child(blob, vstart, vend, 0xA2)
  if not tstart then return nil end
  local otag, ostart, oend = read_tlv(blob, tstart)
  if otag ~= 0x04 then return nil end

  local token = blob:sub(ostart, oend)
  if token:sub(1, #NTLMSSP_SIGNATURE) ~= NTLMSSP_SIGNATURE then
    return nil
  end
  return token
end

-- Parses a (possibly combined) WWW-Authenticate header value.
-- Returns a table of offered schemes, keyed by lowercase scheme name, with
-- the token68 value if present, or true if the scheme carries no token.
local function parse_www_authenticate (value)
  local schemes = {}
  if not value then return schemes end
  for _, challenge in ipairs(stringaux.strsplit(",", value)) do
    local scheme, token = challenge:match("^%s*([%w!#$%%&'*+.^_`|~-]+)%s*(%S*)")
    if scheme then
      scheme = scheme:lower()
      -- auth-params such as realm="x" are not token68 values
      if token ~= "" and token:match("^[%w%-._~+/]+=*$") then
        schemes[scheme] = token
      elseif schemes[scheme] == nil then
        schemes[scheme] = true
      end
    end
  end
  return schemes
end

-- Sends an Authorization request using the given scheme and method and
-- returns the decoded NTLM challenge message, the time it was received, the
-- schemes the server offered and the raw response.
local function request_challenge (host, port, root, scheme, method)
  local auth = scheme .. " " .. auth_blobs[scheme]
  local opts = { header = { Authorization = auth } }
  local response
  if method == "POST" then
    -- WS-Management (WinRM) only authenticates SOAP POST requests
    opts.header["Content-Type"] = "application/soap+xml;charset=UTF-8"
    opts.content = ""
    response = http.generic_request(host, port, "POST", root, opts)
  else
    response = http.get(host, port, root, opts)
  end
  local recvtime = os.time()
  local header = response.header or {}
  local offered = parse_www_authenticate(header["www-authenticate"])

  local token = offered[scheme:lower()]
  if type(token) ~= "string" then
    return nil, recvtime, offered, response
  end

  local data = base64.dec(token)
  if scheme == "Negotiate" then
    data = ntlm_from_negotiate(data)
    if not data then
      stdnse.debug1("Negotiate response did not contain an NTLM challenge")
      return nil, recvtime, offered, response
    end
  end
  return data, recvtime, offered, response
end

action = function(host, port)

  local output = stdnse.output_table()
  local root = stdnse.get_script_args(SCRIPT_NAME .. ".root") or "/"

  -- Inject NTLM authorization header with null domain and user credentials
  local method = "GET"
  local data, recvtime, offered, response =
    request_challenge(host, port, root, "NTLM", method)

  -- WinRM answers GET with "405 Method Not Allowed" before authenticating;
  -- repeat the request as a POST when the server says only POST is allowed.
  local allow = response.header and response.header["allow"] or ""
  if not data and response.status == 405
    and allow:upper():find("POST", 1, true) then
    stdnse.debug1("GET not allowed; retrying with POST")
    method = "POST"
    data, recvtime, offered =
      request_challenge(host, port, root, "NTLM", method)
  end

  -- Servers that strictly enforce Negotiate (e.g. WinRM) ignore a plain
  -- NTLM token, so retry with an SPNEGO-wrapped one.
  if not data and offered.negotiate then
    stdnse.debug1("No NTLM challenge received; retrying with Negotiate")
    data, recvtime = request_challenge(host, port, root, "Negotiate", method)
  end

  -- Continue only if an NTLM challenge was received
  if data then

    -- Leverage smbauth.get_host_info_from_security_blob() for decoding.
    -- It returns false on an invalid message instead of a table.
    local status, ntlm_decoded =
      pcall(smbauth.get_host_info_from_security_blob, data)
    if not status or type(ntlm_decoded) ~= "table" then
      stdnse.debug1("Invalid NTLM challenge message received")
      return nil
    end

    if ntlm_decoded.timestamp then
      -- 64-bit number of 100ns clicks since 1/1/1601
      local unixstamp = ntlm_decoded.timestamp // 10000000 - 11644473600
      datetime.record_skew(host, unixstamp, recvtime)
    end

    -- Target Name will always be returned under any implementation
    output.Target_Name = ntlm_decoded.target_realm

    -- Only display information returned (varies especially with open source implementations)
    -- Additionally ignore responses with null values (very rare)
    if ntlm_decoded.netbios_domain_name and #ntlm_decoded.netbios_domain_name > 0 then
      output.NetBIOS_Domain_Name = ntlm_decoded.netbios_domain_name
    end

    if ntlm_decoded.netbios_computer_name and #ntlm_decoded.netbios_computer_name > 0 then
      output.NetBIOS_Computer_Name = ntlm_decoded.netbios_computer_name
    end

    if ntlm_decoded.dns_domain_name and #ntlm_decoded.dns_domain_name > 0 then
      output.DNS_Domain_Name = ntlm_decoded.dns_domain_name
    end

    if ntlm_decoded.fqdn and #ntlm_decoded.fqdn > 0 then
      output.DNS_Computer_Name = ntlm_decoded.fqdn
    end

    if ntlm_decoded.dns_forest_name and #ntlm_decoded.dns_forest_name > 0 then
      output.DNS_Tree_Name = ntlm_decoded.dns_forest_name
    end

    if ntlm_decoded.os_major_version then
      output.Product_Version = ("%d.%d.%d"):format(
        ntlm_decoded.os_major_version,
        ntlm_decoded.os_minor_version,
        ntlm_decoded.os_build)
    end

    return output

  end

end
