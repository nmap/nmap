--
-- this library implements management requests for Teradici PCoIP devices
-- uses key from software downloaded from their website
--

local http = require 'http'
local stdnse = require 'stdnse'
local nmap = require 'nmap'
local slaxml = require 'slaxml'
local string = require 'string'

_ENV = stdnse.module('teradici', stdnse.seeall)

local crt = [[
-----BEGIN CERTIFICATE-----
MIIDJDCCAgygAwIBAgIJAMW4gkQr3113MA0GCSqGSIb3DQEBBQUAMC0xEzARBgNV
BAoTClBDb0lQIFJvb3QxFjAUBgNVBAMTDVBDb0lQIFJvb3QgQ0EwHhcNMDYwODIx
MTYxODU0WhcNMjYwODE2MTYxODU0WjA9MRIwEAYDVQQKEwlQQ29JUCBDTVMxGTAX
BgNVBAsTEHRlcmEgQ01TIHRlc3RiZWQxDDAKBgNVBAMTA2NtczCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEA5F9K9KAPiP1Xj2wnSb56qfYXjN8rEMAbAVGvmN9W
C88lnyqBuEsPC47pege7UMAi1EqmkE+qk1Ul8HRKsj+2GxG2uMYQQTDeo53zdwf2
WD1uXUfcRwBMxxJ6K5OWCHAuhZSwRUGNGBvauIXvOFrMzanuEVf17kCeREKCIX5p
WoECAwEAAaOBujCBtzAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQULkg8b8gWSn1sPxXBT56a
tBc9IM8wXQYDVR0jBFYwVIAUpEuDdUPn5OBO9a2zv5tUOfrEbv+hMaQvMC0xEzAR
BgNVBAoTClBDb0lQIFJvb3QxFjAUBgNVBAMTDVBDb0lQIFJvb3QgQ0GCCQC2oRrW
SCjrdDANBgkqhkiG9w0BAQUFAAOCAQEA5CjLoF5WLEe4oJYSGPynbIjw+Zeefqn7
6vnMv0lKJ+xxOh6l+wI0GYEV6HcZHwmjK/+d+6TqhU+bvVPC/ESkaBcywgs4DRvP
Y+gh8Onw06F1x3SdgFTG9WBEWp2Z3wuFVRA58r8S6BCtpTRP7hVHImKTX97tcioT
vB3GMvRS0MHALfNGLltLTcqgeLzxCjXPwddmiZkjLZNYrlhhIO8cdPgeFLr/btcp
/H2EgrxiJ1Y4glboM39C7Y/kYWKln7/UAgga6JHAabxRZUpZqe/85OX/7oNfqM4z
FVRM9qEI98HgccX2v/GvGPf2i7RP6rmubemfU8DiT0BmQ6AR65imsQ==
-----END CERTIFICATE-----
]]

local key = [[
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDkX0r0oA+I/VePbCdJvnqp9heM3ysQwBsBUa+Y31YLzyWfKoG4
Sw8Ljul6B7tQwCLUSqaQT6qTVSXwdEqyP7YbEba4xhBBMN6jnfN3B/ZYPW5dR9xH
AEzHEnork5YIcC6FlLBFQY0YG9q4he84WszNqe4RV/XuQJ5EQoIhfmlagQIDAQAB
AoGAB4tSWZR0Du13mAhVn+0H9ldn3cJ9lLcT7U46g81U9VzpfEGWOXVZUONuuRZK
TNecDvFMYVYQZ3+XmkLtOMg8BsbmQnUawb36slrJ2kZrsGfPo1woZT07pyOAJM6V
txQ0M4tApvQjNTu85M3JvpaAyg8kfOkjbE+kjL6un+8AQ/ECQQD/WURXRPerZrmx
AOk5N2i/DS79KrrnRWEjoin8J+XlG1Mwss2XcqLkZPPj3uidDnNZcKetUV9aEhzg
0YSmUGAtAkEA5PRpRlQ7mYSlDLsW8HMpQZi8U/IP3c0PPcxDfGieABqtEzSp0zvC
UZO8/Bn2jiogJWJUEmwaL2cY7aXl2G3EJQJBAMVmVRbCElVHDLZxZdr9otRPdMvy
hJrVX8sUSjDNB0SeYyl6kMVLsfGuuXynjlwcF8BE/ttV1Mjkx75lOo74A+ECQQDg
yJF/Kf3lyFQfPqPT6MytiV4E8NfhBI2dN6leQHw3T/lyrLa7G6W5X9ogjQEDLJqo
+XPfLmE6/vZ7g/A4X/Q9AkEA21n1SvGVAgbNTNpZHU3XsOxBd/ii2w1QtYSfb8ys
6ukWc0+gQSdEa99dSsxIn5gAZlYZUW8v1waBIzcGBatONQ==
-----END RSA PRIVATE KEY-----
]]

local req = [[
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:pcoip="http://www.pcoip.org/2006/XMLSchema" xmlns:SOAP-RPC="http://www.w3.org/2003/05/soap-rpc"><SOAP-ENV:Body><pcoip:getPROPERTY SOAP-ENV:encodingStyle="http://www.w3.org/2003/05/soap-encoding"></pcoip:getPROPERTY></SOAP-ENV:Body></SOAP-ENV:Envelope>
]]

function get_property(host, port, property)
  if not nmap.have_ssl() then
    return nil
  end

  local thisReq = string.gsub(req, 'PROPERTY', property)

  local headers = {}
  headers['Content-Length'] = string.len(thisReq)

  rsp = http.post(host, port, '/', { ssl_client_x509 = crt, ssl_client_key = key, header = headers }, nil, thisReq.."\n\n")

  if rsp.status ~= 200 or rsp.body == nil then
    return nil
  end

  local to_return = {}
  local current_tag = nil

  local callbacks = {
    startElement = function(name, nsURI, nsPrefix)
      current_tag = name
    end,

    closeElement = function(name, nsURI)
      current_tag = nil
    end,

    text = function(text)
      if current_tag ~= nil then
        to_return[current_tag]=text
      end
    end
  }

  slaxml.parser:new(callbacks):parseSAX(rsp.body)

  return to_return
end

return _ENV
