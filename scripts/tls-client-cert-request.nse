local asn1 = require "asn1"
local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local tls = require "tls"

description = [[
Collects the acceptable certificate authorities and signature algorithms from a
TLS 1.2 server's client-certificate request.

TLS 1.3 encrypts this message. Nmap's NSE TLS library does not yet implement
TLS 1.3 handshake decryption, so this script intentionally negotiates TLS 1.2.
]]

---
-- @usage
-- nmap --script tls-client-cert-request <targets>
--
-- @output
-- 443/tcp open  https
-- | tls-client-cert-request:
-- |   Acceptable Certificate Authorities:
-- |     C = US, ST = California, L = San Francisco, O = BadSSL, CN = BadSSL Client Root Certificate Authority
-- |   Client Certificate Types:
-- |     rsa_sign
-- |     dss_sign
-- |     ecdsa_sign
-- |   Signature Algorithms:
-- |     sha512-rsa
-- |     sha512-dsa
-- |     sha512-ecdsa
-- |     sha384-rsa
-- |     sha384-dsa
-- |     sha384-ecdsa
-- |     sha256-rsa
-- |     sha256-dsa
-- |     sha256-ecdsa
-- |     sha224-rsa
-- |     sha224-dsa
-- |     sha224-ecdsa
-- |     sha1-rsa
-- |     sha1-dsa
-- |_    sha1-ecdsa

author = "Clément Notin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"https-redirect"}

portrule = function(host, port)
  return port.protocol == "tcp" and
    (shortport.ssl(host, port) or sslcert.getPrepareTLSWithoutReconnect(port))
end

action = function(host, port)
  local status, sock, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
  else
    sock = nmap.new_socket()
    status, err = sock:connect(host, port)
  end
  if not status then
    stdnse.debug1("Connection to server failed: %s", sock or err)
    return nil
  end

  sock:set_timeout(((host.times and host.times.timeout) or 5) * 1000 + 5000)
  local server_name = tls.servername(host)
  local hello = tls.client_hello({
    protocol = "TLSv1.2",
    record_protocol = "TLSv1.2",
    extensions = {
      elliptic_curves = tls.EXTENSION_HELPERS.elliptic_curves(tls.DEFAULT_ELLIPTIC_CURVES),
      ec_point_formats = tls.EXTENSION_HELPERS.ec_point_formats({"uncompressed"}),
      server_name = server_name and tls.EXTENSION_HELPERS.server_name(server_name),
    },
  })
  status, err = sock:send(hello)
  if not status then
    stdnse.debug1("Could not send TLS ClientHello: %s", err)
    sock:close()
    return nil
  end

  local next_record = tls.record_iter(sock)
  while true do
    local record, read_err = next_record()
    if not record then
      stdnse.debug1("Could not read TLS record: %s", read_err)
      break
    end
    if record.type == "handshake" then
      for _, message in ipairs(record.body) do
        if message.type == "certificate_request" then
          sock:close()
          local output = {
            ["Client Certificate Types"] = message.certificate_types,
            ["Signature Algorithms"] = {},
            ["Acceptable Certificate Authorities"] = {},
          }
          for _, algorithm in ipairs(message.signature_algorithms) do
            output["Signature Algorithms"][#output["Signature Algorithms"] + 1] =
              ("%s-%s"):format(algorithm.hash, algorithm.signature)
          end
          for _, authority in ipairs(message.certificate_authorities) do
            output["Acceptable Certificate Authorities"][#output["Acceptable Certificate Authorities"] + 1] =
              asn1.decodeX509Name(authority)
          end
          return output
        elseif message.type == "server_hello_done" then
          sock:close()
          return nil
        end
      end
    elseif record.type == "alert" then
      break
    end
  end
  sock:close()
end
