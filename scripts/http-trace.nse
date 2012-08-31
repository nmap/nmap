local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends an HTTP TRACE request and shows if the method TRACE is enabled. If debug is enabled, it returns the header fields that were modified in the response.
]]

---
-- @usage
-- nmap --script http-trace -d <ip>
--
-- @output
-- 80/tcp open  http    syn-ack
-- | http-trace: TRACE is enabled
-- | Headers:
-- | Date: Tue, 14 Jun 2011 04:41:28 GMT
-- | Server: Apache
-- | Connection: close
-- | Transfer-Encoding: chunked
-- |_Content-Type: message/http
--
-- @args http-trace.path Path to URI

author = "Paulino Calderon"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"vuln", "discovery", "safe"}


portrule = shortport.http

--- Validates the HTTP response and returns header list
--@param response The HTTP response
--@param response_headers The HTTP response headers 
local validate = function(response, response_headers)
  local output_lines = {}
  if ( not(response) ) then
    return
  end
  if not(response:match("HTTP/1.[01] 200") or response:match("TRACE / HTTP/1.[01]")) then
    return
  else
    output_lines[ #output_lines+1 ] = "TRACE is enabled"
  end
  if nmap.verbosity() >= 2 then 
    output_lines[ #output_lines+1 ]= "Headers:"
    for _, value in pairs(response_headers) do
      output_lines [ #output_lines+1 ] = value
    end
  end
  if #output_lines > 0 then
    return stdnse.strjoin("\n", output_lines)
  end 
end

---
--MAIN
---
action = function(host, port)
  local path = stdnse.get_script_args("http-trace.path") or "/"
  
  local req = http.generic_request(host, port, "TRACE", path)
  if (req.status == 301 or req.status == 302) and req.header["location"] then
    req = http.generic_request(host, port, "TRACE", req.header["location"])
  end
  return validate(req.body, req.rawheader)
end
