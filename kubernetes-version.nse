description = [[
  Attempts to detect the Kubernetes API version.
]]

categories = {"safe", "version"}

author = "Jon Mosco"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

---
-- @usage
-- nmap --script kubernetes-version <host>
-- @output
-- PORT     STATE SERVICE VERSION
-- 8443/tcp open  kubernetes-api

local shortport = require "shortport"
local json = require "json"
local http = require "http"
local nmap = require "nmap"

portrule = shortport.version_port_or_service({6443, 8443}, {"kubernetes", "kubernetes-api"}, "tcp")

action = function(host, port)

  local http_response = http.get(host, port, "/version")
  if not http_response or not http_response.status or
    http_response.status ~= 200 or not http_response.body then
    return
  end

  local ok_json, response = json.parse(http_response.body)
  if ok_json and response["major"] and response["minor"] then
    ---Detected
    port.version.name = 'kubernetes-api'
    port.version.version = response["gitVersion"]
    port.version.product = "Kubernetes"
    nmap.set_port_version(host, port)
    return response
  end
  return
end
