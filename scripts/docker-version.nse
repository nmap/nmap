local shortport =  require "shortport"
local json = require "json"
local http = require "http"
local nmap = require "nmap"

description = [[Detects the Docker service version.]]

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 2375/tcp open  docker  Docker 1.11.2
-- |   Version: 1.11.2
-- |   BuildTime: 2016-06-01T21:47:50.269346868+00:00
-- |   Arch: amd64
-- |   KernelVersion: 3.13.0-91-generic
-- |   Os: linux
-- |   ApiVersion: 1.23
-- |   GitCommit: b9f10c9
-- |_  GoVersion: go1.5.4


author = "Claudio Criscione"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.version_port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

action = function(host, port)

  local http_response = http.get(host, port, "/version")
  if not http_response or not http_response.status or
    http_response.status ~= 200 or not http_response.body then
    return
  end

  local ok_json, response = json.parse(http_response.body)
  if ok_json and response["Version"] and response["GitCommit"] then
    ---Detected
    port.version.name = 'docker'
    port.version.version = response["Version"]
    port.version.product = "Docker"
    nmap.set_port_version(host, port)
    return response
  end
  return
end
